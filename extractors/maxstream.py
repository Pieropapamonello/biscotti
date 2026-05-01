import logging
import random
import re
import socket
import io
from urllib.parse import urlparse, quote_plus
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp.resolver import DefaultResolver
from aiohttp_socks import ProxyConnector
from bs4 import BeautifulSoup
from config import GLOBAL_PROXIES, TRANSPORT_ROUTES, get_proxy_for_url, get_connector_for_proxy

from utils.smart_request import smart_request

logger = logging.getLogger(__name__)

class StaticResolver(DefaultResolver):
    """Custom resolver to force specific IPs for domains (bypass hijacking)."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mapping = {}

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host in self.mapping:
            ip = self.mapping[host]
            logger.debug(f"StaticResolver: forcing {host} -> {ip}")
            # Format required by aiohttp: list of dicts
            return [{
                'hostname': host,
                'host': ip,
                'port': port,
                'family': family,
                'proto': 0,
                'flags': 0
            }]
        return await super().resolve(host, port, family)

class ExtractorError(Exception):
    pass

class MaxstreamExtractor:
    """Maxstream URL extractor."""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate",
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
        }
        self.session = None
        self.mediaflow_endpoint = "hls_proxy"
        self.proxies = proxies or []
        self.resolver = StaticResolver()

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    def _get_proxies_for_url(self, url: str) -> list[str]:
        """Build ordered proxy list for current URL, honoring TRANSPORT_ROUTES first."""
        ordered = []

        route_proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, GLOBAL_PROXIES)
        if route_proxy:
            ordered.append(route_proxy)

        for proxy in self.proxies:
            if proxy and proxy not in ordered:
                ordered.append(proxy)

        return ordered

    async def _get_session(self, proxy=None):
        """Get or create session, optionally with a specific proxy."""
        # Note: we use our custom resolver only for non-proxy requests
        # because proxies handle their own DNS resolution.
        
        timeout = ClientTimeout(total=45, connect=15, sock_read=30)
        if proxy:
            connector = get_connector_for_proxy(proxy)
            return ClientSession(timeout=timeout, connector=connector, headers=self.base_headers)
        
        if self.session is None or self.session.closed:
            connector = TCPConnector(
                limit=0, 
                limit_per_host=0, 
                keepalive_timeout=60, 
                enable_cleanup_closed=True, 
                resolver=self.resolver # Use custom StaticResolver
            )
            self.session = ClientSession(timeout=timeout, connector=connector, headers=self.base_headers)
        return self.session

    async def _resolve_doh(self, domain: str) -> list[str]:
        """Resolve domain using DNS-over-HTTPS (Google) to bypass local DNS hijacking."""
        try:
            # Using Google DoH API
            url = f"https://dns.google/resolve?name={domain}&type=A"
            async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ips = [ans['data'] for ans in data.get('Answer', []) if ans.get('type') == 1]
                        if ips:
                            logger.debug(f"DoH resolved {domain} to {ips}")
                            return ips
        except Exception as e:
            logger.debug(f"DoH resolution failed for {domain}: {e}")
        return []


    async def _fetch_folder_direct(self, url: str):
        """Fetch /msfld/ folder HTML directly via residential proxy (no captcha needed).
        
        uprot.net serves folder listings without captcha to Italian residential IPs.
        This is much faster and more reliable than the curl_cffi + captcha path.
        """
        proxies = self._get_proxies_for_url(url)
        if not proxies:
            proxies = self.proxies

        # Try aiohttp with each proxy
        for proxy in proxies:
            if not proxy:
                continue
            session = await self._get_session(proxy=proxy)
            try:
                headers = {
                    **self.base_headers,
                    "accept-language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
                }
                async with session.get(url, headers=headers, allow_redirects=True) as resp:
                    if resp.status < 300:
                        text = await resp.text()
                        if text and len(text) > 500 and "/msfi/" in text:
                            logger.info(f"Folder direct fetch via proxy OK, len={len(text)}")
                            return text
                        logger.debug(f"Folder direct fetch: no /msfi/ links (len={len(text) if text else 0})")
                    else:
                        logger.debug(f"Folder direct fetch: HTTP {resp.status}")
            except Exception as e:
                logger.debug(f"Folder direct fetch via proxy error: {e}")
            finally:
                if not session.closed:
                    await session.close()

        # Fallback: try curl_cffi with TLS fingerprinting
        for proxy in (proxies or [None]):
            result = await self._curl_cffi_request(url, proxy, "GET", False)
            if result and len(result) > 500 and "/msfi/" in result:
                logger.info(f"Folder curl_cffi fetch OK, len={len(result)}")
                return result

        return None

    async def _curl_cffi_request(self, url: str, proxy, method: str, is_binary: bool, **kwargs):
        """
        Single-shot request via curl_cffi with Chrome TLS impersonation.

        uprot.net inspects the TLS handshake and serves a captcha page to any
        client whose fingerprint isn't a real browser (aiohttp / httpx / python
        requests all trigger it, even from residential IPs). curl_cffi makes
        the connection indistinguishable from real Chrome, so uprot serves
        the maxstream / stayonline redirect link directly on the first GET —
        no captcha solver needed for `/msf/`, `/msfi/`, `/msfld/`.

        Returns the response body (str or bytes) on success, None on failure
        / non-success / Cloudflare challenge — the caller falls through to
        the regular aiohttp path.
        """
        try:
            from curl_cffi import requests as cffi_requests
        except ImportError:
            logger.debug("curl_cffi not installed, skipping browser-impersonation path")
            return None

        proxies_arg = {"http": proxy, "https": proxy} if proxy else None
        headers = kwargs.get("headers") or self.base_headers

        import asyncio
        loop = asyncio.get_running_loop()

        def _do_request():
            try:
                r = cffi_requests.request(
                    method,
                    url,
                    headers=headers,
                    data=kwargs.get("data"),
                    proxies=proxies_arg,
                    impersonate="chrome131",
                    timeout=30,
                    allow_redirects=True,
                )
                # Snapshot cookies + status BEFORE checking status, so the
                # caller can reuse them for the captcha POST without re-fetching
                # (uprot 503s on a second GET in quick succession).
                try:
                    cookies = {c.name: c.value for c in r.cookies.jar}
                except Exception:
                    cookies = dict(r.cookies) if r.cookies else {}
                if r.status_code >= 400:
                    return ("status_fail", r.status_code, None, cookies)
                if is_binary:
                    return ("ok_binary", r.status_code, r.content, cookies)
                return ("ok_text", r.status_code, r.text, cookies)
            except Exception as inner:
                return ("error", 0, str(inner), {})

        kind, status, payload, cookies = await loop.run_in_executor(None, _do_request)
        # Stash uprot cookies so _solve_uprot_captcha_once can reuse them for
        # the POST without re-fetching (which uprot rate-limits with 503).
        if "uprot.net" in url and cookies:
            self._last_uprot_cookies = cookies
            self._last_uprot_url = url
            self._last_uprot_proxy = proxy

        if kind == "ok_text":
            if any(marker in payload.lower() for marker in ["cf-challenge", "ray id", "checking your browser"]):
                logger.debug(f"curl_cffi got CF challenge on {url}, falling back to aiohttp")
                return None
            logger.debug(f"curl_cffi {method} {url} → {status} text len={len(payload)}")
            return payload
        if kind == "ok_binary":
            logger.debug(f"curl_cffi {method} {url} → {status} binary len={len(payload)}")
            return payload
        if kind == "status_fail":
            logger.debug(f"curl_cffi {method} {url} → status {status}, falling back")
            return None
        logger.debug(f"curl_cffi {method} {url} → exception: {payload}, falling back")
        return None

    async def _smart_request(self, url: str, method="GET", is_binary=False, **kwargs):
        """Request with automatic retry using different proxies and resolver fallback on connection failure."""
        last_error = None
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Clear previous mapping for this domain to start fresh
        self.resolver.mapping.pop(domain, None)

        # Path 0: For uprot.net, try curl_cffi with Chrome TLS impersonation.
        # uprot serves the redirect link / folder content / captcha page when
        # it sees a real browser fingerprint. Always go via the configured
        # proxy first (uprot bans datacenter IPs aggressively); only try
        # naked as a last resort. Each call to a proxied request can use
        # 1 concurrent slot, so do not stack a redundant naked attempt
        # before the proxy one.
        if "uprot.net" in domain:
            for p in self._get_proxies_for_url(url):
                cffi_result = await self._curl_cffi_request(url, p, method, is_binary, **kwargs)
                if cffi_result is not None:
                    return cffi_result
            cffi_result = await self._curl_cffi_request(url, None, method, is_binary, **kwargs)
            if cffi_result is not None:
                return cffi_result
            logger.debug(f"curl_cffi paths exhausted for {url}, falling back to aiohttp")

        # Determine paths to try: Direct, Proxies, and then resolver override
        paths = []
        # Path 1: Direct (system DNS)
        paths.append({"proxy": None, "use_ip": None})
        
        # Path 2: Proxies (route-specific first)
        proxies_for_url = self._get_proxies_for_url(url)
        if proxies_for_url:
            for p in proxies_for_url:
                paths.append({"proxy": p, "use_ip": None})
        
        # Path 3: DoH fallback (override resolver) if it's uprot or maxstream
        if "uprot.net" in domain or "maxstream" in domain:
            real_ips = await self._resolve_doh(domain)
            for ip in real_ips[:2]: # Try first 2 IPs
                paths.append({"proxy": None, "use_ip": ip})
        
        for path in paths:
            proxy = path["proxy"]
            use_ip = path["use_ip"]
            
            if use_ip:
                # CRITICAL: Must destroy old session to flush TCPConnector DNS cache!
                # Otherwise connector reuses cached (hijacked) IP even with new resolver mapping.
                if self.session and not self.session.closed:
                    await self.session.close()
                    self.session = None
                self.resolver.mapping[domain] = use_ip
                logger.debug(f"DoH bypass: forcing {domain} -> {use_ip}")
            else:
                self.resolver.mapping.pop(domain, None)

            session = await self._get_session(proxy=proxy)
            try:
                async with session.request(method, url, **kwargs) as response:
                    if response.status < 400:
                        if is_binary:
                            content = await response.read()
                            if proxy: await session.close()
                            return content
                        text = await response.text()
                        
                        # Check for Cloudflare challenge in successful response
                        if any(marker in text.lower() for marker in ["cf-challenge", "ray id", "checking your browser"]):
                            logger.warning(f"Cloudflare detected on {url} (Proxy: {proxy}), trying FlareSolverr fallback...")
                            # Fallback to the global smart_request utility
                            if proxy: await session.close()
                            fs_cmd = f"request.{method.lower()}"
                            result = await smart_request(fs_cmd, url, headers=kwargs.get("headers"), post_data=kwargs.get("data"), proxies=self.proxies)
                            return result.get("html", "") if isinstance(result, dict) else result

                        if proxy: await session.close()
                        return text
                    elif response.status in (403, 503):
                        # Might be Cloudflare block, try FlareSolverr immediately for this path
                        logger.warning(f"HTTP {response.status} on {url}, checking with FlareSolverr...")
                        if proxy: await session.close()
                        fs_cmd = f"request.{method.lower()}"
                        result = await smart_request(fs_cmd, url, headers=kwargs.get("headers"), post_data=kwargs.get("data"), proxies=self.proxies)
                        return result.get("html", "") if isinstance(result, dict) else result
                    else:
                        logger.warning(f"Request to {url} failed (Status {response.status}) [Proxy: {proxy}, StaticIP: {use_ip}]")
            except Exception as e:
                logger.warning(f"Request to {url} failed (Error: {e}) [Proxy: {proxy}, StaticIP: {use_ip}]")
                last_error = e
                # If DoH attempt failed, destroy session so next IP gets fresh connector
                if use_ip and self.session and not self.session.closed:
                    await self.session.close()
                    self.session = None
            finally:
                if proxy and 'session' in locals() and not session.closed:
                    await session.close()
        
        raise ExtractorError(f"Connection failed for {url} after trying all paths. Last error: {last_error}")

    async def _solve_uprot_captcha(self, text: str, original_url: str, max_attempts: int = 4) -> str:
        """
        Find, decode and solve captcha on uprot page — with retry loop.

        ddddocr OCR has roughly 70-80% accuracy on uprot's 3-digit captcha;
        a single attempt is too unreliable. Each attempt opens a fresh
        curl_cffi.Session (so PHPSESSID + captcha cookie pair are consistent
        between the GET that returns the captcha and the POST that submits
        the answer — uprot binds them) and tries OCR + submit. We give up
        after `max_attempts` failures.
        """
        for attempt in range(1, max_attempts + 1):
            result = await self._solve_uprot_captcha_once(text, original_url)
            if result:
                if attempt > 1:
                    logger.debug(f"Captcha solve: succeeded on attempt {attempt}")
                return result
            logger.debug(f"Captcha solve: attempt {attempt}/{max_attempts} failed, retrying" if attempt < max_attempts else f"Captcha solve: all {max_attempts} attempts exhausted")
        return None

    async def _solve_uprot_captcha_once(self, text: str, original_url: str) -> str:
        """
        Single captcha-solve attempt. Returns the parsed redirect link on
        success, None on any failure (caller may retry).

        Modern uprot.net embeds the captcha image inline as
        `<img src="data:image/png;base64,XXXX">` and binds the answer to the
        PHPSESSID cookie set by the GET that returned the captcha page —
        the POST has to be made with that same cookie or uprot just shows a
        new captcha page.
        """
        try:
            import ddddocr
        except ImportError:
            logger.error("ddddocr not installed. Cannot solve captcha.")
            return None

        try:
            from curl_cffi import requests as cffi_requests
        except ImportError:
            logger.debug("Captcha solve: curl_cffi not available")
            return None

        # Reuse cookies + proxy from the original GET (stashed by
        # _curl_cffi_request) instead of re-fetching. uprot.net 503s a
        # second GET in quick succession, so this is the only reliable path.
        captcha_cookies = getattr(self, "_last_uprot_cookies", None)
        proxy = getattr(self, "_last_uprot_proxy", None)
        proxies_arg = {"http": proxy, "https": proxy} if proxy else None

        if not captcha_cookies:
            logger.debug("Captcha solve: no cached uprot cookies, cannot solve")
            return None

        # Note: `text` is the body the caller already has — we trust it was
        # captured in the same GET as the cookies, so the captcha image
        # embedded in it is the one bound to those cookies.

        import asyncio
        loop = asyncio.get_running_loop()
        logger.debug(f"Captcha solve: reusing cookies={list(captcha_cookies.keys())} proxy={'yes' if proxy else 'no'}")

        soup = BeautifulSoup(text, "lxml")

        # Look for either an inline data-URL captcha (modern uprot) OR an
        # external captcha URL (legacy uprot / other forks).
        img_tag = soup.find(
            "img",
            src=re.compile(r"^data:image/[a-z]+;base64,|/captcha|/image/", re.I),
        )
        form = soup.find("form")

        if not img_tag or not form:
            logger.debug("Captcha solve: no img/form found in page")
            return None

        captcha_src = img_tag["src"]

        # Get the raw bytes of the captcha image
        if captcha_src.startswith("data:"):
            # Inline base64 — decode directly, no network call
            try:
                import base64
                b64_payload = captcha_src.split(",", 1)[1]
                img_data = base64.b64decode(b64_payload)
                logger.debug(f"Captcha solve: decoded inline base64 ({len(img_data)} bytes)")
            except Exception as e:
                logger.debug(f"Captcha solve: failed to decode inline base64: {e}")
                return None
        else:
            # External URL — fetch
            captcha_url = captcha_src
            if captcha_url.startswith("/"):
                parsed = urlparse(original_url)
                captcha_url = f"{parsed.scheme}://{parsed.netloc}{captcha_url}"
            logger.debug(f"Captcha solve: fetching external image from {captcha_url}")
            img_data = await self._smart_request(captcha_url, is_binary=True)

        if not img_data:
            return None

        # Initialize ddddocr (lazy init for performance)
        if not hasattr(self, "_ocr_engine"):
            self._ocr_engine = ddddocr.DdddOcr(show_ad=False)

        # Solve
        res = self._ocr_engine.classification(img_data)
        # Captcha is always digits; keep only those to avoid OCR junk chars
        res_digits = "".join(c for c in str(res) if c.isdigit())
        logger.debug(f"Captcha solved: raw={res!r} digits={res_digits!r}")
        if not res_digits:
            return None

        # Submit form
        form_action = form.get("action", "")
        if not form_action or form_action == "#":
            form_action = original_url
        elif form_action.startswith("/"):
            parsed = urlparse(original_url)
            form_action = f"{parsed.scheme}://{parsed.netloc}{form_action}"

        # Find the captcha input field name
        captcha_input = soup.find("input", {"name": re.compile(r"captcha|code|val", re.I)})
        field_name = captcha_input["name"] if captcha_input else "captcha"

        post_data = {field_name: res_digits}
        for hidden in form.find_all("input", type="hidden"):
            if hidden.get("name"):
                post_data[hidden["name"]] = hidden.get("value", "")

        logger.debug(f"Submitting captcha to: {form_action} field={field_name} cookies={list((captcha_cookies or {}).keys())}")
        headers = {**self.base_headers, "referer": original_url}

        # POST with the cookies captured from the GET — uprot binds the captcha
        # answer to PHPSESSID + captcha hash. Without these cookies the POST
        # gets a fresh captcha page back.
        def _do_post():
            try:
                return cffi_requests.post(
                    form_action,
                    data=post_data,
                    headers=headers,
                    cookies=captcha_cookies or {},
                    proxies=proxies_arg,
                    impersonate="chrome131",
                    timeout=20,
                    allow_redirects=True,
                )
            except Exception as inner:
                return inner

        post_resp = await loop.run_in_executor(None, _do_post)
        if isinstance(post_resp, Exception):
            logger.debug(f"Captcha solve: POST failed: {post_resp}")
            return None
        if post_resp.status_code >= 400:
            logger.debug(f"Captcha solve: POST status {post_resp.status_code}")
            return None
        solved_text = post_resp.text

        if not solved_text:
            return None

        try:
            return self._parse_uprot_html(solved_text)
        except Exception as e:
            logger.debug(f"Captcha solve: parse_uprot_html failed: {e}")
            return None

    def _parse_uprot_html(self, text: str) -> str:
        """Parse uprot HTML to extract redirect link."""
        # 1. Look for direct links in text (including escaped slashes)
        match = re.search(r'https?://(?:www\.)?(?:stayonline\.pro|maxstream\.video)[^"\'\s<>\\ ]+', text.replace("\\/", "/"))
        if match:
            return match.group(0)
            
        # 2. Look for JavaScript-based redirects
        js_match = re.search(r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', text)
        if js_match:
            return js_match.group(1)
            
        # 3. Look for Meta refresh
        meta_match = re.search(r'content=["\']0;\s*url=([^"\']+)["\']', text, re.I)
        if meta_match:
            return meta_match.group(1)
            
        # 4. Use BeautifulSoup for interactive elements
        soup = BeautifulSoup(text, "lxml")
        
        # Look for Bulma-style buttons or links with "Continue" text
        for btn in soup.find_all(["a", "button"]):
            text_content = btn.get_text().strip().lower()
            if "continue" in text_content or "continua" in text_content or "vai al" in text_content:
                href = btn.get("href")
                if not href and btn.parent.name == "a":
                    href = btn.parent.get("href")
                
                if href and "uprot" not in href:
                    return href
        
        # Specific Bulma selectors
        for selector in ['a[href*="maxstream"]', 'a[href*="stayonline"]', '.button.is-info', '.button.is-success', 'a.button']:
            tag = soup.select_one(selector)
            if tag and tag.get("href") and "uprot" not in tag["href"]:
                return tag["href"]
        
        # If it's a form
        form = soup.find("form")
        if form and form.get("action") and "uprot" not in form["action"]:
            return form["action"]
            
        return None

    def _parse_uprot_folder(self, text: str, season, episode) -> str | None:
        """
        Parse a /msfld/ folder HTML and return the /msfi/ link for the
        requested S{ss}E{ee}. CB01 indexes long anime by absolute episode in
        season 1 (e.g. Naruto S3E2 = 1x85), so callers should pass the
        already-resolved absolute episode when applicable.
        """
        try:
            s_int = int(season)
            e_int = int(episode)
        except (TypeError, ValueError):
            return None
        s_pad = f"{s_int:02d}"
        e_pad = f"{e_int:02d}"
        # Order: most specific first. Each pattern is followed by an msfi href
        # within ~500 chars (the row layout in the folder HTML).
        patterns = [
            rf"S{s_pad}E{e_pad}",
            rf"\b0*{s_int}x0*{e_int}\b",
            rf"\b0*{s_int}&#215;0*{e_int}\b",
            rf"\b0*{s_int}×0*{e_int}\b",
        ]
        for pat in patterns:
            m = re.search(
                rf"{pat}[\s\S]{{0,500}}?href=['\"]([^'\"]+/msfi/[^'\"]+)['\"]",
                text,
                re.I,
            )
            if m:
                return m.group(1)
        return None

    async def get_uprot(self, link: str, season=None, episode=None):
        """Extract MaxStream URL from uprot redirect.

        Supports three uprot path types:
          - /msf/{id}    single movie (legacy alias /mse/ still works upstream)
          - /msfi/{id}   single episode (NOT to be rewritten)
          - /msfld/{id}  folder of episodes; requires season + episode kwargs to
                         pick the right /msfi/ link inside the folder HTML
        """
        # Map only the modern /msf/ single-video path to its legacy /mse/ alias.
        # A naive str.replace("msf", "mse") corrupts /msfld/ into /mseld/ (404)
        # and /msfi/ into /msei/ (a deprecated path that returns 500 for new IDs).
        link = re.sub(r"/msf/", "/mse/", link)

        # /msfld/ folder handling: fetch folder listing directly via residential
        # proxy (no captcha needed for IT IPs), find the episode's /msfi/ link,
        # then resolve it through the normal captcha flow.
        if "/msfld/" in link:
            if season is None or episode is None:
                raise ExtractorError(
                    "msfld folder URL requires 'season' and 'episode' parameters"
                )

            # Step 1: Fetch folder HTML via residential proxy (no captcha)
            folder_html = await self._fetch_folder_direct(link)

            if not folder_html:
                # Fallback: try _smart_request (may trigger captcha on some IPs)
                logger.debug("Folder direct fetch failed, trying _smart_request fallback")
                folder_html = await self._smart_request(link)

            if not folder_html:
                raise ExtractorError("Failed to fetch msfld folder page")

            # Step 2: Find the /msfi/ link for the requested episode
            episode_link = self._parse_uprot_folder(folder_html, season, episode)
            if not episode_link:
                raise ExtractorError(
                    f"Episode S{season}E{episode} not found in msfld folder"
                )

            logger.info(f"Folder resolved S{season}E{episode} -> {episode_link}")

            # Step 3: Resolve the single episode URL (normal captcha flow)
            return await self.get_uprot(episode_link)

        # Direct request (user should provide non-datacenter proxy in GLOBAL_PROXY)
        text = await self._smart_request(link)

        # 1. Try normal parse
        res = self._parse_uprot_html(text)
        if res:
            return res

        # 2. If no link, try puzzle/captcha solver
        logger.debug("Direct link not found, checking for captcha...")
        res = await self._solve_uprot_captcha(text, link)
        if res:
            return res

        # If we see "Cloudflare" or "Challenge" in text, it's a block
        if "cf-challenge" in text or "ray id" in text.lower() or "checking your browser" in text.lower():
            raise ExtractorError("Cloudflare block (Browser check/Challenge)")

        logger.error(f"Uprot Parse Failure. Content: {text[:2000]}...")
        raise ExtractorError("Redirect link not found in uprot page")

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract Maxstream URL.

        For /msfld/ folder URLs, callers must pass season=N&episode=M as
        query parameters (forwarded by MFP routes as kwargs).
        """
        season = kwargs.get("season")
        episode = kwargs.get("episode")
        maxstream_url = await self.get_uprot(url, season=season, episode=episode)
        logger.debug(f"Target URL: {maxstream_url}")
        
        # Use strict headers to avoid Error 131
        headers = {
            **self.base_headers,
            "referer": "https://uprot.net/",
            "accept-language": "en-US,en;q=0.5"
        }
        
        text = await self._smart_request(maxstream_url, headers=headers)
        
        # Direct sources check
        direct_match = re.search(r'sources:\s*\[\{src:\s*"([^"]+)"', text)
        if direct_match:
            return {
                "destination_url": direct_match.group(1),
                "request_headers": {**self.base_headers, "referer": maxstream_url},
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Fallback to packer logic
        match = re.search(r"\}\('(.+)',.+,'(.+)'\.split", text)
        if not match:
             match = re.search(r"eval\(function\(p,a,c,k,e,d\).+?\}\('(.+?)',.+?,'(.+?)'\.split", text, re.S)
        
        if not match:
            raise ExtractorError(f"Failed to extract from: {text[:200]}")

        # ... rest of packer logic (terms.index, etc) ...})
        # ... rest of regex logic ...

        # Fallback to packer logic
        match = re.search(r"\}\('(.+)',.+,'(.+)'\.split", text)
        if not match:
            # Maybe it's a different packer signature?
            match = re.search(r"eval\(function\(p,a,c,k,e,d\).+?\}\('(.+?)',.+?,'(.+?)'\.split", text, re.S)
            
        if not match:
            logger.error(f"Failed to find packer script or direct source in: {text[:500]}...")
            raise ExtractorError("Failed to extract URL components")

        s1 = match.group(2)
        # Extract Terms
        terms = s1.split("|")
        try:
            urlset_index = terms.index("urlset")
            hls_index = terms.index("hls")
            sources_index = terms.index("sources")
        except ValueError as e:
            logger.error(f"Required terms missing in packer: {e}")
            raise ExtractorError(f"Missing components in packer: {e}")

        result = terms[urlset_index + 1 : hls_index]
        reversed_elements = result[::-1]
        first_part_terms = terms[hls_index + 1 : sources_index]
        reversed_first_part = first_part_terms[::-1]
        
        first_url_part = ""
        for fp in reversed_first_part:
            if "0" in fp:
                first_url_part += fp
            else:
                first_url_part += fp + "-"

        base_url = f"https://{first_url_part.rstrip('-')}.host-cdn.net/hls/"
        
        if len(reversed_elements) == 1:
            final_url = base_url + "," + reversed_elements[0] + ".urlset/master.m3u8"
        else:
            final_url = base_url
            for i, element in enumerate(reversed_elements):
                final_url += element + ","
            final_url = final_url.rstrip(",") + ".urlset/master.m3u8"

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
