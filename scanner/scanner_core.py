"""
Scanner AI Shield - Core Scanner Module (v2.0 — Refactored)

Architecture : Pipe and Filter
Filter #1   : IntelligentCrawler  — Attack Surface Mapping
Filter #2   : VulnerabilityScannerEngine — XSS / SQLi payload injection

Implemented requirements
────────────────────────
FR2  : Authorized target validation
FR3  : Sub-link discovery, form/input extraction, dynamic DOM & async API tracing
FR4  : SQLi (error-based + boolean-based) and XSS (Selenium alert) scanning
FR5  : Structured JSON adapter layer, LLM-provider agnostic
FR8  : Real-time console + dashboard callback logging
NFR2 : Request rate limiting (≤ 10 req/s)
NFR3 : Standard JSON output schema
NFR5 : Stateless adapter (no provider lock-in)
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from requests import Response, Session
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# ──────────────────────────────────────────────
# Module-level logger (FR8)
# ──────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# FR4: Detection patterns & baseline payloads
# ──────────────────────────────────────────────
SQL_ERROR_REGEX = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-[0-9]{4,5}|pg_query|"
    r"sqlite3\.OperationalError|SQLSTATE|unclosed quotation mark)",
    re.IGNORECASE,
)

BASELINE_SQLI_PAYLOADS: List[str] = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "1; DROP TABLE users--",
]

BASELINE_XSS_PAYLOADS: List[str] = [
    # Classic reflected / stored XSS
    "<script>alert('XSS_TEST')</script>",
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
    # Tag-breaking variants (bypass basic sanitisers)
    "'><script>alert('XSS_TEST')</script>",
    "</title><script>alert('XSS_TEST')</script>",
    # Event-handler variants
    '" onmouseover="alert(1)',
    "' onfocus='alert(1)' autofocus='",
    # DOM XSS — JavaScript URI
    "javascript:alert(document.domain)",
]

# Unique marker embedded in every XSS payload for reliable reflection detection.
_XSS_MARKER = "XSS_TEST"

# Heuristics for detecting that a response is a login/auth page redirect.
# Use specific path/file patterns to avoid false positives on vulnerability
# pages that happen to contain words like 'session' in their URL.
_LOGIN_PAGE_MARKERS: List[str] = [
    "/login.php", "/signin", "/sign-in", "/auth/login",
    "please login", "please sign in", "로그인",
]

# URLs matching this pattern will be skipped BEFORE making the request to
# prevent session invalidation (e.g., visiting /logout.php logs the user out).
_LOGOUT_URL_PATTERN = re.compile(
    r"(?:logout|signout|sign[-_]?out)(?:\.php|\b)",
    re.IGNORECASE,
)

# JavaScript keywords that indicate client-side routing / async navigation
_JS_ROUTE_PATTERN = re.compile(
    r"""(?:router\.push|history\.push|window\.location\s*=|href\s*=)\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)


# ══════════════════════════════════════════════
# Data-transfer objects
# ══════════════════════════════════════════════

@dataclass
class InputPoint:
    """
    A single injectable attack point discovered by the crawler (FR3).

    Attributes
    ----------
    url        : Absolute URL where the injection should be sent.
    http_method: HTTP verb (GET / POST / PUT …).
    parameter  : Name of the injectable parameter / field.
    form_action: Resolved action URL of the enclosing <form>, if applicable.
    input_type : HTML input type attribute (text, hidden, email …).
    extra_data : Any extra context (e.g., API endpoint metadata).
    """

    url: str
    http_method: str
    parameter: str
    form_action: Optional[str] = None
    input_type: str = "text"
    extra_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityFinding:
    """Internal structured finding before JSON-adapter conversion (FR5)."""

    target_url: str
    vulnerability_type: str
    parameter: str
    payload: str
    http_method: str
    status_code: int
    evidence: Dict[str, Any]


@dataclass
class LoginConfig:
    """
    Credentials for form-based automatic authentication.

    The scanner will POST these credentials to *login_url* before crawling,
    automatically acquiring and persisting the session cookies so the user
    never has to copy-paste them manually.

    Attributes
    ----------
    login_url      : Absolute URL of the login form (e.g. /login.php).
    username_field : Name attribute of the username <input>.
    password_field : Name attribute of the password <input>.
    username_value : Credential to submit.
    password_value : Credential to submit.
    success_marker : Optional string expected in the post-login page that
                     confirms a successful login (URL substring or body text).
    """

    login_url: str
    username_field: str
    password_field: str
    username_value: str
    password_value: str
    success_marker: str = ""


# ══════════════════════════════════════════════
# NFR2: Sliding-window rate limiter
# ══════════════════════════════════════════════

def rate_limited(max_requests_per_second: int = 10) -> Callable:
    """
    Decorator that enforces a sliding-window rate limit so the decorated
    function is called at most *max_requests_per_second* times per second.
    Thread-safe via a per-decorator lock.
    """
    request_times: deque = deque()
    lock = threading.Lock()

    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with lock:
                now = time.monotonic()
                window_start = now - 1.0
                # Evict timestamps outside the 1-second window.
                while request_times and request_times[0] < window_start:
                    request_times.popleft()

                if len(request_times) >= max_requests_per_second:
                    # Sleep until the oldest request falls out of the window.
                    sleep_for = request_times[0] + 1.0 - now
                    if sleep_for > 0:
                        time.sleep(sleep_for)
                    # Re-evict after sleeping.
                    now = time.monotonic()
                    window_start = now - 1.0
                    while request_times and request_times[0] < window_start:
                        request_times.popleft()

                request_times.append(time.monotonic())
            return func(*args, **kwargs)

        return wrapper

    return decorator


# ══════════════════════════════════════════════
# FR2: Target authorization
# ══════════════════════════════════════════════

class AuthorizedTargetValidator:
    """
    FR2: Only allow scanning of localhost or explicitly pre-approved domains.
    Prevents accidental/malicious scanning of arbitrary third-party hosts.
    """

    _LOCALHOST_HOSTS: frozenset = frozenset({"localhost", "127.0.0.1", "::1"})

    def __init__(self, pre_approved_domains: Iterable[str]) -> None:
        self.pre_approved_domains: Set[str] = {
            d.lower().strip() for d in pre_approved_domains
        }

    def is_authorized(self, target_url: str) -> bool:
        hostname = (urlparse(target_url).hostname or "").lower()
        return hostname in self._LOCALHOST_HOSTS or hostname in self.pre_approved_domains

    def validate_or_raise(self, target_url: str) -> None:
        if not self.is_authorized(target_url):
            raise PermissionError(
                f"Unauthorized target: '{target_url}'. "
                "Only localhost or pre-approved domains are allowed."
            )


# ══════════════════════════════════════════════
# Filter #1 — IntelligentCrawler (FR3)
# ══════════════════════════════════════════════

class IntelligentCrawler:
    """
    FR3: Hybrid crawler that discovers the full attack surface of a web target.

    Strategy
    ────────
    1. Static pass  — requests + BeautifulSoup for every queued URL.
       Fast, zero overhead, sufficient for server-rendered pages.
    2. Dynamic pass — Selenium (headless Chrome) for pages that exhibit
       JavaScript-rendered content or that were found only via JS routing.
       Triggered per-URL when static analysis detects JS-heavy content.
    3. API trace    — Chrome DevTools performance logs capture XHR/fetch
       requests made during dynamic rendering, exposing async endpoints.

    Public Attributes (class spec)
    ──────────────────────────────
    discoveredLinks : All unique absolute URLs visited during the crawl.
    forms           : Deduplicated list of raw form metadata dicts.
    parameters      : Deduplicated list of injectable InputPoint objects
                      (the "Attack Surface Mapping Data" for the next filter).
    """

    # Pages with fewer than this many visible characters in the raw HTML are
    # likely SPA shells that need dynamic rendering.
    _STATIC_CONTENT_THRESHOLD = 500

    # Tags whose href/src are navigation candidates.
    _LINK_ATTRS: Dict[str, str] = {"a": "href", "link": "href"}

    def __init__(
        self,
        session: Session,
        timeout: int = 10,
        max_pages: int = 30,
        dynamic_enabled: bool = True,
    ) -> None:
        self.session = session
        self.timeout = timeout
        self.max_pages = max_pages
        self.dynamic_enabled = dynamic_enabled

        # ── Public attributes (class spec) ──────────────────────────────
        self.discoveredLinks: List[str] = []   # All visited absolute URLs
        self.forms: List[Dict[str, Any]] = []  # Raw form metadata
        self.parameters: List[InputPoint] = [] # Attack surface mapping data

        # ── Internal state ───────────────────────────────────────────────
        self._visited: Set[str] = set()        # Canonical URL fingerprints
        self._dynamic_candidates: Set[str] = set()  # URLs needing Selenium

    # ──────────────────────────────────────────────
    # Public entry point (FR3 — crawl)
    # ──────────────────────────────────────────────

    def crawl(self, targetUrl: str) -> List[InputPoint]:  # noqa: N803 (spec name)
        """
        FR3: Main crawl entry point.

        Performs a hybrid BFS crawl starting from *targetUrl* and returns
        the consolidated list of InputPoint objects ready for payload
        injection by the scanner engine.

        Parameters
        ----------
        targetUrl : Seed URL for the crawl (must be an absolute URL).

        Returns
        -------
        List[InputPoint]
            Deduplicated attack-surface mapping data (pipe output).
        """
        # Reset state for a fresh crawl.
        self.discoveredLinks = []
        self.forms = []
        self.parameters = []
        self._visited = set()
        self._dynamic_candidates = set()

        base_parsed = urlparse(targetUrl)
        base_netloc = base_parsed.netloc

        queue: deque[str] = deque([targetUrl])
        raw_points: List[InputPoint] = []
        raw_forms: List[Dict[str, Any]] = []

        # ── Phase 1: Static BFS ─────────────────────────────────────────
        while queue and len(self._visited) < self.max_pages:
            current_url = queue.popleft()
            canonical = self._canonicalize(current_url)

            if canonical in self._visited:
                continue
            self._visited.add(canonical)

            # ── Pre-request logout guard ────────────────────────────────
            # Never request logout URLs. Visiting /logout.php would instantly
            # invalidate the session, causing ALL subsequent pages to redirect
            # to the login page and appear as auth failures.
            if _LOGOUT_URL_PATTERN.search(current_url):
                logger.info(
                    "[CRAWLER] Skipping logout URL to preserve session: %s",
                    current_url,
                )
                continue

            try:
                response = self._http_get(current_url)
            except requests.RequestException as exc:
                logger.warning("[CRAWLER] GET failed for %s: %s", current_url, exc)
                continue

            html = response.text

            # ── Login-redirect guard ─────────────────────────────────────
            # If the response URL changed to a login page, our session is
            # invalid. Skip this URL and emit a warning rather than parsing
            # login-form inputs as attack surface.
            resp_url = response.url.lower()
            if any(m in resp_url for m in _LOGIN_PAGE_MARKERS):
                logger.warning(
                    "[CRAWLER] Redirected to login page for %s → "
                    "skipping. Provide session cookies or login config.",
                    current_url,
                )
                continue

            # Detect SPA-shell pages — queue for dynamic rendering.
            if self.dynamic_enabled and self._needs_dynamic_rendering(html):
                self._dynamic_candidates.add(current_url)

            soup = BeautifulSoup(html, "html.parser")

            # Extract URL query parameters as GET injection points.
            raw_points.extend(self._extract_url_params(current_url))

            # Extract forms and their inputs.
            page_forms, page_points = self.extractForms(soup, current_url)
            raw_forms.extend(page_forms)
            raw_points.extend(page_points)

            # Extract JS-embedded route strings for further crawling.
            js_links = self._extract_js_routes(html, current_url, base_netloc)

            # Enqueue discovered links.
            for next_url in self._extract_links(soup, current_url, base_netloc):
                if self._canonicalize(next_url) not in self._visited:
                    queue.append(next_url)
            for next_url in js_links:
                if self._canonicalize(next_url) not in self._visited:
                    self._dynamic_candidates.add(next_url)

        # ── Phase 2: Dynamic rendering for JS-heavy pages ───────────────
        if self.dynamic_enabled and self._dynamic_candidates:
            dynamic_points = self._crawl_dynamic(
                base_url=targetUrl,
                candidates=self._dynamic_candidates,
                base_netloc=base_netloc,
            )
            raw_points.extend(dynamic_points)

        # ── Consolidate results into public attributes ───────────────────
        self.discoveredLinks = sorted(
            {self._canonicalize(u) for u in self._visited}
        )
        self.forms = self._deduplicate_form_inputs(raw_forms)
        self.parameters = self._deduplicate_points(raw_points)

        return self.parameters

    # ──────────────────────────────────────────────
    # FR3 — Form extraction (public, per spec)
    # ──────────────────────────────────────────────

    def extractForms(                              # noqa: N802 (spec name)
        self,
        soup: BeautifulSoup,
        page_url: str,
    ) -> Tuple[List[Dict[str, Any]], List[InputPoint]]:
        """
        FR3: Extract all <form> elements from a parsed page.

        Returns a tuple of:
          - raw form metadata dicts (stored in self.forms)
          - InputPoint objects for each named input field
        """
        forms_meta: List[Dict[str, Any]] = []
        input_points: List[InputPoint] = []

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper().strip()
            raw_action = form.get("action") or page_url
            action_url = urljoin(page_url, raw_action)  # always absolute

            enctype = form.get("enctype", "application/x-www-form-urlencoded")
            form_id = form.get("id", "")
            form_name = form.get("name", "")

            form_meta: Dict[str, Any] = {
                "url": action_url,
                "method": method,
                "enctype": enctype,
                "id": form_id,
                "name": form_name,
                "inputs": [],
            }

            # Extract all input fields for the form payload body.
            for tag in form.find_all(["input", "textarea", "select", "button"]):
                name = tag.get("name")
                if not name:
                    continue

                input_type = tag.get("type", "text").lower()
                default_value = tag.get("value", "")
                
                # Add to the form's default payload map.
                form_meta["inputs"].append(
                    {"name": name, "type": input_type, "default": default_value}
                )

                # Skip creating an injection point for non-injectable types.
                if input_type in {"submit", "reset", "image", "button", "file"}:
                    continue

                input_points.append(
                    InputPoint(
                        url=action_url,
                        http_method=method,
                        parameter=name,
                        form_action=action_url,
                        input_type=input_type,
                        extra_data={
                            "enctype": enctype,
                            "default_value": default_value,
                            "form_inputs": form_meta["inputs"],
                        },
                    )
                )

            forms_meta.append(form_meta)

        return forms_meta, input_points

    # ──────────────────────────────────────────────
    # FR3 — Input extraction (public, per spec)
    # ──────────────────────────────────────────────

    def extractInputs(                             # noqa: N802 (spec name)
        self,
        soup: BeautifulSoup,
        page_url: str,
    ) -> List[InputPoint]:
        """
        FR3: Extract standalone <input> / <textarea> elements not wrapped in
        a <form> tag (common in modern SPA fragments).
        """
        points: List[InputPoint] = []
        # Collect inputs that have no <form> ancestor.
        for tag in soup.find_all(["input", "textarea", "select"]):
            if tag.find_parent("form"):
                continue  # handled by extractForms
            name = tag.get("name")
            if not name:
                continue
            input_type = tag.get("type", "text").lower()
            if input_type in {"submit", "reset", "image", "button", "file"}:
                continue
            points.append(
                InputPoint(
                    url=page_url,
                    http_method="GET",
                    parameter=name,
                    input_type=input_type,
                    extra_data={"context": "orphan_input"},
                )
            )
        return points

    # ──────────────────────────────────────────────
    # FR3 — Dynamic crawl (private, per spec)
    # ──────────────────────────────────────────────

    def _crawl_dynamic(
        self,
        base_url: str,
        candidates: Set[str],
        base_netloc: str,
    ) -> List[InputPoint]:
        """
        FR3: Dynamic DOM + async API tracing via Selenium headless Chrome.

        For each candidate URL:
          1. Navigate with Selenium and wait for the DOM to stabilise.
          2. Extract <form> elements and named inputs from the rendered DOM.
          3. Parse Chrome DevTools performance logs to discover XHR/fetch
             endpoints (async API call tracing).
          4. Scroll to the bottom to trigger lazy-loaded components.
          5. Click navigation elements to reveal SPA sub-routes.

        A single WebDriver instance is reused across all candidates to
        amortise the startup cost.
        """
        points: List[InputPoint] = []
        driver: Optional[webdriver.Chrome] = None

        try:
            driver = _build_headless_driver(enable_performance_logs=True)

            for url in candidates:
                if len(self.discoveredLinks) >= self.max_pages:
                    break
                try:
                    points.extend(
                        self._dynamic_extract_page(driver, url, base_netloc)
                    )
                except WebDriverException as exc:
                    logger.warning(
                        "[CRAWLER][DYN] WebDriver error on %s: %s", url, exc
                    )
        except WebDriverException as exc:
            logger.error(
                "[CRAWLER][DYN] Could not start headless Chrome: %s. "
                "Dynamic crawling is disabled for this run.",
                exc,
            )
        finally:
            if driver is not None:
                try:
                    driver.quit()
                except Exception:  # noqa: BLE001
                    pass

        return points

    def _dynamic_extract_page(
        self,
        driver: webdriver.Chrome,
        url: str,
        base_netloc: str,
    ) -> List[InputPoint]:
        """Extract attack points from a single URL using an existing driver."""
        points: List[InputPoint] = []

        driver.get(url)

        # Wait for the body — use a generous timeout for heavy SPAs.
        try:
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except TimeoutException:
            logger.warning("[CRAWLER][DYN] Body not found within timeout: %s", url)
            return points

        # Scroll to bottom to trigger lazy rendering.
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1.0)  # brief pause for lazy content to render

        # ── DOM form extraction ──────────────────────────────────────────
        for form in driver.find_elements(By.TAG_NAME, "form"):
            try:
                method = (form.get_attribute("method") or "GET").upper()
                raw_action = form.get_attribute("action") or url
                # action may be a full URL or relative — normalise.
                action_url = (
                    raw_action
                    if raw_action.startswith("http")
                    else urljoin(url, raw_action)
                )

                # First, collect all form inputs into a single list to mimic static crawler behavior
                form_inputs = []
                for selector in ["input[name]", "textarea[name]", "select[name]", "button[name]"]:
                    for elem in form.find_elements(By.CSS_SELECTOR, selector):
                        name = elem.get_attribute("name")
                        if not name:
                            continue
                        input_type = (elem.get_attribute("type") or "text").lower()
                        default_value = elem.get_attribute("value") or ""
                        form_inputs.append({
                            "name": name,
                            "type": input_type,
                            "default": default_value
                        })

                # Second, create injection points but skip non-injectables
                for selector in ["input[name]", "textarea[name]", "select[name]"]:
                    for elem in form.find_elements(By.CSS_SELECTOR, selector):
                        name = elem.get_attribute("name")
                        if not name:
                            continue
                        input_type = (
                            elem.get_attribute("type") or "text"
                        ).lower()
                        if input_type in {"submit", "reset", "image", "button", "file"}:
                            continue
                        
                        points.append(
                            InputPoint(
                                url=action_url,
                                http_method=method,
                                parameter=name,
                                form_action=action_url,
                                input_type=input_type,
                                extra_data={
                                    "source": "dynamic_dom",
                                    "form_inputs": form_inputs
                                },
                            )
                        )
            except WebDriverException:
                continue  # stale element — skip

        # ── Orphan inputs (not inside a <form>) ─────────────────────────
        rendered_html = driver.page_source
        soup = BeautifulSoup(rendered_html, "html.parser")
        points.extend(self.extractInputs(soup, url))

        # ── SPA sub-route discovery via clickable nav elements ───────────
        self._discover_spa_routes(driver, url, base_netloc)

        # ── Async API endpoint tracing via DevTools performance logs ─────
        points.extend(self._trace_async_api_calls(driver, url))

        return points

    def _discover_spa_routes(
        self,
        driver: webdriver.Chrome,
        current_url: str,
        base_netloc: str,
    ) -> None:
        """
        Click <a href="#…"> and data-route links that trigger SPA navigation,
        adding newly discovered URLs to the dynamic candidate queue.
        """
        try:
            nav_links = driver.find_elements(
                By.CSS_SELECTOR,
                "a[href], [data-route], [data-href], [data-url]",
            )
            for link in nav_links[:20]:  # cap to avoid excessive clicking
                try:
                    href = (
                        link.get_attribute("href")
                        or link.get_attribute("data-route")
                        or link.get_attribute("data-href")
                        or ""
                    )
                    if not href:
                        continue
                    parsed = urlparse(href)
                    # Only same-origin links.
                    if parsed.netloc and parsed.netloc != base_netloc:
                        continue
                    abs_href = urljoin(current_url, href)
                    canonical = self._canonicalize(abs_href)
                    if canonical not in self._visited:
                        self._dynamic_candidates.add(abs_href)
                except WebDriverException:
                    continue
        except WebDriverException:
            pass

    def _trace_async_api_calls(
        self,
        driver: webdriver.Chrome,
        page_url: str,
    ) -> List[InputPoint]:
        """
        Parse Chrome DevTools Network events from the performance log to
        surface XHR/fetch endpoints as additional injection points.
        """
        points: List[InputPoint] = []
        try:
            for entry in driver.get_log("performance"):
                try:
                    message = json.loads(entry["message"])["message"]
                    if message.get("method") != "Network.requestWillBeSent":
                        continue

                    params = message.get("params", {})
                    request = params.get("request", {})
                    req_url = request.get("url", "")
                    req_method = request.get("method", "GET").upper()

                    if not req_url or req_url.startswith("data:"):
                        continue

                    # Ignore non-HTTP requests (chrome-extension, blob, …).
                    if not req_url.startswith(("http://", "https://")):
                        continue

                    # GET query parameters → injection points.
                    parsed = urlparse(req_url)
                    for param in parse_qs(parsed.query):
                        points.append(
                            InputPoint(
                                url=req_url,
                                http_method=req_method,
                                parameter=param,
                                extra_data={
                                    "source": "async_api_trace",
                                    "initiator": params.get("initiator", {}).get(
                                        "type", "unknown"
                                    ),
                                },
                            )
                        )

                    # POST body parameters → injection points.
                    if req_method == "POST":
                        post_data = request.get("postData", "")
                        for param in parse_qs(post_data):
                            points.append(
                                InputPoint(
                                    url=req_url,
                                    http_method="POST",
                                    parameter=param,
                                    extra_data={
                                        "source": "async_api_trace",
                                        "post_body_param": True,
                                    },
                                )
                            )
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        except Exception as exc:  # noqa: BLE001
            # Performance log availability varies by driver/browser version.
            logger.debug("[CRAWLER][DYN] Performance log unavailable: %s", exc)

        return points

    # ──────────────────────────────────────────────
    # Helper: static HTTP GET (rate-limited)
    # ──────────────────────────────────────────────

    @rate_limited(10)  # NFR2
    def _http_get(self, url: str) -> Response:
        """Issue a rate-limited HTTP GET, following redirects."""
        return self.session.get(url, timeout=self.timeout, allow_redirects=True)

    # ──────────────────────────────────────────────
    # Helpers: link/param extraction from static HTML
    # ──────────────────────────────────────────────

    @staticmethod
    def _extract_url_params(url: str) -> List[InputPoint]:
        """Return one InputPoint per query parameter in *url*."""
        parsed = urlparse(url)
        return [
            InputPoint(url=url, http_method="GET", parameter=param)
            for param in parse_qs(parsed.query)
        ]

    @staticmethod
    def _extract_links(
        soup: BeautifulSoup, current_url: str, base_netloc: str
    ) -> List[str]:
        """
        Extract same-origin absolute URLs from <a href> tags.
        Fragment-only links and non-HTTP schemes are filtered out.
        """
        links: List[str] = []
        for tag in soup.find_all("a", href=True):
            raw = tag["href"].strip()
            if not raw or raw.startswith(("javascript:", "mailto:", "tel:")):
                continue
            abs_url = urljoin(current_url, raw)
            parsed = urlparse(abs_url)
            if parsed.netloc == base_netloc and parsed.scheme in {"http", "https"}:
                # Strip fragments to avoid revisiting the same page via #anchor.
                clean = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, "")
                )
                links.append(clean)
        return links

    @staticmethod
    def _extract_js_routes(
        html: str, current_url: str, base_netloc: str
    ) -> List[str]:
        """
        Regex-scan inline <script> content for JS router calls.
        Discovers SPA routes that are never in static <a href> tags.
        """
        routes: List[str] = []
        for match in _JS_ROUTE_PATTERN.finditer(html):
            raw_route = match.group(1)
            if not raw_route or raw_route.startswith(("http", "//")):
                continue
            abs_url = urljoin(current_url, raw_route)
            parsed = urlparse(abs_url)
            if parsed.netloc == base_netloc:
                routes.append(abs_url)
        return routes

    @staticmethod
    def _needs_dynamic_rendering(html: str) -> bool:
        """
        Heuristic: if the raw HTML body is thin (SPA shell) or contains known
        SPA framework markers, schedule a dynamic rendering pass.
        """
        lower = html.lower()
        spa_markers = (
            "ng-version",     # Angular
            "data-reactroot",  # React
            "__vue_",          # Vue
            "data-server-rendered",  # Nuxt/SSR markers
            "id=\"app\"",
            "id='app'",
        )
        if any(marker in lower for marker in spa_markers):
            return True
        # Very sparse body content → likely an SPA shell.
        text_len = len(BeautifulSoup(html, "html.parser").get_text(strip=True))
        return text_len < IntelligentCrawler._STATIC_CONTENT_THRESHOLD

    @staticmethod
    def _canonicalize(url: str) -> str:
        """
        Produce a canonical URL key for deduplication.
        Strips fragments; sorts query parameters for order-independent comparison.
        """
        parsed = urlparse(url)
        sorted_query = urlencode(
            sorted(parse_qs(parsed.query, keep_blank_values=True).items()),
            doseq=True,
        )
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, sorted_query, "")
        )

    # ──────────────────────────────────────────────
    # Deduplication helpers
    # ──────────────────────────────────────────────

    @staticmethod
    def _deduplicate_points(points: List[InputPoint]) -> List[InputPoint]:
        unique: Dict[str, InputPoint] = {}
        for p in points:
            key = f"{p.http_method}|{p.url}|{p.parameter}"
            unique.setdefault(key, p)  # keep first occurrence
        return list(unique.values())

    @staticmethod
    def _deduplicate_form_inputs(
        form_inputs: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        unique: Dict[str, Dict[str, Any]] = {}
        for item in form_inputs:
            key = f"{item['method']}|{item['url']}"
            unique.setdefault(key, item)
        return list(unique.values())


# ══════════════════════════════════════════════
# FR5 / NFR3 / NFR5: JSON adapter
# ══════════════════════════════════════════════

class ScannerJSONAdapter:
    """
    FR5, NFR3, NFR5:
    Converts internal VulnerabilityFinding objects to a provider-agnostic
    JSON-serialisable dictionary schema.
    """

    @staticmethod
    def to_standard_json(finding: VulnerabilityFinding) -> Dict[str, Any]:
        return asdict(finding)

    @staticmethod
    def to_standard_json_list(
        findings: List[VulnerabilityFinding],
    ) -> List[Dict[str, Any]]:
        return [ScannerJSONAdapter.to_standard_json(f) for f in findings]


# ══════════════════════════════════════════════
# Filter #2 — VulnerabilityScannerEngine (FR4)
# ══════════════════════════════════════════════

class VulnerabilityScannerEngine:
    """
    Core scanner orchestrator.

    Receives the attack-surface mapping data (List[InputPoint]) from the
    IntelligentCrawler pipe and injects SQLi / XSS payloads into each point.
    """

    def __init__(
        self,
        pre_approved_domains: Iterable[str],
        timeout: int = 10,
        log_callback: Optional[Callable[[str], None]] = None,
        session_cookies: Optional[Dict[str, str]] = None,
        login_config: Optional[LoginConfig] = None,
    ) -> None:
        self.session = requests.Session()
        self.session.cookies.set("PHPSESSID", "fo85gqkk0t2ltbh7n4ul8pkms6")
        self.session.cookies.set("security", "low")
        self.timeout = timeout
        self.session_cookies: Dict[str, str] = session_cookies or {}
        self.login_config = login_config
        # Inject any provided session cookies into the shared requests.Session
        # so that every HTTP request (crawl + scan) uses the authenticated session.
        if self.session_cookies:
            self.session.cookies.update(self.session_cookies)
        self.validator = AuthorizedTargetValidator(pre_approved_domains)
        self.crawler = IntelligentCrawler(self.session, timeout=timeout)
        self.adapter = ScannerJSONAdapter()
        self.log_callback = log_callback
        # Expose last crawl context for the dashboard.
        self.last_scan_context: Dict[str, Any] = {"sub_links": [], "input_forms": []}

    # ──────────────────────────────────────────────
    # FR8: unified logging
    # ──────────────────────────────────────────────

    def _log_info(self, message: str) -> None:
        print(message)
        logger.info(message)
        if self.log_callback:
            self.log_callback(message)

    # ──────────────────────────────────────────────
    # Main scan entry point
    # ──────────────────────────────────────────────

    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Orchestrate the full scan pipeline:
          FR2 → FR3 → FR4 → FR5

        Returns a list of standardised vulnerability finding dicts.
        """
        self.validator.validate_or_raise(target_url)

        # ── Auto-login (Form-based) ──────────────────────────────────────
        # If login_config is supplied, authenticate before crawling so that
        # session cookies are injected into the shared requests.Session.
        # This means the user only provides credentials once; the scanner
        # manages session renewal automatically.
        if self.login_config:
            if self._perform_form_login(self.login_config):
                self._log_info("[AUTH] Auto-login succeeded. Session cookies acquired.")
            else:
                self._log_info(
                    "[AUTH] Auto-login FAILED. Scan will continue without authentication "
                    "— authenticated pages will not be reachable."
                )

        self._log_info(f"[SCAN] Starting crawl: {target_url}")
        input_points = self.crawler.crawl(target_url)

        # Expose crawl results for the Flask dashboard.
        self.last_scan_context = {
            "sub_links": self.crawler.discoveredLinks,
            "input_forms": self.crawler.forms,
        }

        self._log_info(
            f"[SCAN] Discovered {len(input_points)} injection point(s) "
            f"across {len(self.crawler.discoveredLinks)} page(s)."
        )

        # Convert InputPoint objects to dicts for JSON representation
        findings = [
            {
                "url": point.url,
                "method": point.http_method,
                "parameter": point.parameter,
                "parameter_type": point.input_type,
                "extra_data": point.extra_data,
            }
            for point in input_points
        ]

        return findings
    # ──────────────────────────────────────────────
    # Form-based auto-login
    # ──────────────────────────────────────────────

    def _perform_form_login(self, cfg: LoginConfig) -> bool:
        """
        Perform a form-based login and persist the resulting session cookies
        into self.session so all subsequent requests use the authenticated context.

        Handles CSRF tokens automatically by parsing all <input> fields on the
        login page (hidden fields, submit buttons, etc.) and including them in
        the POST body. This is required by frameworks like DVWA that check
        for the presence of the submit button value (e.g., Login=Login) to
        trigger the login logic.
        """
        try:
            self._log_info(f"[AUTH] Fetching login page: {cfg.login_url}")
            get_resp = self.session.get(cfg.login_url, timeout=self.timeout, allow_redirects=True)
            get_resp.raise_for_status()

            soup = BeautifulSoup(get_resp.text, "html.parser")

            # Find the login form (prefer the form that contains the password field).
            login_form = None
            for form in soup.find_all("form"):
                if form.find("input", {"name": cfg.password_field}):
                    login_form = form
                    break
            if login_form is None:
                login_form = soup.find("form")  # Fallback: first form.

            # Collect ALL input fields from the form (hidden + text + submit etc.)
            # This ensures submit button values like "Login=Login" are included,
            # which PHP apps (e.g., DVWA) require to trigger the login handler.
            post_data: Dict[str, str] = {}
            if login_form:
                for inp in login_form.find_all("input"):
                    inp_name  = inp.get("name")
                    inp_type  = (inp.get("type") or "text").lower()
                    inp_value = inp.get("value", "")
                    if inp_name and inp_type not in ("checkbox", "radio"):
                        post_data[inp_name] = inp_value
            else:
                # No form found — fall back to just hidden fields.
                for hidden in soup.find_all("input", {"type": "hidden"}):
                    name = hidden.get("name")
                    if name:
                        post_data[name] = hidden.get("value", "")

            # Overlay credentials (overwrite whatever the form pre-filled).
            post_data[cfg.username_field] = cfg.username_value
            post_data[cfg.password_field] = cfg.password_value

            self._log_info(
                f"[AUTH] Submitting credentials to: {cfg.login_url} "
                f"(fields: {list(post_data.keys())})"
            )
            post_resp = self.session.post(
                cfg.login_url, data=post_data, timeout=self.timeout, allow_redirects=True
            )

            # Verify login success.
            login_failed = any(m in post_resp.url.lower() for m in _LOGIN_PAGE_MARKERS)

            if cfg.success_marker:
                if cfg.success_marker.lower() in post_resp.url.lower():
                    login_failed = False
                elif cfg.success_marker.lower() in post_resp.text.lower():
                    login_failed = False
                else:
                    self._log_info(
                        f"[AUTH] Success marker '{cfg.success_marker}' not found after login."
                    )
                    return False

            if login_failed:
                self._log_info(
                    "[AUTH] Still on login page after POST — check credentials, "
                    f"final URL was: {post_resp.url}"
                )
                return False

            # Sync all session cookies to session_cookies for Selenium injection.
            for cookie in self.session.cookies:
                self.session_cookies[cookie.name] = cookie.value

            self._log_info(
                f"[AUTH] Session cookies acquired: {list(self.session_cookies.keys())}"
            )
            return True

        except requests.RequestException as exc:
            self._log_info(f"[AUTH] Login request failed: {exc}")
            return False

    # ──────────────────────────────────────────────
    # HTTP helper (rate-limited)
    # ──────────────────────────────────────────────

    @rate_limited(10)  # NFR2
    def _send_request(
        self, point: InputPoint, payload: str
    ) -> Optional[Response]:
        """Send a single payload-injected HTTP request including all form defaults."""
        try:
            # Reconstruct the base parameters from the form
            base_params = {}
            if "form_inputs" in point.extra_data:
                for inp in point.extra_data["form_inputs"]:
                    base_params[inp["name"]] = inp["default"]
            base_params[point.parameter] = payload

            if point.http_method.upper() == "POST":
                return self.session.post(
                    point.url, data=base_params, timeout=self.timeout
                )

            parsed = urlparse(point.url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            # Add existing URL query params to base_params
            for k, v in query.items():
                if k not in base_params:
                    base_params[k] = v[0] if v else ""
            
            base_params[point.parameter] = payload
            
            # Using safe="..." so characters like =, (, ) are NOT encoded.
            new_query = urlencode(base_params, doseq=True, safe="<>=()\"'/")
            injected = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )
            return self.session.get(injected, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("[SCAN] Request failed: %s", exc)
            return None

    # ──────────────────────────────────────────────
    # FR4: SQLi scanning
    # ──────────────────────────────────────────────

    def _scan_sqli(self, point: InputPoint) -> List[VulnerabilityFinding]:
        matches: List[VulnerabilityFinding] = []

        for payload in BASELINE_SQLI_PAYLOADS:
            self._log_info(
                f"[SQLI] Param='{point.parameter}' Payload='{payload}'"
            )
            response = self._send_request(point, payload)
            if response is None:
                continue

            # Error-based detection.
            if SQL_ERROR_REGEX.search(response.text):
                matches.append(
                    VulnerabilityFinding(
                        target_url=point.url,
                        vulnerability_type="SQL Injection (Error-based)",
                        parameter=point.parameter,
                        payload=payload,
                        http_method=point.http_method,
                        status_code=response.status_code,
                        evidence={
                            "detection_method": "error_regex",
                            "regex": SQL_ERROR_REGEX.pattern,
                        },
                    )
                )
                continue  # No need for boolean check if error already found.

            # Boolean-based cross-validation.
            true_resp = self._send_request(point, "' AND 1=1--")
            false_resp = self._send_request(point, "' AND 1=2--")

            if not true_resp or not false_resp:
                continue

            length_diff = abs(len(true_resp.text) - len(false_resp.text))
            status_diff = true_resp.status_code != false_resp.status_code

            if length_diff > 30 or status_diff:
                matches.append(
                    VulnerabilityFinding(
                        target_url=point.url,
                        vulnerability_type="SQL Injection (Boolean-based)",
                        parameter=point.parameter,
                        payload=payload,
                        http_method=point.http_method,
                        status_code=response.status_code,
                        evidence={
                            "detection_method": "boolean_cross_validation",
                            "true_status_code": true_resp.status_code,
                            "false_status_code": false_resp.status_code,
                            "true_length": len(true_resp.text),
                            "false_length": len(false_resp.text),
                            "length_diff": length_diff,
                        },
                    )
                )

        return matches

    # ──────────────────────────────────────────────
    # FR4: XSS scanning
    # ──────────────────────────────────────────────

    def _scan_xss(self, point: InputPoint) -> List[VulnerabilityFinding]:
        matches: List[VulnerabilityFinding] = []
        # Track already-confirmed (url, param) pairs to avoid duplicate reports.
        confirmed: set = set()

        for payload in BASELINE_XSS_PAYLOADS:
            self._log_info(
                f"[XSS] Param='{point.parameter}' Payload='{payload}'"
            )
            response = self._send_request(point, payload)
            if response is None:
                continue

            dedup_key = (point.url, point.parameter)

            # ── Layer 1: Reflection check (fast, no browser needed) ──────
            # If our exact marker string appears verbatim in the HTML response
            # the application is reflecting user input without encoding.
            if _XSS_MARKER in response.text and dedup_key not in confirmed:
                confirmed.add(dedup_key)
                matches.append(
                    VulnerabilityFinding(
                        target_url=point.url,
                        vulnerability_type="Reflected XSS",
                        parameter=point.parameter,
                        payload=payload,
                        http_method=point.http_method,
                        status_code=response.status_code,
                        evidence={
                            "detection_method": "reflection_check",
                            "reflected_marker": _XSS_MARKER,
                            "payload": payload,
                        },
                    )
                )
                continue  # No need for slower Selenium check on same point.

            # ── Layer 2: Selenium alert validation (definitive execution) ─
            if dedup_key not in confirmed and self._validate_xss_with_selenium(
                point, payload
            ):
                confirmed.add(dedup_key)
                matches.append(
                    VulnerabilityFinding(
                        target_url=point.url,
                        vulnerability_type="Reflected XSS",
                        parameter=point.parameter,
                        payload=payload,
                        http_method=point.http_method,
                        status_code=response.status_code,
                        evidence={
                            "detection_method": "selenium_alert",
                            "alert_detected": True,
                            "payload": payload,
                        },
                    )
                )

        return matches

    def _validate_xss_with_selenium(
        self, point: InputPoint, payload: str
    ) -> bool:
        """
        Return True if injecting *payload* into *param* triggers a JS alert.

        Session cookies (e.g., PHPSESSID for DVWA) are injected into the
        Selenium driver so the browser uses the authenticated session.
        """
        driver: Optional[webdriver.Chrome] = None
        try:
            driver = _build_headless_driver(enable_performance_logs=False)

            parsed_base = urlparse(point.url)

            # ── Inject session cookies into Selenium ─────────────────────
            # We must load the origin first before set_cookie() is accepted.
            if self.session_cookies:
                origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
                driver.get(origin)
                for name, value in self.session_cookies.items():
                    driver.add_cookie({"name": name, "value": value,
                                       "domain": parsed_base.hostname})

            # ── Intercept alert() in Headless Chrome ─────────────────────
            # Headless Chrome can miss alerts that fire immediately (like svg onload).
            # We inject a script that redefines alert() to change the document title.
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": "window.alert = function(msg) { document.title = 'XSS_TRIGGERED'; };"}
            )

            base_params = {}
            if "form_inputs" in point.extra_data:
                for inp in point.extra_data["form_inputs"]:
                    base_params[inp["name"]] = inp["default"]

            if point.http_method.upper() == "GET":
                query = parse_qs(parsed_base.query, keep_blank_values=True)
                for k, v in query.items():
                    if k not in base_params:
                        base_params[k] = v[0] if v else ""
                
                base_params[point.parameter] = payload
                
                # Use quote_via=quote so spaces become %20.
                # Use safe="..." so characters like =, (, ) are NOT encoded.
                # If they are encoded, apps using decodeURI() won't decode them back,
                # which breaks DOM XSS payloads like <svg onload=alert(1)>.
                test_url = urlunparse(
                    (
                        parsed_base.scheme,
                        parsed_base.netloc,
                        parsed_base.path,
                        parsed_base.params,
                        urlencode(base_params, doseq=True, quote_via=quote, safe="<>=()\"'/"),
                        parsed_base.fragment,
                    )
                )
                driver.get(test_url)
            else:
                base_params[point.parameter] = payload
                driver.get(point.url)
                
                # Construct JS fetch dynamically
                js_script = "const body = new URLSearchParams();\n"
                js_args = []
                idx = 0
                for k, v in base_params.items():
                    js_script += f"body.append(arguments[{idx}], arguments[{idx+1}]);\n"
                    js_args.extend([k, v])
                    idx += 2
                    
                js_script += """
                fetch(window.location.href, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: body.toString()
                });
                """
                driver.execute_script(js_script, *js_args)

            WebDriverWait(driver, 5).until(EC.title_is("XSS_TRIGGERED"))
            return True
        except TimeoutException:
            return False
        except WebDriverException as exc:
            logger.debug("[XSS][SELENIUM] %s", exc)
            return False
        finally:
            if driver is not None:
                try:
                    driver.quit()
                except Exception:  # noqa: BLE001
                    pass


# ══════════════════════════════════════════════
# Shared WebDriver factory
# ══════════════════════════════════════════════

def _build_headless_driver(enable_performance_logs: bool) -> webdriver.Chrome:
    """
    Build a Selenium Chrome WebDriver configured for headless scanning (FR4).

    Performance logs are only enabled when needed (dynamic crawl phase) to
    reduce overhead during XSS validation passes.
    """
    options = ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    # Suppress verbose browser console output.
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    if enable_performance_logs:
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    return webdriver.Chrome(options=options)


# ══════════════════════════════════════════════
# Quick smoke-test (run directly)
# ══════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Replace with your own pre-approved domain and target URL.
    engine = VulnerabilityScannerEngine(pre_approved_domains=["example.com"])
    try:
        result = engine.scan("http://localhost:8000/search?q=test")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except PermissionError as exc:
        print(f"[ERROR] {exc}")
