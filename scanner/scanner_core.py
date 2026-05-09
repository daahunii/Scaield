"""
Scanner AI Shield - Core Scanner Module

This module implements:
- Target authorization validation (FR2)
- Request rate limiting (NFR2)
- Intelligent crawler including dynamic DOM/API discovery (FR3)
- SQLi / XSS scanner core with strict verification (FR4)
- Real-time console logging (FR8)
- Structured JSON adapter layer decoupled from LLM providers (FR5, NFR3, NFR5)
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from requests import Response, Session
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


# FR4: SQLi error-based detection regex with strict patterns.
SQL_ERROR_REGEX = re.compile(r"(SQL syntax|mysql_fetch|ORA-[1-9]{4})", re.IGNORECASE)

# FR4: Baseline payloads only (no runtime AI payload generation).
BASELINE_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
]

BASELINE_XSS_PAYLOADS = [
    "<script>alert('XSS_TEST')</script>",
]


@dataclass
class InputPoint:
    """Represents a discovered injection point (FR3)."""

    url: str
    http_method: str
    parameter: str
    form_action: Optional[str] = None


@dataclass
class VulnerabilityFinding:
    """Internal structured finding before JSON adapter conversion (FR5)."""

    target_url: str
    vulnerability_type: str
    parameter: str
    payload: str
    http_method: str
    status_code: int
    evidence: Dict[str, Any]


class AuthorizedTargetValidator:
    """
    FR2: Validate targets against localhost + pre-approved domain whitelist.
    """

    def __init__(self, pre_approved_domains: Iterable[str]):
        self.pre_approved_domains: Set[str] = {d.lower().strip() for d in pre_approved_domains}

    def is_authorized(self, target_url: str) -> bool:
        parsed = urlparse(target_url)
        hostname = (parsed.hostname or "").lower()
        if hostname in {"localhost", "127.0.0.1", "::1"}:
            return True
        return hostname in self.pre_approved_domains

    def validate_or_raise(self, target_url: str) -> None:
        if not self.is_authorized(target_url):
            raise PermissionError(
                f"Unauthorized target: {target_url}. "
                "Only localhost or pre-approved domains are allowed."
            )


def rate_limited(max_requests_per_second: int = 10) -> Callable:
    """
    NFR2: Enforce max HTTP request throughput (e.g., 10 req/sec) globally
    for the decorated function via delay intervals.
    """

    request_times: deque = deque()
    lock = threading.Lock()

    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with lock:
                now = time.time()
                window_start = now - 1.0
                while request_times and request_times[0] < window_start:
                    request_times.popleft()

                if len(request_times) >= max_requests_per_second:
                    sleep_for = request_times[0] + 1.0 - now
                    if sleep_for > 0:
                        time.sleep(sleep_for)
                    now = time.time()
                    window_start = now - 1.0
                    while request_times and request_times[0] < window_start:
                        request_times.popleft()

                request_times.append(time.time())
            return func(*args, **kwargs)

        return wrapper

    return decorator


class IntelligentCrawler:
    """
    FR3: Discover sub-links, form inputs, dynamic DOM state, and async API traces.
    """

    def __init__(self, session: Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self.last_visited_urls: List[str] = []
        self.last_form_inputs: List[Dict[str, str]] = []

    @rate_limited(10)  # NFR2
    def _http_get(self, url: str) -> Response:
        return self.session.get(url, timeout=self.timeout)

    def crawl(self, base_url: str, max_pages: int = 20) -> List[InputPoint]:
        discovered_points: List[InputPoint] = []
        visited: Set[str] = set()
        queue: deque = deque([base_url])
        discovered_forms: List[Dict[str, str]] = []

        while queue and len(visited) < max_pages:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            try:
                response = self._http_get(current)
            except requests.RequestException:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # FR3: Query parameters as attack surface.
            parsed = urlparse(current)
            for param in parse_qs(parsed.query).keys():
                discovered_points.append(
                    InputPoint(url=current, http_method="GET", parameter=param)
                )

            # FR3: Form input discovery.
            for form in soup.find_all("form"):
                method = (form.get("method") or "GET").upper()
                action = form.get("action") or current
                action_url = urljoin(current, action)
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    name = input_tag.get("name")
                    if name:
                        discovered_forms.append(
                            {
                                "url": action_url,
                                "method": method,
                                "parameter": name,
                            }
                        )
                        discovered_points.append(
                            InputPoint(
                                url=action_url,
                                http_method=method,
                                parameter=name,
                                form_action=action_url,
                            )
                        )

            # FR3: Sub-link discovery.
            for anchor in soup.find_all("a", href=True):
                next_url = urljoin(current, anchor["href"])
                if urlparse(next_url).netloc == urlparse(base_url).netloc:
                    if next_url not in visited:
                        queue.append(next_url)

        # FR3: Dynamic DOM + async API communication inspection.
        discovered_points.extend(self._crawl_dynamic(base_url))
        self.last_visited_urls = sorted(visited)
        self.last_form_inputs = self._deduplicate_form_inputs(discovered_forms)
        return self._deduplicate_points(discovered_points)

    def _crawl_dynamic(self, base_url: str) -> List[InputPoint]:
        points: List[InputPoint] = []
        driver = _build_headless_driver(enable_performance_logs=True)
        try:
            driver.get(base_url)
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            # Dynamic DOM form discovery after JS rendering.
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                method = (form.get_attribute("method") or "GET").upper()
                action = form.get_attribute("action") or base_url
                for selector in ["input[name]", "textarea[name]", "select[name]"]:
                    elements = form.find_elements(By.CSS_SELECTOR, selector)
                    for elem in elements:
                        name = elem.get_attribute("name")
                        if name:
                            points.append(
                                InputPoint(
                                    url=action,
                                    http_method=method,
                                    parameter=name,
                                    form_action=action,
                                )
                            )

            # Async API traces via browser performance logs.
            try:
                for entry in driver.get_log("performance"):
                    message = json.loads(entry["message"])["message"]
                    if message.get("method") != "Network.requestWillBeSent":
                        continue
                    request = message.get("params", {}).get("request", {})
                    req_url = request.get("url", "")
                    if not req_url:
                        continue
                    parsed = urlparse(req_url)
                    for param in parse_qs(parsed.query).keys():
                        points.append(InputPoint(url=req_url, http_method="GET", parameter=param))
            except Exception:
                # Performance log availability varies by driver/browser version.
                pass
        finally:
            driver.quit()
        return points

    @staticmethod
    def _deduplicate_points(points: List[InputPoint]) -> List[InputPoint]:
        unique: Dict[str, InputPoint] = {}
        for p in points:
            key = f"{p.http_method}|{p.url}|{p.parameter}"
            unique[key] = p
        return list(unique.values())

    @staticmethod
    def _deduplicate_form_inputs(form_inputs: List[Dict[str, str]]) -> List[Dict[str, str]]:
        unique: Dict[str, Dict[str, str]] = {}
        for item in form_inputs:
            key = f"{item['method']}|{item['url']}|{item['parameter']}"
            unique[key] = item
        return list(unique.values())


class ScannerJSONAdapter:
    """
    FR5, NFR3, NFR5:
    Converts internal findings into a standard LLM-independent JSON structure.
    """

    @staticmethod
    def to_standard_json(finding: VulnerabilityFinding) -> Dict[str, Any]:
        return asdict(finding)

    @staticmethod
    def to_standard_json_list(findings: List[VulnerabilityFinding]) -> List[Dict[str, Any]]:
        return [ScannerJSONAdapter.to_standard_json(f) for f in findings]


class VulnerabilityScannerEngine:
    """
    Core scanner orchestrator for FR4 with FR8 logging.
    """

    def __init__(
        self,
        pre_approved_domains: Iterable[str],
        timeout: int = 10,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.session = requests.Session()
        self.timeout = timeout
        self.validator = AuthorizedTargetValidator(pre_approved_domains)
        self.crawler = IntelligentCrawler(self.session, timeout=timeout)
        self.adapter = ScannerJSONAdapter()
        self.log_callback = log_callback
        self.last_scan_context: Dict[str, Any] = {"sub_links": [], "input_forms": []}

    def _log_info(self, message: str) -> None:
        # FR8: keep terminal logging while supporting dashboard stream callbacks.
        print(message)
        if self.log_callback:
            self.log_callback(message)

    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        # FR2: target authorization gate.
        self.validator.validate_or_raise(target_url)
        findings: List[VulnerabilityFinding] = []
        input_points = self.crawler.crawl(target_url)
        self.last_scan_context = {
            "sub_links": self.crawler.last_visited_urls,
            "input_forms": self.crawler.last_form_inputs,
        }

        for point in input_points:
            findings.extend(self._scan_sqli(point))
            findings.extend(self._scan_xss(point))

        # FR5/NFR5: return only standardized JSON records.
        return self.adapter.to_standard_json_list(findings)

    @rate_limited(10)  # NFR2
    def _send_request(
        self, url: str, method: str, param: str, payload: str
    ) -> Optional[Response]:
        try:
            if method.upper() == "POST":
                return self.session.post(url, data={param: payload}, timeout=self.timeout)

            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            new_query = urlencode(query, doseq=True)
            injected_url = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )
            return self.session.get(injected_url, timeout=self.timeout)
        except requests.RequestException:
            return None

    def _scan_sqli(self, point: InputPoint) -> List[VulnerabilityFinding]:
        matches: List[VulnerabilityFinding] = []
        for payload in BASELINE_SQLI_PAYLOADS:
            # FR8: real-time console logging.
            self._log_info(f"[INFO] Testing {payload} on parameter '{point.parameter}'")

            response = self._send_request(point.url, point.http_method, point.parameter, payload)
            if response is None:
                continue

            # FR4 SQLi Error-based detection
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
                continue

            # FR4 SQLi Boolean-based cross verification
            true_payload = "' AND 1=1--"
            false_payload = "' AND 1=2--"
            true_resp = self._send_request(point.url, point.http_method, point.parameter, true_payload)
            false_resp = self._send_request(point.url, point.http_method, point.parameter, false_payload)

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

    def _scan_xss(self, point: InputPoint) -> List[VulnerabilityFinding]:
        matches: List[VulnerabilityFinding] = []
        for payload in BASELINE_XSS_PAYLOADS:
            # FR8: real-time console logging.
            self._log_info(f"[INFO] Testing {payload} on parameter '{point.parameter}'")

            response = self._send_request(point.url, point.http_method, point.parameter, payload)
            if response is None:
                continue

            # FR4 XSS validation with Selenium alert_is_present()
            alert_detected = self._validate_xss_with_selenium(
                point.url, point.http_method, point.parameter, payload
            )
            if alert_detected:
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
                        },
                    )
                )
        return matches

    def _validate_xss_with_selenium(
        self, url: str, method: str, param: str, payload: str
    ) -> bool:
        driver = _build_headless_driver(enable_performance_logs=False)
        try:
            test_url = url
            if method.upper() == "GET":
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                query[param] = [payload]
                new_query = urlencode(query, doseq=True)
                test_url = urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment,
                    )
                )
                driver.get(test_url)
            else:
                # For POST, execute JS fetch to preserve method semantics in browser context.
                driver.get(url)
                script = """
                    const p = arguments[0];
                    const v = arguments[1];
                    const body = new URLSearchParams();
                    body.append(p, v);
                    fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: body.toString()
                    });
                """
                driver.execute_script(script, param, payload)

            WebDriverWait(driver, 5).until(EC.alert_is_present())
            return True
        except TimeoutException:
            return False
        finally:
            driver.quit()


def _build_headless_driver(enable_performance_logs: bool) -> webdriver.Chrome:
    """Build Selenium Chrome WebDriver configured for headless scanning (FR4)."""

    options = ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    if enable_performance_logs:
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    return webdriver.Chrome(options=options)


if __name__ == "__main__":
    # Example usage only. Replace with your own approved domains / target.
    engine = VulnerabilityScannerEngine(pre_approved_domains=["example.com"])
    try:
        result = engine.scan("http://localhost:8000/search?q=test")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except PermissionError as exc:
        print(f"[ERROR] {exc}")
