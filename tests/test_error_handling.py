from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in [str(_ROOT / "pentest"), str(_ROOT / "scanner")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from engine import ScannerEngine
from http_client import ScanHttpClient
from models import InputPoint
from rate_limiter import RateLimiter, RateLimiterError
from scanner_core import VulnerabilityScannerEngine


def _free_port() -> int:
    """Return a TCP port that nothing is listening on."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_get_point(url: str, param: str) -> InputPoint:
    return InputPoint(url=url, method="GET", param_name=param,
                      param_type="query", original_value="")


# ══════════════════════════════════════════════════════════════════════
# 1. Connection refused
# ══════════════════════════════════════════════════════════════════════

class TestConnectionRefused:

    def test_scanner_returns_empty_on_refused(self):
        """Scanning a port with nothing listening returns empty findings without crashing."""
        port = _free_port()
        target = _make_get_point(f"http://127.0.0.1:{port}/test", "q")

        engine = ScannerEngine(config={})
        findings = []
        for scanner in engine.scanners:
            findings.extend(scanner.scan(target))

        assert findings == []

    def test_http_client_returns_none_on_refused(self):
        """ScanHttpClient.request() returns None on connection failure."""
        port = _free_port()
        client = ScanHttpClient(RateLimiter())
        resp = client.request("GET", f"http://127.0.0.1:{port}/test")
        assert resp is None


# ══════════════════════════════════════════════════════════════════════
# 2. Timeout
# ══════════════════════════════════════════════════════════════════════

class TestTimeout:

    def test_http_client_returns_none_on_timeout(self, target_server: str):
        """request() returns None when the server takes longer than the timeout."""
        client = ScanHttpClient(RateLimiter(), timeout=1)
        resp = client.request("GET", f"{target_server}/slow?delay=3")
        assert resp is None

    def test_scanner_returns_empty_on_timeout(self, target_server: str):
        """Scanning a slow endpoint returns empty findings without crashing."""
        engine = ScannerEngine(config={})
        short_client = ScanHttpClient(RateLimiter(), timeout=1)
        for scanner in engine.scanners:
            scanner.http = short_client

        target = _make_get_point(f"{target_server}/slow?delay=3", "delay")
        findings = []
        for scanner in engine.scanners:
            findings.extend(scanner.scan(target))

        assert findings == []


# ══════════════════════════════════════════════════════════════════════
# 3. Unauthorized domain
# ══════════════════════════════════════════════════════════════════════

class TestUnauthorizedDomain:

    def test_raises_permission_error_for_external_domain(self):
        """Scanning an unapproved external domain raises PermissionError."""
        engine = VulnerabilityScannerEngine(pre_approved_domains=["localhost"])
        with pytest.raises(PermissionError):
            engine.scan("http://evil.example.com/page")

    def test_authorized_domain_does_not_raise(self, target_server: str):
        """An approved domain does not raise PermissionError."""
        engine = VulnerabilityScannerEngine(
            pre_approved_domains=["127.0.0.1"],
            timeout=3,
        )
        try:
            engine.scan(f"{target_server}/safe?name=test")
        except PermissionError:
            pytest.fail("PermissionError raised for an approved domain")

    def test_localhost_always_authorized(self):
        """localhost is always permitted even with an empty pre_approved_domains list."""
        engine = VulnerabilityScannerEngine(pre_approved_domains=[])
        try:
            engine.scan("http://localhost:9999/nonexistent")
        except PermissionError:
            pytest.fail("localhost must always be authorized")
        except Exception:
            pass  # other errors (connection, etc.) are acceptable


# ══════════════════════════════════════════════════════════════════════
# 4. Rate limiter integration
# ══════════════════════════════════════════════════════════════════════

class TestRateLimiterIntegration:

    def test_scanner_continues_after_rate_limit_error(self):
        """
        After hitting the consecutive-failure threshold, scan() returns empty
        results without propagating RateLimiterError.
        """
        port = _free_port()
        rl = RateLimiter(fail_threshold=2)
        client = ScanHttpClient(rl, timeout=1)

        engine = ScannerEngine(config={})
        for scanner in engine.scanners:
            scanner.http = client

        target = _make_get_point(f"http://127.0.0.1:{port}/test", "q")
        findings = []
        for scanner in engine.scanners:
            findings.extend(scanner.scan(target))

        assert findings == []


# ══════════════════════════════════════════════════════════════════════
# 5. ScanHttpClient direct error handling
# ══════════════════════════════════════════════════════════════════════

class TestScanHttpClient:

    def test_request_returns_none_not_raises_on_network_error(self):
        """Network errors are caught internally; request() returns None."""
        port = _free_port()
        client = ScanHttpClient(RateLimiter())
        result = client.request("GET", f"http://127.0.0.1:{port}/")
        assert result is None

    def test_request_returns_none_on_invalid_scheme(self):
        """An unsupported URL scheme results in None, not an exception."""
        client = ScanHttpClient(RateLimiter())
        result = client.request("GET", "ftp://localhost/file")
        assert result is None

    def test_success_increments_no_failure_count(self, target_server: str):
        """A successful response resets the consecutive-failure counter to 0."""
        rl = RateLimiter(fail_threshold=3)
        client = ScanHttpClient(rl, timeout=5)
        resp = client.request("GET", f"{target_server}/safe?name=test")
        assert resp is not None
        assert rl._consecutive_failures == 0
