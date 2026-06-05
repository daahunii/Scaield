"""
test_error_handling.py — 스캐너 에러 핸들링 테스트

대상 시나리오
-------------
1. 연결 불가 서버 (Connection Refused)
   → ScannerEngine이 빈 findings 반환 (크래시 없음)

2. 타임아웃 서버 (Slow Response)
   → ScanHttpClient가 None 반환 (크래시 없음)

3. 비인가 도메인 스캔
   → VulnerabilityScannerEngine이 PermissionError 발생

4. Rate Limiter 연속 실패
   → RateLimiterError 발생 후 스캐너가 조용히 빈 결과 반환

5. ScanHttpClient 연결 실패
   → request() 반환값이 None (예외 전파 없음)
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

# ── 경로 추가 ────────────────────────────────────────────────────────
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
    """아무것도 리슨하지 않는 빈 TCP 포트를 반환한다."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_get_point(url: str, param: str) -> InputPoint:
    return InputPoint(url=url, method="GET", param_name=param,
                      param_type="query", original_value="")


# ══════════════════════════════════════════════════════════════════════
# 1. 연결 불가 서버
# ══════════════════════════════════════════════════════════════════════

class TestConnectionRefused:

    def test_scanner_returns_empty_on_refused(self):
        """연결이 거부된 포트 대상으로 스캔 시 빈 findings 반환 (크래시 없음)."""
        port = _free_port()  # 아무것도 없는 포트
        target = _make_get_point(f"http://127.0.0.1:{port}/test", "q")

        engine = ScannerEngine(config={})
        findings = []
        for scanner in engine.scanners:
            findings.extend(scanner.scan(target))

        assert findings == []

    def test_http_client_returns_none_on_refused(self):
        """ScanHttpClient.request()가 연결 실패 시 None을 반환한다."""
        port = _free_port()
        client = ScanHttpClient(RateLimiter())
        resp = client.request("GET", f"http://127.0.0.1:{port}/test")
        assert resp is None


# ══════════════════════════════════════════════════════════════════════
# 2. 타임아웃 서버
# ══════════════════════════════════════════════════════════════════════

class TestTimeout:

    def test_http_client_returns_none_on_timeout(self, target_server: str):
        """응답이 timeout보다 느린 서버에 요청 시 None 반환."""
        client = ScanHttpClient(RateLimiter(), timeout=1)
        resp = client.request("GET", f"{target_server}/slow?delay=3")
        assert resp is None

    def test_scanner_returns_empty_on_timeout(self, target_server: str):
        """타임아웃 서버에 스캔 시 빈 findings 반환 (크래시 없음)."""
        # ScanHttpClient timeout=1로 ScannerEngine 내부를 교체
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
# 3. 비인가 도메인
# ══════════════════════════════════════════════════════════════════════

class TestUnauthorizedDomain:

    def test_raises_permission_error_for_external_domain(self):
        """사전 승인되지 않은 외부 도메인 스캔 시 PermissionError 발생."""
        engine = VulnerabilityScannerEngine(pre_approved_domains=["localhost"])
        with pytest.raises(PermissionError):
            engine.scan("http://evil.example.com/page")

    def test_authorized_domain_does_not_raise(self, target_server: str):
        """승인된 도메인은 PermissionError 없이 스캔이 시작된다."""
        engine = VulnerabilityScannerEngine(
            pre_approved_domains=["127.0.0.1"],
            timeout=3,
        )
        # PermissionError 없이 실행되면 통과 (결과는 무관)
        try:
            engine.scan(f"{target_server}/safe?name=test")
        except PermissionError:
            pytest.fail("승인된 도메인인데 PermissionError 발생")

    def test_localhost_always_authorized(self):
        """localhost는 pre_approved_domains 없이도 항상 허용된다."""
        engine = VulnerabilityScannerEngine(pre_approved_domains=[])
        try:
            engine.scan("http://localhost:9999/nonexistent")
        except PermissionError:
            pytest.fail("localhost는 항상 허용돼야 함")
        except Exception:
            pass  # 연결 실패 등 다른 예외는 허용


# ══════════════════════════════════════════════════════════════════════
# 4. Rate Limiter 연속 실패
# ══════════════════════════════════════════════════════════════════════

class TestRateLimiterIntegration:

    def test_scanner_continues_after_rate_limit_error(self):
        """
        Rate Limiter 임계치 초과 시 스캐너가 크래시 없이 빈 results를 반환한다.

        ScanHttpClient는 RateLimiterError를 report_failure()에서 발생시키고,
        scanner.py의 scan()은 Exception으로 잡아 continue 처리한다.
        """
        port = _free_port()  # 연결 실패 → 연속 실패 누적
        # fail_threshold=2로 빠르게 임계치 도달
        rl = RateLimiter(fail_threshold=2)
        client = ScanHttpClient(rl, timeout=1)

        engine = ScannerEngine(config={})
        for scanner in engine.scanners:
            scanner.http = client

        target = _make_get_point(f"http://127.0.0.1:{port}/test", "q")
        findings = []
        for scanner in engine.scanners:
            findings.extend(scanner.scan(target))  # 예외 없이 완료돼야 함

        assert findings == []


# ══════════════════════════════════════════════════════════════════════
# 5. ScanHttpClient 직접 에러 핸들링
# ══════════════════════════════════════════════════════════════════════

class TestScanHttpClient:

    def test_request_returns_none_not_raises_on_network_error(self):
        """네트워크 에러 시 request()가 예외를 전파하지 않고 None을 반환한다."""
        port = _free_port()
        client = ScanHttpClient(RateLimiter())
        result = client.request("GET", f"http://127.0.0.1:{port}/")
        assert result is None  # 예외가 아닌 None

    def test_request_returns_none_on_invalid_scheme(self):
        """잘못된 스킴으로 요청 시 None 반환."""
        client = ScanHttpClient(RateLimiter())
        result = client.request("GET", "ftp://localhost/file")
        assert result is None

    def test_success_increments_no_failure_count(self, target_server: str):
        """정상 응답 수신 시 연속 실패 카운터가 리셋된다."""
        rl = RateLimiter(fail_threshold=3)
        client = ScanHttpClient(rl, timeout=5)

        # 정상 요청 → success 보고 → 카운터 0
        resp = client.request("GET", f"{target_server}/safe?name=test")
        assert resp is not None
        assert rl._consecutive_failures == 0
