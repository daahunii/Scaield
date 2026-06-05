"""
test_backend_api.py — FR1: backend_bridge/app.py Flask API 테스트

대상
----
backend_bridge/app.py의 REST 엔드포인트:
  GET  /health
  POST /scan/start
  GET  /scan/<id>/status
  GET  /scan/<id>/result

검증 항목
---------
1. GET /health → 200, status: "ok"
2. POST /scan/start (target_url 포함) → scan_id 반환, status: "running"
3. POST /scan/start (target_url 없음) → 400 에러
4. GET /scan/<unknown_id>/status → 404
5. GET /scan/<id>/result (스캔 미완료) → 409
6. POST /scan/start + GET /scan/<id>/status → 상태 필드 존재
7. scan_type 필드 포함 요청 → 오류 없이 400/200 처리

실행
----
    pytest tests/test_backend_api.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# ── backend_bridge 경로 추가 ──────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
_BACKEND_DIR = _ROOT / "backend_bridge"
_PENTEST_DIR = _ROOT / "pentest"
_SCANNER_DIR = _ROOT / "scanner"

for _p in [str(_BACKEND_DIR), str(_PENTEST_DIR), str(_SCANNER_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ══════════════════════════════════════════════════════════════════════
# Flask 테스트 클라이언트 fixture
# ══════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def api_client():
    """
    backend_bridge/app.py Flask 앱의 테스트 클라이언트를 반환한다.

    실제 스캔 스레드(_run_scan)는 각 테스트에서 patch로 차단한다.
    """
    import app as bridge_app
    bridge_app.app.config["TESTING"] = True
    with bridge_app.app.test_client() as client:
        yield client


# ══════════════════════════════════════════════════════════════════════
# 1. GET /health
# ══════════════════════════════════════════════════════════════════════

class TestHealth:

    def test_health_returns_200(self, api_client):
        """GET /health는 HTTP 200을 반환해야 한다."""
        resp = api_client.get("/health")
        assert resp.status_code == 200

    def test_health_status_ok(self, api_client):
        """GET /health 응답 JSON에 status: 'ok'가 있어야 한다."""
        resp = api_client.get("/health")
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_health_has_service_field(self, api_client):
        """GET /health 응답에 service 필드가 있어야 한다."""
        resp = api_client.get("/health")
        data = resp.get_json()
        assert "service" in data


# ══════════════════════════════════════════════════════════════════════
# 2. POST /scan/start — 정상 요청
# ══════════════════════════════════════════════════════════════════════

class TestScanStart:

    def test_start_returns_scan_id(self, api_client):
        """POST /scan/start (target_url 포함) 시 scan_id가 반환돼야 한다."""
        with patch("app._run_scan"):  # 실제 스캔 스레드 실행 차단
            resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "scan_id" in data
        assert data["scan_id"]  # 빈 문자열이 아님

    def test_start_returns_running_status(self, api_client):
        """POST /scan/start 응답의 status는 'running'이어야 한다."""
        with patch("app._run_scan"):
            resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        data = resp.get_json()
        assert data["status"] == "running"

    def test_start_with_scan_type_field_accepted(self, api_client):
        """scan_type 필드를 포함해도 오류 없이 처리돼야 한다 (무시 또는 허용)."""
        with patch("app._run_scan"):
            resp = api_client.post(
                "/scan/start",
                json={
                    "target_url": "http://127.0.0.1:9999/test",
                    "scan_type": "all",
                },
                content_type="application/json",
            )
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════
# 3. POST /scan/start — 잘못된 요청
# ══════════════════════════════════════════════════════════════════════

class TestScanStartValidation:

    def test_missing_target_url_returns_400(self, api_client):
        """target_url 없이 POST /scan/start 시 HTTP 400을 반환해야 한다."""
        resp = api_client.post(
            "/scan/start",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_empty_target_url_returns_400(self, api_client):
        """target_url이 빈 문자열이면 HTTP 400을 반환해야 한다."""
        resp = api_client.post(
            "/scan/start",
            json={"target_url": ""},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_400_response_has_error_field(self, api_client):
        """400 응답 JSON에 error 필드가 있어야 한다."""
        resp = api_client.post(
            "/scan/start",
            json={},
            content_type="application/json",
        )
        data = resp.get_json()
        assert "error" in data


# ══════════════════════════════════════════════════════════════════════
# 4. GET /scan/<id>/status
# ══════════════════════════════════════════════════════════════════════

class TestScanStatus:

    def test_unknown_scan_id_returns_404(self, api_client):
        """존재하지 않는 scan_id로 상태 조회 시 HTTP 404를 반환해야 한다."""
        resp = api_client.get("/scan/nonexistent-id-xyz/status")
        assert resp.status_code == 404

    def test_known_scan_id_returns_status_fields(self, api_client):
        """정상 생성된 scan_id의 상태 응답에 필수 필드가 있어야 한다."""
        with patch("app._run_scan"):
            start_resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        scan_id = start_resp.get_json()["scan_id"]

        resp = api_client.get(f"/scan/{scan_id}/status")
        assert resp.status_code == 200
        data = resp.get_json()
        for field in ("scan_id", "status", "progress", "current_step"):
            assert field in data, f"status 응답 필수 필드 누락: {field}"

    def test_status_scan_id_matches(self, api_client):
        """상태 응답의 scan_id는 요청한 scan_id와 일치해야 한다."""
        with patch("app._run_scan"):
            start_resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        scan_id = start_resp.get_json()["scan_id"]
        resp = api_client.get(f"/scan/{scan_id}/status")
        assert resp.get_json()["scan_id"] == scan_id


# ══════════════════════════════════════════════════════════════════════
# 5. GET /scan/<id>/result — 스캔 미완료 시 409
# ══════════════════════════════════════════════════════════════════════

class TestScanResult:

    def test_result_before_completion_returns_409(self, api_client):
        """스캔이 완료되기 전 result 조회 시 HTTP 409를 반환해야 한다."""
        with patch("app._run_scan"):
            start_resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        scan_id = start_resp.get_json()["scan_id"]

        # _run_scan을 mock으로 차단했으므로 status는 'queued' 또는 'running' 상태
        resp = api_client.get(f"/scan/{scan_id}/result")
        assert resp.status_code == 409

    def test_unknown_scan_id_result_returns_404(self, api_client):
        """존재하지 않는 scan_id로 결과 조회 시 HTTP 404를 반환해야 한다."""
        resp = api_client.get("/scan/nonexistent-id-xyz/result")
        assert resp.status_code == 404

    def test_completed_scan_result_returns_200(self, api_client):
        """완료 상태로 직접 설정된 스캔의 result 조회는 200을 반환해야 한다."""
        import app as bridge_app
        import uuid

        scan_id = str(uuid.uuid4())
        bridge_app.SCANS[scan_id] = {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "current_step": "완료",
            "logs": [],
            "error": None,
            "result": {
                "scan_id": scan_id,
                "vulnerabilities": [],
                "risk_level": "Low",
            },
            "payload": {},
            "started_at": "2026-01-01T00:00:00",
        }
        resp = api_client.get(f"/scan/{scan_id}/result")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scan_id"] == scan_id
