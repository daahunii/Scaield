from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_BACKEND_DIR = _ROOT / "backend_bridge"
_PENTEST_DIR = _ROOT / "pentest"
_SCANNER_DIR = _ROOT / "scanner"

for _p in [str(_BACKEND_DIR), str(_PENTEST_DIR), str(_SCANNER_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ══════════════════════════════════════════════════════════════════════
# Flask test client fixture
# ══════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def api_client():
    """Return a Flask test client for backend_bridge/app.py."""
    import app as bridge_app
    bridge_app.app.config["TESTING"] = True
    with bridge_app.app.test_client() as client:
        yield client


# ══════════════════════════════════════════════════════════════════════
# 1. GET /health
# ══════════════════════════════════════════════════════════════════════

class TestHealth:

    def test_health_returns_200(self, api_client):
        resp = api_client.get("/health")
        assert resp.status_code == 200

    def test_health_status_ok(self, api_client):
        resp = api_client.get("/health")
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_health_has_service_field(self, api_client):
        resp = api_client.get("/health")
        data = resp.get_json()
        assert "service" in data


# ══════════════════════════════════════════════════════════════════════
# 2. POST /scan/start — valid request
# ══════════════════════════════════════════════════════════════════════

class TestScanStart:

    def test_start_returns_scan_id(self, api_client):
        with patch("app._run_scan"):  # prevent the real scan thread from running
            resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "scan_id" in data
        assert data["scan_id"]  # non-empty

    def test_start_returns_running_status(self, api_client):
        with patch("app._run_scan"):
            resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        data = resp.get_json()
        assert data["status"] == "running"

    def test_start_with_scan_type_field_accepted(self, api_client):
        """Extra scan_type field should be accepted without error."""
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
# 3. POST /scan/start — invalid request
# ══════════════════════════════════════════════════════════════════════

class TestScanStartValidation:

    def test_missing_target_url_returns_400(self, api_client):
        resp = api_client.post(
            "/scan/start",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_empty_target_url_returns_400(self, api_client):
        resp = api_client.post(
            "/scan/start",
            json={"target_url": ""},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_400_response_has_error_field(self, api_client):
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
        resp = api_client.get("/scan/nonexistent-id-xyz/status")
        assert resp.status_code == 404

    def test_known_scan_id_returns_status_fields(self, api_client):
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
            assert field in data, f"Missing required status field: {field}"

    def test_status_scan_id_matches(self, api_client):
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
# 5. GET /scan/<id>/result — scan not yet completed → 409
# ══════════════════════════════════════════════════════════════════════

class TestScanResult:

    def test_result_before_completion_returns_409(self, api_client):
        with patch("app._run_scan"):
            start_resp = api_client.post(
                "/scan/start",
                json={"target_url": "http://127.0.0.1:9999/test"},
                content_type="application/json",
            )
        scan_id = start_resp.get_json()["scan_id"]

        # _run_scan is mocked so the scan stays in 'running' state
        resp = api_client.get(f"/scan/{scan_id}/result")
        assert resp.status_code == 409

    def test_unknown_scan_id_result_returns_404(self, api_client):
        resp = api_client.get("/scan/nonexistent-id-xyz/result")
        assert resp.status_code == 404

    def test_completed_scan_result_returns_200(self, api_client):
        """Directly inject a completed scan entry and verify result returns 200."""
        import app as bridge_app
        import uuid

        scan_id = str(uuid.uuid4())
        bridge_app.SCANS[scan_id] = {
            "scan_id": scan_id,
            "status": "completed",
            "progress": 100,
            "current_step": "Done",
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
