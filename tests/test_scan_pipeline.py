from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# pentest module path is added by conftest.py
from engine import ScannerEngine
from models import Finding, InputPoint, VulnType
from adapter import findings_to_ai_input

_DATASET_PATH = Path(__file__).parent / "expected_findings.json"
_DATASET: List[Dict[str, Any]] = json.loads(_DATASET_PATH.read_text(encoding="utf-8"))

# VulnType enum → human-readable label (must match adapter.py)
_VULN_LABEL = {
    VulnType.XSS_REFLECTED: "Reflected XSS",
    VulnType.SQLI_ERROR:    "SQL Injection (Error-based)",
    VulnType.SQLI_BOOLEAN:  "SQL Injection (Boolean-based)",
}

_metrics: Dict[str, int] = {"tp": 0, "fp": 0, "fn": 0}


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def _run_scan_on_endpoint(base_url: str, entry: Dict[str, Any]) -> List[str]:
    """Run all scanners against a single endpoint and return detected vuln-type strings."""
    endpoint_path: str = entry["endpoint_path"]
    method: str = entry["method"].upper()
    parameter: str = entry["parameter"]

    url = f"{base_url}{endpoint_path}"
    param_type = "query" if method == "GET" else "form"

    target = InputPoint(
        url=url,
        method=method,          # type: ignore[arg-type]
        param_name=parameter,
        param_type=param_type,  # type: ignore[arg-type]
        original_value="",
    )

    engine = ScannerEngine(config={})
    findings: List[Finding] = []
    for scanner in engine.scanners:
        findings.extend(scanner.scan(target))

    return [_VULN_LABEL.get(f.vuln_type, f.vuln_type.value) for f in findings]


def _compute_result(detected: List[str], expected: List[str]) -> Dict[str, Any]:
    detected_set = set(detected)
    expected_set = set(expected)
    tp = detected_set & expected_set
    fn = expected_set - detected_set
    fp = detected_set - expected_set
    return {
        "tp": list(tp), "fn": list(fn), "fp": list(fp),
        "tp_count": len(tp), "fn_count": len(fn), "fp_count": len(fp),
    }


# ══════════════════════════════════════════════════════════════════════
# Parametrized endpoint detection tests
# ══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "entry",
    _DATASET,
    ids=[f"{e['method']}_{e['endpoint_path']}_{e['parameter']}" for e in _DATASET],
)
def test_endpoint_detection(target_server: str, entry: Dict[str, Any], request) -> None:
    """
    Verify each endpoint matches its expected_findings.json ground-truth.

    - Vulnerable endpoint : all expected vuln types must be detected (no FN)
    - Safe endpoint       : no vuln may be detected (no FP)
    - known_scanner_limitation : marked xfail — failure is tolerated and documented
    """
    if entry.get("known_scanner_limitation"):
        request.node.add_marker(
            pytest.mark.xfail(
                strict=False,
                reason=f"Known scanner limitation: {entry['description']}",
            )
        )

    expected_vuln_types: List[str] = entry["expected_vuln_types"]
    detected_types = _run_scan_on_endpoint(target_server, entry)
    result = _compute_result(detected_types, expected_vuln_types)

    _metrics["tp"] += result["tp_count"]
    _metrics["fp"] += result["fp_count"]
    _metrics["fn"] += result["fn_count"]

    endpoint_label = f"[{entry['method']} {entry['endpoint_path']}?{entry['parameter']}]"

    if not expected_vuln_types:
        assert not detected_types, (
            f"{endpoint_label} safe endpoint incorrectly flagged (FP): "
            f"{detected_types}\ndescription: {entry['description']}"
        )
        return

    missing = result["fn"]
    assert not missing, (
        f"{endpoint_label} missed vulnerabilities (FN): {missing}\n"
        f"detected: {detected_types}\n"
        f"expected: {expected_vuln_types}\n"
        f"description: {entry['description']}"
    )


# ══════════════════════════════════════════════════════════════════════
# Session-end metrics output
# ══════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session", autouse=True)
def print_metrics_at_end():
    """Print TP / FP / FN and Precision / Recall / F1 after all tests finish."""
    yield

    tp = _metrics["tp"]
    fp = _metrics["fp"]
    fn = _metrics["fn"]

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )

    sep = "=" * 52
    print(f"\n{sep}")
    print("  Scan Pipeline Performance Metrics (full session)")
    print(sep)
    print(f"  TP (True Positive)  : {tp:>4}  — Vulnerable endpoints correctly detected")
    print(f"  FP (False Positive) : {fp:>4}  — Safe endpoints incorrectly flagged")
    print(f"  FN (False Negative) : {fn:>4}  — Vulnerable endpoints missed")
    print(sep)
    print(f"  Precision   : {precision:.3f}  (= TP / (TP+FP))")
    print(f"  Recall      : {recall:.3f}  (= TP / (TP+FN))")
    print(f"  F1 Score    : {f1:.3f}  (harmonic mean)")
    print(sep)


# ══════════════════════════════════════════════════════════════════════
# scanner/app.py Flask API integration tests
# ══════════════════════════════════════════════════════════════════════

class TestScannerAppAPI:
    """
    Call scanner/app.py via Flask test client to validate the full
    synchronous POST → Stage 1 scan pipeline.
    """

    @pytest.fixture(scope="class")
    def flask_client(self):
        """
        Load scanner/app.py directly by file path to avoid the sys.modules
        conflict with backend_bridge/app.py (both are named 'app').
        Registering under a unique key ensures Flask resolves the template
        directory from scanner/templates/ correctly.
        """
        _scanner_dir = Path(__file__).parent.parent / "scanner"
        if str(_scanner_dir) not in sys.path:
            sys.path.insert(0, str(_scanner_dir))

        spec = importlib.util.spec_from_file_location(
            "scanner_app_module", str(_scanner_dir / "app.py")
        )
        scanner_app = importlib.util.module_from_spec(spec)
        sys.modules["scanner_app_module"] = scanner_app
        spec.loader.exec_module(scanner_app)
        scanner_app.app.config["TESTING"] = True
        with scanner_app.app.test_client() as client:
            yield client

    def test_post_scan_returns_200(self, flask_client, target_server: str) -> None:
        """POST / with a valid target returns HTTP 200 with an HTML body."""
        resp = flask_client.post(
            "/",
            data={
                "target_url": f"{target_server}/xss-vuln?q=test",
                "approved_domains_text": "127.0.0.1",
                "session_cookies": "",
                "timeout": "10",
                "run_ai": "",
            },
        )
        assert resp.status_code == 200
        assert b"<html" in resp.data.lower() or b"<!doctype" in resp.data.lower()

    def test_post_scan_unauthorized_target(self, flask_client) -> None:
        """POST / with an unauthorized domain returns an error message in the HTML body."""
        resp = flask_client.post(
            "/",
            data={
                "target_url": "http://evil.example.com/page",
                "approved_domains_text": "",
                "session_cookies": "",
                "timeout": "5",
                "run_ai": "",
            },
        )
        assert resp.status_code == 200
        body = resp.data.decode("utf-8", errors="replace")
        assert "인가되지 않은" in body or "Unauthorized" in body or "오류" in body
