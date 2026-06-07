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

