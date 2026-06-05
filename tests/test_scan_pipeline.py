"""
test_scan_pipeline.py — 스캔 파이프라인 통합 테스트

전략
----
1. target_server.py(취약/안전 엔드포인트 혼합)를 pytest fixture로 기동.
2. expected_findings.json에 정의된 ground-truth 데이터셋을 기준으로
   pentest/engine.ScannerEngine이 올바른 취약점을 탐지하는지 검증.
3. 각 엔드포인트마다 독립 테스트 케이스를 parametrize로 생성.
4. 전체 세션 종료 시 TP / FP / FN 집계 및 Precision / Recall / F1 출력.

실행
----
    cd /path/to/Scaield
    pytest tests/ -v

메트릭 정의
-----------
  TP : 취약한 엔드포인트를 정확한 vuln_type으로 탐지
  FP : 안전한 엔드포인트를 취약하다고 오탐
  FN : 취약한 엔드포인트를 탐지하지 못함
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# ── pentest 모듈 경로는 conftest.py에서 sys.path에 추가됨 ─────────────
from engine import ScannerEngine
from models import Finding, InputPoint, VulnType
from adapter import findings_to_ai_input

# ── ground-truth 데이터셋 로드 ────────────────────────────────────────
_DATASET_PATH = Path(__file__).parent / "expected_findings.json"
_DATASET: List[Dict[str, Any]] = json.loads(_DATASET_PATH.read_text(encoding="utf-8"))

# ── VulnType 레이블 → 문자열 역매핑 (adapter.py 와 동일 기준) ──────────
_VULN_LABEL = {
    VulnType.XSS_REFLECTED: "Reflected XSS",
    VulnType.SQLI_ERROR:    "SQL Injection (Error-based)",
    VulnType.SQLI_BOOLEAN:  "SQL Injection (Boolean-based)",
}

# ── 세션 전체 메트릭 누적 컨테이너 ────────────────────────────────────
_metrics: Dict[str, int] = {"tp": 0, "fp": 0, "fn": 0}


# ══════════════════════════════════════════════════════════════════════
# 헬퍼
# ══════════════════════════════════════════════════════════════════════

def _run_scan_on_endpoint(base_url: str, entry: Dict[str, Any]) -> List[str]:
    """
    단일 엔드포인트에 대해 스캔을 실행하고
    탐지된 vuln_type 문자열 목록을 반환한다.

    Parameters
    ----------
    base_url : 테스트 서버 base URL (예: "http://127.0.0.1:PORT")
    entry    : expected_findings.json 항목 하나

    Returns
    -------
    List[str]  탐지된 취약점 타입 문자열 목록
    """
    endpoint_path: str = entry["endpoint_path"]
    method: str = entry["method"].upper()
    parameter: str = entry["parameter"]

    url = f"{base_url}{endpoint_path}"
    param_type = "query" if method == "GET" else "form"

    # URL에 파라미터를 포함하지 않는다.
    # scanner._send()가 params={param_name: payload}로 직접 붙이기 때문에
    # 미리 URL에 넣으면 ?id=test&id=<payload> 형태로 중복돼 서버가 첫 값만 읽는다.
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

    detected_types = [_VULN_LABEL.get(f.vuln_type, f.vuln_type.value) for f in findings]
    return detected_types


def _compute_result(
    detected: List[str],
    expected: List[str],
) -> Dict[str, Any]:
    """
    탐지 결과와 ground-truth를 비교해 TP/FP/FN을 반환한다.

    TP : expected에 있고 detected에도 있는 vuln_type
    FN : expected에 있지만 detected에 없는 vuln_type
    FP : detected에 있지만 expected에 없는 vuln_type
    """
    detected_set = set(detected)
    expected_set = set(expected)

    tp = detected_set & expected_set
    fn = expected_set - detected_set
    fp = detected_set - expected_set

    return {
        "tp": list(tp),
        "fn": list(fn),
        "fp": list(fp),
        "tp_count": len(tp),
        "fn_count": len(fn),
        "fp_count": len(fp),
    }


# ══════════════════════════════════════════════════════════════════════
# parametrize: 각 데이터셋 항목마다 독립 테스트 케이스 생성
# ══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "entry",
    _DATASET,
    ids=[f"{e['method']}_{e['endpoint_path']}_{e['parameter']}" for e in _DATASET],
)
def test_endpoint_detection(target_server: str, entry: Dict[str, Any], request) -> None:
    """
    각 엔드포인트가 expected_findings.json 대로 탐지/미탐지되는지 검증한다.

    - 취약한 엔드포인트          : expected_vuln_types에 명시된 타입이 모두 탐지돼야 함 (FN 없음)
    - 안전한 엔드포인트          : 아무 취약점도 탐지되면 안 됨 (FP 없음)
    - known_scanner_limitation : 알려진 스캐너 한계 → xfail 마킹 (실패해도 허용)
    """
    if entry.get("known_scanner_limitation"):
        request.node.add_marker(
            pytest.mark.xfail(
                strict=False,
                reason=f"알려진 스캐너 한계: {entry['description']}",
            )
        )
    expected_vuln_types: List[str] = entry["expected_vuln_types"]
    detected_types = _run_scan_on_endpoint(target_server, entry)
    result = _compute_result(detected_types, expected_vuln_types)

    # 세션 메트릭 누적
    _metrics["tp"] += result["tp_count"]
    _metrics["fp"] += result["fp_count"]
    _metrics["fn"] += result["fn_count"]

    endpoint_label = f"[{entry['method']} {entry['endpoint_path']}?{entry['parameter']}]"

    # ── 안전한 엔드포인트 검증 (FP 허용 안 함) ──────────────────────
    if not expected_vuln_types:
        assert not detected_types, (
            f"{endpoint_label} 안전한 엔드포인트인데 취약점이 탐지됨 (FP): "
            f"{detected_types}\n설명: {entry['description']}"
        )
        return

    # ── 취약한 엔드포인트 검증 (FN 허용 안 함) ──────────────────────
    missing = result["fn"]
    assert not missing, (
        f"{endpoint_label} 탐지 누락 (FN): {missing}\n"
        f"탐지됨: {detected_types}\n"
        f"기대함: {expected_vuln_types}\n"
        f"설명: {entry['description']}"
    )


# ══════════════════════════════════════════════════════════════════════
# 세션 종료 후 종합 메트릭 출력
# ══════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session", autouse=True)
def print_metrics_at_end():
    """모든 테스트가 끝난 뒤 TP/FP/FN 및 Precision/Recall/F1을 출력한다."""
    yield  # 모든 테스트 실행 완료 후 아래 실행

    tp = _metrics["tp"]
    fp = _metrics["fp"]
    fn = _metrics["fn"]

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    separator = "=" * 52
    print(f"\n{separator}")
    print("  스캔 파이프라인 성능 메트릭 (전체 세션)")
    print(separator)
    print(f"  TP (정탐)   : {tp:>4}  — 취약 엔드포인트 정확히 탐지")
    print(f"  FP (오탐)   : {fp:>4}  — 안전 엔드포인트를 취약으로 잘못 탐지")
    print(f"  FN (미탐)   : {fn:>4}  — 취약 엔드포인트 탐지 실패")
    print(separator)
    print(f"  Precision   : {precision:.3f}  (= TP / (TP+FP))")
    print(f"  Recall      : {recall:.3f}  (= TP / (TP+FN))")
    print(f"  F1 Score    : {f1:.3f}  (조화평균)")
    print(separator)


# ══════════════════════════════════════════════════════════════════════
# API 엔드포인트 통합 테스트 (scanner/app.py Flask 테스트 클라이언트)
# ══════════════════════════════════════════════════════════════════════

class TestScannerAppAPI:
    """
    scanner/app.py의 Flask 앱을 Flask 테스트 클라이언트로 직접 호출해
    동기 POST ↦ Stage 1 스캔 파이프라인 전체를 검증한다.

    target_server fixture가 제공하는 외부 서버 URL을 target_url로 사용한다.
    """

    @pytest.fixture(scope="class")
    def flask_client(self):
        """scanner/app.py Flask 앱의 테스트 클라이언트를 반환한다."""
        _scanner_dir = Path(__file__).parent.parent / "scanner"
        if str(_scanner_dir) not in sys.path:
            sys.path.insert(0, str(_scanner_dir))

        # scanner/app.py를 import하기 전에 pentest 경로가 sys.path에 있어야 함
        import app as scanner_app
        scanner_app.app.config["TESTING"] = True
        with scanner_app.app.test_client() as client:
            yield client

    def test_post_scan_returns_200(self, flask_client, target_server: str) -> None:
        """POST / 요청이 200을 반환하고 HTML 응답이 있어야 한다."""
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
        """인가되지 않은 도메인으로의 스캔 요청은 에러 메시지를 포함해야 한다."""
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
        # 인가 실패는 에러 메시지로 처리됨
        assert "인가되지 않은" in body or "Unauthorized" in body or "오류" in body
