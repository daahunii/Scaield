"""
test_ai_reporter.py — FR5: JSON 어댑터 + AIReporter 단위 테스트

대상
----
- pentest/adapter.py : finding_to_ai_input(), findings_to_ai_input()
- scanner/ai_reporter.py : AIReporter.analyze_all(), _analyze_one(), fallback

검증 항목
---------
1. adapter 출력 스펙 — 필수 필드 존재, VulnType 레이블 매핑
2. AIReporter.analyze_all() — Gemini 모의(mock) 로 실제 API 미호출
3. analyze_all 실패 처리 — API 오류 시 fallback 반환
4. analyze_all JSON 파싱 실패 — 잘못된 JSON 반환 시 fallback
5. _fill_missing_fields — 누락 필드 자동 채움
6. analyze_all log_callback — 진행 콜백 호출 확인
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# ── pentest / scanner 모듈 경로 추가 ─────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
for _p in [str(_ROOT / "pentest"), str(_ROOT / "scanner")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from adapter import finding_to_ai_input, findings_to_ai_input
from models import Finding, InputPoint, VulnType


# ══════════════════════════════════════════════════════════════════════
# 테스트 데이터 헬퍼
# ══════════════════════════════════════════════════════════════════════

def _make_finding(vuln_type: VulnType, param: str = "q") -> Finding:
    target = InputPoint(
        url=f"http://example.com/test?{param}=x",
        method="GET",
        param_name=param,
        param_type="query",
        original_value="",
    )
    return Finding(
        vuln_type=vuln_type,
        target=target,
        payload="<script>alert(1)</script>" if vuln_type == VulnType.XSS_REFLECTED else "' OR 1=1--",
        evidence="payload reflected" if vuln_type == VulnType.XSS_REFLECTED else "syntax error",
        confidence="high",
        status_code=200,
        raw_response="<html>...</html>",
    )


_ADAPTER_REQUIRED_FIELDS = [
    "target_url",
    "vulnerability_type",
    "parameter",
    "payload",
    "http_method",
    "status_code",
    "response_body_excerpt",
    "confidence",
    "evidence",
]


# ══════════════════════════════════════════════════════════════════════
# 1. adapter 출력 스펙
# ══════════════════════════════════════════════════════════════════════

class TestFindingToAIInput:

    def test_required_fields_present(self):
        """finding_to_ai_input() 출력에 필수 필드가 모두 존재해야 한다."""
        finding = _make_finding(VulnType.XSS_REFLECTED)
        result = finding_to_ai_input(finding)

        for field in _ADAPTER_REQUIRED_FIELDS:
            assert field in result, f"필수 필드 누락: {field}"

    def test_xss_vuln_type_label(self):
        """XSS_REFLECTED → 'Reflected XSS' 문자열 매핑."""
        result = finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))
        assert result["vulnerability_type"] == "Reflected XSS"

    def test_sqli_error_vuln_type_label(self):
        """SQLI_ERROR → 'SQL Injection (Error-based)' 문자열 매핑."""
        result = finding_to_ai_input(_make_finding(VulnType.SQLI_ERROR))
        assert result["vulnerability_type"] == "SQL Injection (Error-based)"

    def test_sqli_boolean_vuln_type_label(self):
        """SQLI_BOOLEAN → 'SQL Injection (Boolean-based)' 문자열 매핑."""
        result = finding_to_ai_input(_make_finding(VulnType.SQLI_BOOLEAN))
        assert result["vulnerability_type"] == "SQL Injection (Boolean-based)"

    def test_evidence_has_detection_method(self):
        """evidence 필드에 detection_method 키가 있어야 한다."""
        result = finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))
        assert isinstance(result["evidence"], dict)
        assert "detection_method" in result["evidence"]

    def test_response_body_excerpt_truncated(self):
        """raw_response가 500자 이상일 때 response_body_excerpt는 500자로 잘려야 한다."""
        finding = _make_finding(VulnType.XSS_REFLECTED)
        finding.raw_response = "A" * 1000
        result = finding_to_ai_input(finding)
        assert len(result["response_body_excerpt"]) <= 500

    def test_findings_to_ai_input_returns_list(self):
        """findings_to_ai_input()은 Finding 목록에 대응하는 dict 목록을 반환한다."""
        findings = [
            _make_finding(VulnType.XSS_REFLECTED),
            _make_finding(VulnType.SQLI_ERROR, param="id"),
        ]
        result = findings_to_ai_input(findings)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["vulnerability_type"] == "Reflected XSS"
        assert result[1]["vulnerability_type"] == "SQL Injection (Error-based)"

    def test_empty_findings_returns_empty_list(self):
        """빈 리스트 입력 시 빈 리스트를 반환해야 한다."""
        assert findings_to_ai_input([]) == []


# ══════════════════════════════════════════════════════════════════════
# 2. AIReporter — Gemini mock으로 실제 API 미호출
# ══════════════════════════════════════════════════════════════════════

_AI_REPORTER_REQUIRED_FIELDS = [
    "vulnerability_summary",
    "root_cause",
    "risk_level",
    "attack_scenario",
    "secure_coding_guidance",
    "fixed_code_example",
    "validation_steps",
    "disclaimer",
]

def _make_mock_response(data: Dict[str, Any]) -> MagicMock:
    """Gemini API 응답을 흉내 내는 Mock 객체를 반환한다."""
    mock_resp = MagicMock()
    mock_resp.text = json.dumps(data)
    return mock_resp


def _sample_ai_response() -> Dict[str, Any]:
    return {
        "vulnerability_summary": "XSS 취약점 발견",
        "root_cause": "입력값 미이스케이프",
        "risk_level": "High",
        "attack_scenario": "세션 탈취",
        "secure_coding_guidance": "escape() 사용",
        "fixed_code_example": "return escape(user_input)",
        "validation_steps": "페이로드 재주입 후 미실행 확인",
        "disclaimer": "참고용 리포트",
    }


class TestAIReporterAnalyzeAll:

    @pytest.fixture(autouse=True)
    def patch_genai(self):
        """genai.Client를 mock으로 대체해 실제 API 호출을 차단한다."""
        with patch("ai_reporter.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.models.generate_content.return_value = _make_mock_response(
                _sample_ai_response()
            )
            self.mock_client = mock_client
            yield

    def _make_reporter(self):
        from ai_reporter import AIReporter
        return AIReporter(api_key="test-key-fake")

    def test_analyze_all_returns_list(self):
        """analyze_all()은 입력 finding 수와 같은 길이의 리스트를 반환한다."""
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        assert isinstance(result, list)
        assert len(result) == 1

    def test_analyze_all_adds_ai_analysis_key(self):
        """각 결과 dict에 'ai_analysis' 키가 추가돼야 한다."""
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        assert "ai_analysis" in result[0]

    def test_ai_analysis_has_required_fields(self):
        """ai_analysis dict에 필수 필드가 모두 있어야 한다."""
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        ai = result[0]["ai_analysis"]
        for field in _AI_REPORTER_REQUIRED_FIELDS:
            assert field in ai, f"ai_analysis 필수 필드 누락: {field}"

    def test_ai_analysis_success_true_on_success(self):
        """정상 응답 시 ai_analysis_success는 True여야 한다."""
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        assert result[0]["ai_analysis"]["ai_analysis_success"] is True

    def test_analyze_all_preserves_original_fields(self):
        """반환된 dict에 원본 finding 필드가 그대로 유지돼야 한다."""
        reporter = self._make_reporter()
        finding_dict = finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))
        result = reporter.analyze_all([finding_dict])
        for key, val in finding_dict.items():
            assert result[0][key] == val, f"원본 필드 변조: {key}"

    def test_analyze_all_multiple_findings(self):
        """여러 finding 처리 시 각각 ai_analysis가 추가돼야 한다."""
        self.mock_client.models.generate_content.return_value = _make_mock_response(
            _sample_ai_response()
        )
        reporter = self._make_reporter()
        findings = [
            finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED)),
            finding_to_ai_input(_make_finding(VulnType.SQLI_ERROR, param="id")),
        ]
        result = reporter.analyze_all(findings)
        assert len(result) == 2
        assert all("ai_analysis" in r for r in result)

    def test_log_callback_called_for_each_finding(self):
        """log_callback이 finding 수만큼 호출돼야 한다."""
        reporter = self._make_reporter()
        findings = [
            finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED)),
            finding_to_ai_input(_make_finding(VulnType.SQLI_BOOLEAN, param="id")),
        ]
        callback = MagicMock()
        reporter.analyze_all(findings, log_callback=callback)
        assert callback.call_count == 2


# ══════════════════════════════════════════════════════════════════════
# 3. APIReporter 실패 처리
# ══════════════════════════════════════════════════════════════════════

class TestAIReporterFallback:

    def _make_reporter(self):
        from ai_reporter import AIReporter
        return AIReporter(api_key="test-key-fake")

    def test_api_error_returns_fallback(self):
        """Gemini API 호출 중 예외 발생 시 fallback ai_analysis가 반환돼야 한다."""
        with patch("ai_reporter.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.models.generate_content.side_effect = Exception("API 오류")

            reporter = self._make_reporter()
            findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
            result = reporter.analyze_all(findings)

            ai = result[0]["ai_analysis"]
            assert ai["ai_analysis_success"] is False

    def test_invalid_json_response_returns_fallback(self):
        """Gemini가 잘못된 JSON을 반환하면 fallback ai_analysis가 반환돼야 한다."""
        with patch("ai_reporter.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            bad_resp = MagicMock()
            bad_resp.text = "NOT A JSON {{ invalid"
            mock_client.models.generate_content.return_value = bad_resp

            reporter = self._make_reporter()
            findings = [finding_to_ai_input(_make_finding(VulnType.SQLI_ERROR))]
            result = reporter.analyze_all(findings)

            ai = result[0]["ai_analysis"]
            assert ai["ai_analysis_success"] is False

    def test_fallback_has_all_required_fields(self):
        """fallback ai_analysis에도 필수 필드가 모두 존재해야 한다."""
        with patch("ai_reporter.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.models.generate_content.side_effect = RuntimeError("timeout")

            reporter = self._make_reporter()
            findings = [finding_to_ai_input(_make_finding(VulnType.SQLI_BOOLEAN))]
            result = reporter.analyze_all(findings)

            ai = result[0]["ai_analysis"]
            for field in _AI_REPORTER_REQUIRED_FIELDS:
                assert field in ai, f"fallback ai_analysis 필수 필드 누락: {field}"

    def test_missing_api_key_raises_environment_error(self):
        """api_key도 없고 환경변수도 없으면 EnvironmentError가 발생해야 한다."""
        import os
        from ai_reporter import AIReporter

        saved = os.environ.pop("GEMINI_API_KEY", None)
        try:
            with pytest.raises(EnvironmentError):
                AIReporter(api_key=None)
        finally:
            if saved is not None:
                os.environ["GEMINI_API_KEY"] = saved


# ══════════════════════════════════════════════════════════════════════
# 4. _fill_missing_fields 헬퍼
# ══════════════════════════════════════════════════════════════════════

class TestFillMissingFields:

    def test_fills_empty_response(self):
        """비어있는 dict에 모든 필수 필드가 채워져야 한다."""
        from ai_reporter import _fill_missing_fields
        result = _fill_missing_fields({})
        for field in _AI_REPORTER_REQUIRED_FIELDS:
            assert field in result

    def test_does_not_overwrite_existing_fields(self):
        """이미 값이 있는 필드는 덮어쓰지 않아야 한다."""
        from ai_reporter import _fill_missing_fields
        data = {"vulnerability_summary": "original value"}
        result = _fill_missing_fields(data)
        assert result["vulnerability_summary"] == "original value"
