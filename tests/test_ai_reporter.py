from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in [str(_ROOT / "pentest"), str(_ROOT / "scanner")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from adapter import finding_to_ai_input, findings_to_ai_input
from models import Finding, InputPoint, VulnType


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
    "target_url", "vulnerability_type", "parameter", "payload",
    "http_method", "status_code", "response_body_excerpt", "confidence", "evidence",
]

_AI_REPORTER_REQUIRED_FIELDS = [
    "vulnerability_summary", "root_cause", "risk_level", "attack_scenario",
    "secure_coding_guidance", "fixed_code_example", "validation_steps", "disclaimer",
]


# ══════════════════════════════════════════════════════════════════════
# 1. Adapter output spec
# ══════════════════════════════════════════════════════════════════════

class TestFindingToAIInput:

    def test_required_fields_present(self):
        result = finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))
        for field in _ADAPTER_REQUIRED_FIELDS:
            assert field in result, f"Missing required field: {field}"

    def test_xss_vuln_type_label(self):
        result = finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))
        assert result["vulnerability_type"] == "Reflected XSS"

    def test_sqli_error_vuln_type_label(self):
        result = finding_to_ai_input(_make_finding(VulnType.SQLI_ERROR))
        assert result["vulnerability_type"] == "SQL Injection (Error-based)"

    def test_sqli_boolean_vuln_type_label(self):
        result = finding_to_ai_input(_make_finding(VulnType.SQLI_BOOLEAN))
        assert result["vulnerability_type"] == "SQL Injection (Boolean-based)"

    def test_evidence_has_detection_method(self):
        result = finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))
        assert isinstance(result["evidence"], dict)
        assert "detection_method" in result["evidence"]

    def test_response_body_excerpt_truncated(self):
        """raw_response > 500 chars is truncated to 500 in the adapter output."""
        finding = _make_finding(VulnType.XSS_REFLECTED)
        finding.raw_response = "A" * 1000
        result = finding_to_ai_input(finding)
        assert len(result["response_body_excerpt"]) <= 500

    def test_findings_to_ai_input_returns_list(self):
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
        assert findings_to_ai_input([]) == []


# ══════════════════════════════════════════════════════════════════════
# 2. AIReporter — Gemini mocked
# ══════════════════════════════════════════════════════════════════════

def _make_mock_response(data: Dict[str, Any]) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.text = json.dumps(data)
    return mock_resp


def _sample_ai_response() -> Dict[str, Any]:
    return {
        "vulnerability_summary": "XSS vulnerability detected",
        "root_cause": "Unescaped user input",
        "risk_level": "High",
        "attack_scenario": "Session hijacking",
        "secure_coding_guidance": "Use escape()",
        "fixed_code_example": "return escape(user_input)",
        "validation_steps": "Re-inject payload and verify it does not execute",
        "disclaimer": "For reference only",
    }


class TestAIReporterAnalyzeAll:

    @pytest.fixture(autouse=True)
    def patch_genai(self):
        """Replace genai.Client with a mock to prevent real API calls."""
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
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        assert isinstance(result, list)
        assert len(result) == 1

    def test_analyze_all_adds_ai_analysis_key(self):
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        assert "ai_analysis" in result[0]

    def test_ai_analysis_has_required_fields(self):
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        ai = result[0]["ai_analysis"]
        for field in _AI_REPORTER_REQUIRED_FIELDS:
            assert field in ai, f"Missing ai_analysis field: {field}"

    def test_ai_analysis_success_true_on_success(self):
        reporter = self._make_reporter()
        findings = [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
        result = reporter.analyze_all(findings)
        assert result[0]["ai_analysis"]["ai_analysis_success"] is True

    def test_analyze_all_preserves_original_fields(self):
        reporter = self._make_reporter()
        finding_dict = finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))
        result = reporter.analyze_all([finding_dict])
        for key, val in finding_dict.items():
            assert result[0][key] == val, f"Original field mutated: {key}"

    def test_analyze_all_multiple_findings(self):
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
        reporter = self._make_reporter()
        findings = [
            finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED)),
            finding_to_ai_input(_make_finding(VulnType.SQLI_BOOLEAN, param="id")),
        ]
        callback = MagicMock()
        reporter.analyze_all(findings, log_callback=callback)
        assert callback.call_count == 2


# ══════════════════════════════════════════════════════════════════════
# 3. AIReporter fallback on failure
# ══════════════════════════════════════════════════════════════════════

class TestAIReporterFallback:

    def _make_reporter(self):
        from ai_reporter import AIReporter
        return AIReporter(api_key="test-key-fake")

    def test_api_error_returns_fallback(self):
        """Gemini API exception → fallback ai_analysis with ai_analysis_success=False."""
        with patch("ai_reporter.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.models.generate_content.side_effect = Exception("API error")

            reporter = self._make_reporter()
            result = reporter.analyze_all(
                [finding_to_ai_input(_make_finding(VulnType.XSS_REFLECTED))]
            )
            assert result[0]["ai_analysis"]["ai_analysis_success"] is False

    def test_invalid_json_response_returns_fallback(self):
        """Malformed JSON from Gemini → fallback ai_analysis."""
        with patch("ai_reporter.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            bad_resp = MagicMock()
            bad_resp.text = "NOT A JSON {{ invalid"
            mock_client.models.generate_content.return_value = bad_resp

            reporter = self._make_reporter()
            result = reporter.analyze_all(
                [finding_to_ai_input(_make_finding(VulnType.SQLI_ERROR))]
            )
            assert result[0]["ai_analysis"]["ai_analysis_success"] is False

    def test_fallback_has_all_required_fields(self):
        """Fallback ai_analysis still contains all required fields."""
        with patch("ai_reporter.genai.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.models.generate_content.side_effect = RuntimeError("timeout")

            reporter = self._make_reporter()
            result = reporter.analyze_all(
                [finding_to_ai_input(_make_finding(VulnType.SQLI_BOOLEAN))]
            )
            ai = result[0]["ai_analysis"]
            for field in _AI_REPORTER_REQUIRED_FIELDS:
                assert field in ai, f"Missing fallback field: {field}"

    def test_missing_api_key_raises_environment_error(self):
        """No api_key argument and no GEMINI_API_KEY env var → EnvironmentError."""
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
# 4. _fill_missing_fields helper
# ══════════════════════════════════════════════════════════════════════

class TestFillMissingFields:

    def test_fills_empty_response(self):
        from ai_reporter import _fill_missing_fields
        result = _fill_missing_fields({})
        for field in _AI_REPORTER_REQUIRED_FIELDS:
            assert field in result

    def test_does_not_overwrite_existing_fields(self):
        from ai_reporter import _fill_missing_fields
        data = {"vulnerability_summary": "original value"}
        result = _fill_missing_fields(data)
        assert result["vulnerability_summary"] == "original value"
