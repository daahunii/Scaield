"""
ai_reporter.py — Stage 2: Gemini AI 기반 취약점 분석 리포터

Stage 1 (Scanner)이 생성한 VulnerabilityFinding dict 목록을 받아
각 finding에 AI 분석(ai_analysis 필드)을 추가한 dict를 반환한다.

사용 방법:
    reporter = AIReporter()                  # GEMINI_API_KEY 환경변수 사용
    reporter = AIReporter(api_key="...")     # 직접 전달
    reports  = reporter.analyze_all(findings)
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import google.generativeai as genai


# ---------------------------------------------------------------------------
# 프롬프트
# ---------------------------------------------------------------------------

_SYSTEM_INSTRUCTION = """You are a web application security consultant.
Analyze ONLY based on the provided scan evidence.
Do not infer or assume source code structure, file names, or function names
that are not present in the given data.
Base all recommendations on OWASP Secure Coding Guidelines.
Return ONLY a valid JSON object — no markdown, no explanation outside JSON."""

_REQUIRED_FIELDS = [
    "vulnerability_summary",   # 취약점 요약 (한국어)
    "root_cause",              # 발생 원인 (한국어)
    "risk_level",              # "High" | "Medium" | "Low"
    "attack_scenario",         # 공격 시나리오 (한국어)
    "secure_coding_guidance",  # 안전한 코딩 가이드 (한국어)
    "fixed_code_example",      # 수정 코드 예시 (코드 스니펫)
    "validation_steps",        # 수정 후 검증 방법 (한국어)
    "disclaimer",              # 면책 조항 (한국어)
]

_USER_PROMPT_TEMPLATE = """Scan Result (Stage 1 Scanner Output):
{finding_json}

Return a JSON object with EXACTLY these fields:
- vulnerability_summary   : 취약점 요약 (Korean)
- root_cause              : 발생 원인 (Korean)
- risk_level              : must be one of "High", "Medium", "Low"
- attack_scenario         : 공격 가능 시나리오 (Korean)
- secure_coding_guidance  : 안전한 코딩 방법 (Korean, OWASP 기반)
- fixed_code_example      : 수정 코드 예시 (code snippet, language-agnostic if no source provided)
- validation_steps        : 수정 후 재검증 방법 (Korean)
- disclaimer              : 본 리포트는 스캔 근거에 기반한 참고용이며 실제 배포 전 개발자 검토가 필요합니다.
"""


# ---------------------------------------------------------------------------
# AIReporter
# ---------------------------------------------------------------------------

class AIReporter:
    """
    Stage 1 스캐너 결과를 Gemini API에 전달해 AI 분석 리포트를 생성한다.

    Parameters
    ----------
    api_key : Gemini API 키. None 이면 환경변수 GEMINI_API_KEY를 사용한다.
    model   : 사용할 Gemini 모델명. 기본값 "gemini-1.5-flash".
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-flash",
    ) -> None:
        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise EnvironmentError(
                "Gemini API 키가 설정되지 않았습니다. "
                "환경변수 GEMINI_API_KEY를 설정하거나 api_key를 직접 전달하세요."
            )
        genai.configure(api_key=key)
        self._model = genai.GenerativeModel(
            model_name=model,
            system_instruction=_SYSTEM_INSTRUCTION,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.2,   # 낮은 temperature → 할루시네이션 감소
            ),
        )

    # ------------------------------------------------------------------
    # 공개 인터페이스
    # ------------------------------------------------------------------

    def analyze_all(
        self,
        findings: List[Dict[str, Any]],
        log_callback=None,
    ) -> List[Dict[str, Any]]:
        """
        finding 목록 전체를 AI 분석한 결과를 반환한다.
        각 dict에 'ai_analysis' 키가 추가된다.

        Parameters
        ----------
        findings     : Stage 1 ScannerJSONAdapter 출력 (list of dict)
        log_callback : 진행 메시지를 받을 콜백 함수 (Flask 대시보드용)
        """
        reports: List[Dict[str, Any]] = []
        total = len(findings)

        for i, finding in enumerate(findings, 1):
            vuln_type = finding.get("vulnerability_type", "Unknown")
            param     = finding.get("parameter", "?")
            msg = f"[AI {i}/{total}] {vuln_type} | param={param}"
            print(msg)
            if log_callback:
                log_callback(msg)

            ai_result = self._analyze_one(finding)
            reports.append({**finding, "ai_analysis": ai_result})

        return reports

    # ------------------------------------------------------------------
    # 내부 로직
    # ------------------------------------------------------------------

    def _analyze_one(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """finding 하나를 Gemini로 분석하고 ai_analysis dict를 반환한다."""
        # evidence 내 response_body 등 불필요한 대용량 필드 제거
        slim_finding = _slim_finding(finding)
        prompt = _USER_PROMPT_TEMPLATE.format(
            finding_json=json.dumps(slim_finding, ensure_ascii=False, indent=2)
        )

        try:
            response = self._model.generate_content(prompt)
            data = json.loads(response.text)
            data = _fill_missing_fields(data)
            data["ai_analysis_success"] = True
        except json.JSONDecodeError as e:
            data = _fallback_analysis(f"JSON 파싱 실패: {e}")
        except Exception as e:
            data = _fallback_analysis(f"API 호출 실패: {e}")

        return data


# ---------------------------------------------------------------------------
# 헬퍼 함수
# ---------------------------------------------------------------------------

def _slim_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    프롬프트에 포함할 finding을 핵심 필드만 남겨 토큰을 절약한다.
    raw response body 등 대용량 텍스트는 제외한다.
    """
    include_keys = {
        "target_url", "vulnerability_type", "parameter",
        "payload", "http_method", "status_code", "evidence",
    }
    return {k: v for k, v in finding.items() if k in include_keys}


def _fill_missing_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """LLM 응답에 누락된 필수 필드를 빈 문자열로 채운다."""
    for field in _REQUIRED_FIELDS:
        data.setdefault(field, "")
    return data


def _fallback_analysis(reason: str) -> Dict[str, Any]:
    """API 오류 시 반환할 기본 분석 결과."""
    return {
        "vulnerability_summary": "AI 분석을 완료하지 못했습니다.",
        "root_cause": reason,
        "risk_level": "Unknown",
        "attack_scenario": "",
        "secure_coding_guidance": "스캐너 1차 결과를 직접 검토하세요.",
        "fixed_code_example": "",
        "validation_steps": "",
        "disclaimer": "AI 분석 실패. 스캐너 결과만 참고하세요.",
        "ai_analysis_success": False,
    }
