"""
ai/llm_analyzer.py — AI 분석 모듈 (파이프 앤 필터 4번째 필터)

Pipe & Filter 아키텍처에서 JSON 어댑터 → [LLMAnalyzer] → 대시보드/PDF 리포트
위치에 해당하는 핵심 모듈.

입력  : findings_to_ai_input() 이 생성한 취약점 증거 dict (또는 list[dict])
출력  : AnalysisReport (Pydantic 모델) — 프론트엔드가 바로 렌더링 가능한 JSON

주요 요구사항:
  - NFR3  : 할루시네이션 방지 — 시스템 프롬프트로 Evidence 기반 분석만 허용
  - NFR4  : OWASP 시큐어 코딩 가이드 기반 수정 코드 제시
  - FR5   : 모든 출력에 면책 조항(disclaimer) 강제 포함
  - NFR5  : 어댑터 패턴으로 LLM Provider 교체 용이
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

from .providers import BaseLLMProvider, create_provider
from .prompts import SYSTEM_PROMPT_TEMPLATE, USER_PROMPT_TEMPLATE
from .schemas import AnalysisReport, DISCLAIMER_TEXT

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
# 예외 클래스
# ══════════════════════════════════════════════════════════════════════

class LLMAnalysisError(Exception):
    """LLM 분석 과정에서 발생하는 모든 오류의 베이스."""
    pass


class LLMAPIError(LLMAnalysisError):
    """LLM API 호출 자체가 실패한 경우."""
    pass


class LLMParsingError(LLMAnalysisError):
    """LLM 응답 JSON 파싱 또는 스키마 검증 실패."""
    pass


# ══════════════════════════════════════════════════════════════════════
# LLMAnalyzer — 메인 분석 클래스
# ══════════════════════════════════════════════════════════════════════

class LLMAnalyzer:
    """취약점 증거 데이터를 LLM 으로 분석하여 구조화된 보안 코칭 리포트를 생성한다.

    Attributes
    ----------
    provider : BaseLLMProvider
        실제 LLM API 호출을 담당하는 어댑터 (OpenAI / Gemini / …)
    prompt_template : str
        시스템 프롬프트 템플릿 (NFR3 할루시네이션 방지 규칙 포함)
    max_retries : int
        JSON 파싱 실패 시 재시도 횟수
    retry_delay : float
        재시도 간격 (초)
    temperature : float
        LLM 생성 온도 (낮을수록 결정적 응답)

    Examples
    --------
    >>> analyzer = LLMAnalyzer(
    ...     provider_name="openai",
    ...     api_key="sk-...",
    ...     model="gpt-4o-mini",
    ... )
    >>> report = analyzer.analyze(evidence_dict)
    >>> print(report.model_dump_json(indent=2))
    """

    def __init__(
        self,
        provider_name: str = "openai",
        api_key: str = "",
        model: Optional[str] = None,
        *,
        max_retries: int = 2,
        retry_delay: float = 1.0,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        provider_instance: Optional[BaseLLMProvider] = None,
    ) -> None:
        """LLMAnalyzer 초기화.

        Parameters
        ----------
        provider_name : "openai" | "gemini" — 사용할 LLM 벤더
        api_key       : 해당 벤더의 API Key
        model         : 모델명 (None이면 Provider 기본값)
        max_retries   : JSON 파싱 실패 시 최대 재시도 횟수
        retry_delay   : 재시도 간 대기 시간 (초)
        temperature   : LLM 생성 온도
        max_tokens    : 최대 응답 토큰 수
        provider_instance : 이미 생성된 Provider를 직접 주입 (테스트용)
        """
        # NFR5: 어댑터 패턴 — Provider 인스턴스 생성 또는 주입
        if provider_instance is not None:
            self.provider: BaseLLMProvider = provider_instance
        else:
            self.provider = create_provider(
                provider_name=provider_name,
                api_key=api_key,
                model=model,
            )

        # 프롬프트 설정
        self.prompt_template: str = SYSTEM_PROMPT_TEMPLATE

        # 생성 파라미터
        self.temperature: float = temperature
        self.max_tokens: int = max_tokens

        # 재시도 설정
        self.max_retries: int = max_retries
        self.retry_delay: float = retry_delay

    # ──────────────────────────────────────────────────────────────────
    # 프롬프트 생성
    # ──────────────────────────────────────────────────────────────────

    def _generate_system_prompt(self) -> str:
        """NFR3 할루시네이션 방지 규칙이 포함된 시스템 프롬프트를 반환한다.

        시스템 프롬프트에는:
          - Evidence 기반 분석만 허용하는 Grounding Rules
          - 소스코드/파일명 추측 금지
          - OWASP 시큐어 코딩 가이드 기반 예시 요구
          - 면책 조항 강제 포함
          - 출력 JSON 스키마 명세
        가 모두 포함되어 있다.
        """
        return self.prompt_template

    def _generate_user_prompt(self, evidence: Dict[str, Any]) -> str:
        """취약점 증거 데이터를 User Prompt로 래핑한다.

        Parameters
        ----------
        evidence : adapter.finding_to_ai_input() 이 반환한 dict

        Returns
        -------
        str : LLM에 전달할 사용자 프롬프트
        """
        evidence_json = json.dumps(evidence, ensure_ascii=False, indent=2)
        return USER_PROMPT_TEMPLATE.format(evidence_json=evidence_json)

    # ──────────────────────────────────────────────────────────────────
    # LLM 호출 + 파싱
    # ──────────────────────────────────────────────────────────────────

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """LLM API를 호출하고 원시 텍스트 응답을 반환한다.

        Raises
        ------
        LLMAPIError : API 호출 자체가 실패한 경우
        """
        try:
            return self.provider.chat_completion(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        except Exception as exc:
            raise LLMAPIError(
                f"LLM API 호출 실패 ({type(exc).__name__}): {exc}"
            ) from exc

    def _parse_response(self, raw_response: str) -> AnalysisReport:
        """LLM 응답 문자열을 AnalysisReport 로 파싱한다.

        Pydantic 모델이 스키마를 강제하므로 누락/타입 불일치를 자동 감지한다.
        disclaimer 필드가 누락되거나 비어있으면 기본 면책 조항으로 교체한다.

        Raises
        ------
        LLMParsingError : JSON 파싱 또는 스키마 검증 실패
        """
        # JSON 파싱 시도
        try:
            # LLM 이 ```json ... ``` 으로 감싸는 경우 처리
            cleaned = raw_response.strip()
            if cleaned.startswith("```"):
                # 첫 줄(```json)과 마지막 줄(```) 제거
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1])

            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise LLMParsingError(
                f"LLM 응답 JSON 파싱 실패: {exc}\n"
                f"원본 응답 (앞 500자): {raw_response[:500]}"
            ) from exc

        # FR5: disclaimer 강제 보장
        if not data.get("disclaimer"):
            data["disclaimer"] = DISCLAIMER_TEXT

        # Pydantic 스키마 검증
        try:
            return AnalysisReport.model_validate(data)
        except Exception as exc:
            raise LLMParsingError(
                f"LLM 응답 스키마 검증 실패: {exc}\n"
                f"파싱된 데이터: {json.dumps(data, ensure_ascii=False, indent=2)[:500]}"
            ) from exc

    # ──────────────────────────────────────────────────────────────────
    # 폴백 리포트
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_fallback_report(
        evidence: Dict[str, Any],
        error_message: str,
    ) -> AnalysisReport:
        """LLM 호출/파싱이 모든 재시도에서 실패했을 때 반환할 폴백 리포트.

        최소한의 정보라도 프론트엔드에 전달하여 빈 화면을 방지한다.
        """
        vuln_type = evidence.get("vulnerability_type", "Unknown")
        parameter = evidence.get("parameter", "N/A")
        target_url = evidence.get("target_url", "N/A")

        return AnalysisReport(
            vulnerability_summary=f"[AI 분석 실패] {vuln_type} — {target_url} (param: {parameter})",
            root_cause=f"AI 분석 중 오류가 발생하여 자동 원인 분석을 수행할 수 없습니다. "
                       f"오류: {error_message}",
            attack_scenario="AI 분석 실패로 인해 공격 시나리오를 자동 생성할 수 없습니다. "
                            "보안 전문가의 수동 분석이 필요합니다.",
            risk_level="Medium",
            secure_code_example="AI 분석 실패로 인해 수정 코드를 자동 생성할 수 없습니다. "
                                "OWASP Cheat Sheet(https://cheatsheetseries.owasp.org)를 참고하세요.",
            validation_steps="1. AI 서비스 상태 및 API Key 확인\n"
                             "2. 재스캔 수행\n"
                             "3. 수동 분석 진행",
            disclaimer=DISCLAIMER_TEXT,
        )

    # ──────────────────────────────────────────────────────────────────
    # 퍼블릭 API
    # ──────────────────────────────────────────────────────────────────

    def analyze(self, evidence: Dict[str, Any]) -> AnalysisReport:
        """단일 취약점 증거를 분석하여 AnalysisReport 를 반환한다.

        Parameters
        ----------
        evidence : adapter.finding_to_ai_input() 이 반환한 dict
            {
              "target_url": "...",
              "vulnerability_type": "Reflected XSS",
              "parameter": "name",
              "payload": "<script>alert('XSS_TEST')</script>",
              "http_method": "GET",
              "status_code": 200,
              "response_body_excerpt": "...",
              "confidence": "high",
              "evidence": {
                "detection_method": "reflection_check",
                "detail": "..."
              }
            }

        Returns
        -------
        AnalysisReport : 구조화된 보안 코칭 리포트
            JSON 파싱/스키마 오류가 max_retries 이후에도 해결되지 않으면
            폴백 리포트를 반환한다 (빈 응답 방지).
        """
        system_prompt = self._generate_system_prompt()
        user_prompt = self._generate_user_prompt(evidence)
        last_error = ""

        for attempt in range(1, self.max_retries + 2):  # 1 ~ max_retries+1
            try:
                logger.info(
                    "[LLMAnalyzer] 분석 시도 %d/%d — %s (param=%s)",
                    attempt, self.max_retries + 1,
                    evidence.get("target_url", "?"),
                    evidence.get("parameter", "?"),
                )

                raw_response = self._call_llm(system_prompt, user_prompt)
                report = self._parse_response(raw_response)

                logger.info(
                    "[LLMAnalyzer] 분석 성공 — risk_level=%s",
                    report.risk_level.value,
                )
                return report

            except LLMAPIError as exc:
                last_error = str(exc)
                logger.error("[LLMAnalyzer] API 오류 (시도 %d): %s", attempt, exc)
                # API 에러는 재시도 의미가 적으나, 일시적 오류일 수 있으므로 1회 재시도
                if attempt <= self.max_retries:
                    time.sleep(self.retry_delay * attempt)  # 점진적 백오프
                    continue
                break

            except LLMParsingError as exc:
                last_error = str(exc)
                logger.warning(
                    "[LLMAnalyzer] 파싱 오류 (시도 %d): %s", attempt, exc
                )
                if attempt <= self.max_retries:
                    time.sleep(self.retry_delay)
                    continue
                break

            except Exception as exc:
                last_error = f"예상치 못한 오류: {exc}"
                logger.exception("[LLMAnalyzer] 알 수 없는 오류 (시도 %d)", attempt)
                break

        # 모든 재시도 실패 → 폴백 리포트
        logger.error(
            "[LLMAnalyzer] 모든 시도 실패 — 폴백 리포트 생성. 마지막 오류: %s",
            last_error,
        )
        return self._build_fallback_report(evidence, last_error)

    def analyze_batch(
        self,
        evidences: List[Dict[str, Any]],
        *,
        progress_callback: Optional[callable] = None,
    ) -> List[AnalysisReport]:
        """여러 취약점 증거를 순차 분석한다.

        Parameters
        ----------
        evidences         : adapter.findings_to_ai_input() 이 반환한 list[dict]
        progress_callback : (current_index, total, report) 를 받는 콜백

        Returns
        -------
        list[AnalysisReport] : 각 취약점에 대한 분석 리포트
        """
        reports: List[AnalysisReport] = []
        total = len(evidences)

        for i, evidence in enumerate(evidences, 1):
            logger.info(
                "[LLMAnalyzer] 배치 분석 %d/%d — %s",
                i, total, evidence.get("vulnerability_type", "?"),
            )
            report = self.analyze(evidence)
            reports.append(report)

            if progress_callback:
                try:
                    progress_callback(i, total, report)
                except Exception:
                    logger.warning("[LLMAnalyzer] progress_callback 오류 무시")

        return reports

    def analyze_to_json(
        self,
        evidences: List[Dict[str, Any]],
        *,
        indent: int = 2,
    ) -> str:
        """여러 취약점 증거를 분석하고 결과를 JSON 문자열로 반환한다.

        파이프라인 Step 4 에서 직접 호출하여 JSON 파일로 저장할 수 있다.
        """
        reports = self.analyze_batch(evidences)
        return json.dumps(
            [r.model_dump() for r in reports],
            ensure_ascii=False,
            indent=indent,
        )
