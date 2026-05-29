"""
ai/schemas.py — Pydantic 기반 LLM 출력 스키마 정의

프론트엔드(대시보드 + PDF)가 바로 렌더링할 수 있는 구조화된
보안 코칭 리포트 데이터 모델.

LLM 응답을 이 모델로 파싱함으로써:
  1. 누락 필드 즉시 감지
  2. 타입 불일치 자동 거부
  3. disclaimer 기본값 강제 포함 (FR5)
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────────────
# 면책 조항 상수 (FR5)
# ──────────────────────────────────────────────────────────────────────

DISCLAIMER_TEXT: str = (
    "본 코드는 참고용 예시이며, "
    "실제 서비스 적용 전 개발자의 검토가 필요합니다."
)


# ──────────────────────────────────────────────────────────────────────
# 위험도 열거형
# ──────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# ──────────────────────────────────────────────────────────────────────
# LLM 출력 스키마 (Pydantic v2 모델)
# ──────────────────────────────────────────────────────────────────────

class AnalysisReport(BaseModel):
    """단일 취약점에 대한 AI 보안 코칭 리포트.

    LLM JSON Mode / Structured Outputs 를 통해 이 스키마를 강제하며,
    파싱 실패 시 재시도 또는 폴백 로직이 동작한다.
    """

    vulnerability_summary: str = Field(
        ...,
        description="취약점 1줄 요약",
    )
    root_cause: str = Field(
        ...,
        description="왜 이 취약점이 발생했는지 기술적 원인 분석. "
                    "제공된 evidence 데이터에 근거해야 하며, "
                    "소스코드를 추측하거나 파일명을 지어내면 안 된다.",
    )
    attack_scenario: str = Field(
        ...,
        description="해커가 어떻게 악용할 수 있는지, 비즈니스 영향도",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="위험도: High / Medium / Low 중 택 1",
    )
    secure_code_example: str = Field(
        ...,
        description="Markdown 형식의 OWASP 시큐어 코딩 수정 코드 스니펫",
    )
    validation_steps: str = Field(
        ...,
        description="수정 후 재검증 방법",
    )
    disclaimer: str = Field(
        default=DISCLAIMER_TEXT,
        description="면책 조항 텍스트 (FR5). 항상 기본값이 포함된다.",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "vulnerability_summary": "사용자 입력이 이스케이프 없이 HTML에 반사되어 XSS 공격 가능",
                    "root_cause": "서버가 GET 파라미터 'name' 값을 HTML 응답에 삽입할 때 "
                                  "htmlspecialchars() 등의 이스케이프 처리를 수행하지 않음",
                    "attack_scenario": "공격자가 악성 JavaScript가 포함된 URL을 피해자에게 전송하면, "
                                       "피해자의 브라우저에서 세션 쿠키 탈취, 키로깅 등이 가능",
                    "risk_level": "High",
                    "secure_code_example": "```python\nfrom markupsafe import escape\n"
                                           "user_input = escape(request.args.get('name', ''))\n```",
                    "validation_steps": "1. 수정 후 동일 페이로드로 재스캔\n"
                                        "2. 응답 HTML에서 <script> 태그가 &lt;script&gt;로 "
                                        "이스케이프되었는지 확인",
                    "disclaimer": DISCLAIMER_TEXT,
                }
            ]
        }
    }
