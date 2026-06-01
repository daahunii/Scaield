"""
ai/providers.py — LLM Provider 어댑터 계층 (NFR5)

어댑터 패턴(Strategy)을 적용하여 LLM 벤더를 쉽게 교체할 수 있도록 설계.

현재 지원:
  - OpenAIProvider  : OpenAI ChatCompletion API (gpt-4o / gpt-4o-mini 등)
  - GeminiProvider  : Google Gemini API (gemini-2.0-flash 등)

추가 방법:
  1. BaseLLMProvider 를 상속
  2. chat_completion() 메서드 구현
  3. PROVIDER_REGISTRY 에 등록
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
# 추상 베이스 Provider
# ══════════════════════════════════════════════════════════════════════

class BaseLLMProvider(ABC):
    """모든 LLM Provider 가 구현해야 할 인터페이스."""

    def __init__(self, api_key: str, model: str, **kwargs: Any) -> None:
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def chat_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> str:
        """LLM 에게 메시지를 전송하고 텍스트 응답을 반환한다.

        Parameters
        ----------
        system_prompt : 시스템 역할 지시문
        user_prompt   : 사용자 입력 (취약점 증거 JSON)
        temperature   : 생성 온도 (낮을수록 결정적)
        max_tokens    : 최대 응답 토큰
        response_format : {"type": "json_object"} 등 벤더별 JSON 모드 설정

        Returns
        -------
        str : LLM 의 텍스트 응답 (JSON 문자열 기대)
        """
        ...


# ══════════════════════════════════════════════════════════════════════
# OpenAI Provider
# ══════════════════════════════════════════════════════════════════════

class OpenAIProvider(BaseLLMProvider):
    """OpenAI ChatCompletion API 어댑터.

    JSON Mode 를 활성화하여 구조화된 응답을 강제한다.
    """

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", **kwargs: Any) -> None:
        super().__init__(api_key, model, **kwargs)
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=api_key)
        except ImportError:
            raise ImportError(
                "openai 패키지가 설치되지 않았습니다. "
                "`pip install openai` 를 실행하세요."
            )

    def chat_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> str:
        # OpenAI JSON Mode: response_format={"type": "json_object"}
        fmt = response_format or {"type": "json_object"}
        logger.debug(
            "[OpenAI] model=%s temperature=%.2f max_tokens=%d",
            self.model, temperature, max_tokens,
        )
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=fmt,
        )
        content = response.choices[0].message.content
        logger.debug("[OpenAI] 응답 길이: %d chars", len(content) if content else 0)
        return content or ""


# ══════════════════════════════════════════════════════════════════════
# Google Gemini Provider
# ══════════════════════════════════════════════════════════════════════

class GeminiProvider(BaseLLMProvider):
    """Google Gemini API 어댑터.

    google-genai 패키지를 사용하며,
    generation_config 에 response_mime_type="application/json" 을 설정하여
    JSON 출력을 강제한다.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.0-flash",
        **kwargs: Any,
    ) -> None:
        super().__init__(api_key, model, **kwargs)
        try:
            from google import genai
            self._client = genai.Client(api_key=api_key)
        except ImportError:
            raise ImportError(
                "google-genai 패키지가 설치되지 않았습니다. "
                "`pip install google-genai` 를 실행하세요."
            )

    def chat_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> str:
        from google.genai import types

        logger.debug(
            "[Gemini] model=%s temperature=%.2f max_tokens=%d",
            self.model, temperature, max_tokens,
        )
        response = self._client.models.generate_content(
            model=self.model,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=temperature,
                max_output_tokens=max_tokens,
                response_mime_type="application/json",
            ),
        )
        content = response.text
        logger.debug("[Gemini] 응답 길이: %d chars", len(content) if content else 0)
        return content or ""


# ══════════════════════════════════════════════════════════════════════
# Provider 레지스트리 — 문자열 키로 Provider 인스턴스 생성
# ══════════════════════════════════════════════════════════════════════

PROVIDER_REGISTRY: Dict[str, type[BaseLLMProvider]] = {
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
}


def create_provider(
    provider_name: str,
    api_key: str,
    model: Optional[str] = None,
    **kwargs: Any,
) -> BaseLLMProvider:
    """문자열 키로 Provider 인스턴스를 생성하는 팩토리 함수.

    Parameters
    ----------
    provider_name : "openai" | "gemini"  (대소문자 무관)
    api_key       : 해당 벤더의 API Key
    model         : 사용할 모델명 (None 이면 Provider 기본값)

    Raises
    ------
    ValueError : 등록되지 않은 provider_name

    Examples
    --------
    >>> provider = create_provider("openai", api_key="sk-...", model="gpt-4o")
    >>> provider = create_provider("gemini", api_key="AIza...")
    """
    key = provider_name.strip().lower()
    if key not in PROVIDER_REGISTRY:
        available = ", ".join(sorted(PROVIDER_REGISTRY.keys()))
        raise ValueError(
            f"Unknown LLM provider '{provider_name}'. "
            f"Available: [{available}]"
        )
    cls = PROVIDER_REGISTRY[key]
    init_kwargs: Dict[str, Any] = {"api_key": api_key, **kwargs}
    if model:
        init_kwargs["model"] = model
    return cls(**init_kwargs)
