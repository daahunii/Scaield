#!/usr/bin/env python3
"""
pipeline/run.py — Scaield 통합 파이프라인

  Step 1 : scanner_core 크롤링 → 입력점(InputPoint) 수집
  Step 2 : pentest/engine.py 취약점 스캔
  Step 3 : AI 분석 (LLMAnalyzer) → 보안 코칭 리포트 생성
  Step 4 : 결과 JSON 파일 저장

사용 예시:
  python run.py --url http://127.0.0.1:5000
  python run.py --url http://127.0.0.1:5000 --output results.json
  python run.py --url http://127.0.0.1:5000 --ai-provider gemini --ai-key AIza...
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# sys.path 설정
# ---------------------------------------------------------------------------

_ROOT        = Path(__file__).resolve().parent.parent   # Scaield/
_SCANNER_DIR = _ROOT / "scanner"
_PENTEST_DIR = _ROOT / "pentest"
_AI_DIR      = _ROOT / "ai"

for _p in (_SCANNER_DIR, _PENTEST_DIR, _ROOT):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

# ---------------------------------------------------------------------------
# 모듈 임포트
# ---------------------------------------------------------------------------

from scanner_core import VulnerabilityScannerEngine, LoginConfig
from engine import ScannerEngine as PentestEngine
from adapter import findings_to_ai_input
from ai import LLMAnalyzer

# ---------------------------------------------------------------------------
# 파이프라인
# ---------------------------------------------------------------------------

def run_pipeline(
    target_url: str,
    approved_domains: list[str],
    timeout: int,
    output_path: Path,
    login_config: LoginConfig | None = None,
    ai_provider: str = "",
    ai_key: str = "",
    ai_model: str = "",
) -> int:
    def log(msg: str) -> None:
        print(msg, file=sys.stderr)

    # ── Step 1: 크롤링 ────────────────────────────────────────────────────
    log(f"[Step 1] 크롤링 시작 → {target_url}")
    try:
        scanner = VulnerabilityScannerEngine(
            pre_approved_domains=approved_domains,
            timeout=timeout,
            log_callback=log,
            login_config=login_config,
        )
        scanner.validator.validate_or_raise(target_url)
        form_inputs = scanner.scan(target_url)
        log(f"[Step 1] 완료 — 입력점 {len(form_inputs)}개 수집")
    except PermissionError as exc:
        log(f"[Step 1] 인가되지 않은 타겟: {exc}")
        return 1
    except Exception as exc:
        log(f"[Step 1] 크롤링 오류: {exc}")
        return 1

    if not form_inputs:
        log("[Step 1] 수집된 입력점이 없습니다. 종료합니다.")
        return 1

    # ── Step 2: 취약점 스캔 ───────────────────────────────────────────────
    log(f"[Step 2] 취약점 스캔 시작 ({len(form_inputs)}개 입력점)")
    try:
        pentest_engine = PentestEngine(config={
            "session_cookies": scanner.session.cookies.get_dict()
        })
        findings = pentest_engine.run_from_form_inputs(form_inputs)
        results = findings_to_ai_input(findings)
        log(f"[Step 2] 완료 — 취약점 {len(results)}건 탐지")
    except Exception as exc:
        log(f"[Step 2] 스캔 오류: {exc}")
        return 1

    # ── Step 3: AI 분석 (선택) ─────────────────────────────────────────────
    ai_reports = []
    if ai_provider and ai_key:
        log(f"[Step 3] AI 분석 시작 — provider={ai_provider}, 취약점 {len(results)}건")
        try:
            analyzer = LLMAnalyzer(
                provider_name=ai_provider,
                api_key=ai_key,
                model=ai_model or None,
            )

            def _progress(i: int, total: int, report: object) -> None:
                log(f"[Step 3] AI 분석 {i}/{total} 완료")

            reports = analyzer.analyze_batch(results, progress_callback=_progress)
            ai_reports = [r.model_dump() for r in reports]
            log(f"[Step 3] AI 분석 완료 — {len(ai_reports)}건 리포트 생성")
        except Exception as exc:
            log(f"[Step 3] AI 분석 오류 (스킵): {exc}")
    else:
        log("[Step 3] AI 분석 스킵 (--ai-provider / --ai-key 미지정)")

    # ── Step 4: 결과 저장 ─────────────────────────────────────────────────
    output = {
        "meta": {
            "target_url":     target_url,
            "scanned_at":     datetime.now().isoformat(timespec="seconds"),
            "input_points":   len(form_inputs),
            "total_findings": len(results),
        },
        "findings": results,
    }
    if ai_reports:
        output["ai_analysis"] = ai_reports

    output_path.write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log(f"[Step 4] 결과 저장 완료: {output_path}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python run.py",
        description="Scaield 파이프라인 — 크롤링 → 펜테스팅 → JSON 저장",
    )
    parser.add_argument("--url", required=True, help="스캔 대상 URL")
    parser.add_argument(
        "--approved-domains", default="", metavar="DOMAINS",
        help="쉼표 구분 허용 도메인 (localhost는 자동 포함)",
    )
    parser.add_argument(
        "--timeout", type=int, default=10, metavar="SEC",
        help="HTTP 요청 타임아웃 (초, 기본 10)",
    )
    parser.add_argument(
        "--output", default="results.json", metavar="PATH",
        help="결과 JSON 저장 경로 (기본 results.json)",
    )
    parser.add_argument(
        "--login-url", default="", help="자동 로그인을 수행할 URL"
    )
    parser.add_argument(
        "--login-user-field", default="username", help="로그인 폼의 아이디 필드명 (기본: username)"
    )
    parser.add_argument(
        "--login-pass-field", default="password", help="로그인 폼의 비밀번호 필드명 (기본: password)"
    )
    parser.add_argument(
        "--login-user", default="", help="자동 로그인용 아이디"
    )
    parser.add_argument(
        "--login-pass", default="", help="자동 로그인용 비밀번호"
    )
    parser.add_argument(
        "--ai-provider", default="", help="AI 분석 LLM 제공자 (openai / gemini)"
    )
    parser.add_argument(
        "--ai-key", default="", help="LLM API Key"
    )
    parser.add_argument(
        "--ai-model", default="", help="LLM 모델명 (기본: 제공자별 기본값)"
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    approved_domains = [d.strip() for d in args.approved_domains.split(",") if d.strip()]
    
    login_cfg = None
    if args.login_url and args.login_user and args.login_pass:
        login_cfg = LoginConfig(
            login_url=args.login_url,
            username_field=args.login_user_field,
            password_field=args.login_pass_field,
            username_value=args.login_user,
            password_value=args.login_pass,
        )

    sys.exit(
        run_pipeline(
            target_url=args.url,
            approved_domains=approved_domains,
            timeout=args.timeout,
            output_path=Path(args.output),
            login_config=login_cfg,
            ai_provider=args.ai_provider,
            ai_key=args.ai_key,
            ai_model=args.ai_model,
        )
    )


if __name__ == "__main__":
    main()
