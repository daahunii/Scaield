#!/usr/bin/env python3
"""
pipeline/run.py — Scaield 통합 파이프라인

  Step 1 : scanner_core 크롤링 → 입력점(InputPoint) 수집
  Step 2 : pentest/engine.py 취약점 스캔
  Step 3 : 결과 JSON 파일 저장
  Step 4 : AI 리포트 생성

사용 예시:
  python run.py --url http://127.0.0.1:5000
  python run.py --url http://127.0.0.1:5000 --output results.json
  python run.py --url http://127.0.0.1:5000 --timeout 15
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
_LLM_DIR     = _ROOT / "LLMmodule"

for _p in (_SCANNER_DIR, _PENTEST_DIR, _LLM_DIR):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

# ---------------------------------------------------------------------------
# 모듈 임포트
# ---------------------------------------------------------------------------

from scanner_core import VulnerabilityScannerEngine, LoginConfig
from engine import ScannerEngine as PentestEngine
from adapter import findings_to_ai_input

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

    # ── 현재 날짜 및 순차적 고유 버전 찾기 ──────────────────────────────
    date_str = datetime.now().strftime("%Y%m%d")
    version = 1
    base_dir = output_path.parent
    while True:
        results_file = base_dir / f"results_{date_str}_v{version}.json"
        report_json_file = base_dir / f"report_{date_str}_v{version}.json"
        report_md_file = base_dir / f"report_{date_str}_v{version}.md"
        if not results_file.exists() and not report_json_file.exists() and not report_md_file.exists():
            break
        version += 1

    # ── Step 3: 결과 저장 ─────────────────────────────────────────────────
    output = {
        "meta": {
            "target_url":     target_url,
            "scanned_at":     datetime.now().isoformat(timespec="seconds"),
            "input_points":   len(form_inputs),
            "total_findings": len(results),
        },
        "findings": results,
    }
    results_file.write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log(f"[Step 3] 결과 저장 완료: {results_file}")

    # ── Step 4: AI 리포트 생성 ─────────────────────────────────────────────
    log("[Step 4] AI 리포트 생성 시작")
    try:
        from llm import generate_report
        ai_report = generate_report(output)
        
        # JSON 포맷 여부 확인 후 적절히 저장
        try:
            cleaned_report = ai_report.strip()
            if cleaned_report.startswith("```"):
                lines = cleaned_report.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                cleaned_report = "\n".join(lines).strip()
            
            parsed_json = json.loads(cleaned_report)
            
            # report json 내에 날짜 정보(scanned_at) 주입
            parsed_json["scanned_at"] = datetime.now().isoformat(timespec="seconds")
            
            report_json_file.write_text(
                json.dumps(parsed_json, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            log(f"[Step 4] AI 리포트 저장 완료 (JSON): {report_json_file}")
        except Exception:
            # JSON 파싱 실패 시 일반 텍스트/MD 형식으로 저장
            report_md_file.write_text(ai_report, encoding="utf-8")
            log(f"[Step 4] AI 리포트 저장 완료 (MD/TXT): {report_md_file}")
    except Exception as exc:
        log(f"[Step 4] AI 리포트 생성 오류: {exc}")
        return 1

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
