"""
Scanner AI Shield - Flask Web App

2-Stage 분석 파이프라인:
  Stage 1 — VulnerabilityScannerEngine  : SQLi / XSS 탐지
  Stage 2 — AIReporter (Gemini)         : 취약점 원인·수정 방법 AI 분석

Run:
    export GEMINI_API_KEY="your-key"
    flask --app app run --debug
"""

from __future__ import annotations

import json
<<<<<<< HEAD
import os
import sys
=======
import re
import threading
import uuid
>>>>>>> 56b0fd3 (fix: modify detection failure)
from collections import Counter

# pentest 모듈 경로를 sys.path에 추가
_PENTEST_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pentest")
)
if _PENTEST_DIR not in sys.path:
    sys.path.insert(0, _PENTEST_DIR)

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify

<<<<<<< HEAD
from ai_reporter import AIReporter
from scanner_core import VulnerabilityScannerEngine
from engine import ScannerEngine as PentestScannerEngine
from adapter import findings_to_ai_input as pentest_to_ai_input
=======
from scanner_core import VulnerabilityScannerEngine, LoginConfig
>>>>>>> 56b0fd3 (fix: modify detection failure)

app = Flask(__name__)
HISTORY_PATH = Path(__file__).with_name("scan_history.json")
PENTEST_INPUT_PATH = Path(_PENTEST_DIR) / "pentest_input.json"

# In-memory store for active scans
SCANS: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# 유틸리티
# ---------------------------------------------------------------------------

def _parse_domain_input(domain_text: str) -> List[str]:
    return [d.strip() for d in domain_text.split(",") if d.strip()]


def _parse_cookies_input(cookie_text: str) -> Dict[str, str]:
    """
    Parse a cookie string (e.g., "PHPSESSID=abc123; security=low") into a dict.
    Accepts both semicolon-separated and newline-separated pairs.
    """
    cookies: Dict[str, str] = {}
    raw = cookie_text.replace("\n", ";").strip()
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            name, _, value = chunk.partition("=")
            name = name.strip()
            value = value.strip()
            if name:
                cookies[name] = value
    return cookies


def _build_login_config(
    login_url: str,
    username_field: str,
    password_field: str,
    username_value: str,
    password_value: str,
    success_marker: str,
) -> Optional[LoginConfig]:
    """Return a LoginConfig if all required login fields are filled, else None."""
    if login_url and username_field and password_field and username_value and password_value:
        return LoginConfig(
            login_url=login_url,
            username_field=username_field,
            password_field=password_field,
            username_value=username_value,
            password_value=password_value,
            success_marker=success_marker,
        )
    return None


def _extract_hostname(target_url: str) -> str:
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").strip().lower()
    # Handle absolute/relative extraction safely
    if not hostname and parsed.path:
        # e.g., if target_url didn't have scheme and parser treated host as path
        possible_host = parsed.path.split("/")[0]
        if "." in possible_host or possible_host == "localhost":
            return possible_host
    return hostname


def _build_effective_domains(target_url: str, approved_domains_text: str) -> List[str]:
    merged: List[str] = []
    # Force auto-extraction of target URL host
    target_host = _extract_hostname(target_url)
    
    # Union of localhost, auto-extracted target host, and any manually specified domains
    input_domains = _parse_domain_input(approved_domains_text) if approved_domains_text else []
    
    for domain in ["localhost", *input_domains, target_host]:
        normalized = domain.strip().lower()
        if normalized and normalized not in merged:
            merged.append(normalized)
    return merged


def _load_history() -> List[Dict[str, Any]]:
    if not HISTORY_PATH.exists():
        return []
    try:
        return json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _save_history(history: List[Dict[str, Any]]) -> None:
    HISTORY_PATH.write_text(
        json.dumps(history, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _build_chart_data(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    vuln_counter: Counter[str] = Counter()
    run_labels: List[str] = []
    run_counts: List[int] = []

    for entry in history:
        run_labels.append(entry.get("timestamp", "unknown"))
        results = entry.get("results", [])
        run_counts.append(len(results))
        for item in results:
            vuln_counter[item.get("vulnerability_type", "Unknown")] += 1

    return {
        "vuln_labels": list(vuln_counter.keys()),
        "vuln_counts": list(vuln_counter.values()),
        "run_labels": run_labels[-20:],
        "run_counts": run_counts[-20:],
    }


<<<<<<< HEAD
# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------
=======
def _run_scan_thread(scan_id: str, target_url: str, approved_domains: List[str], timeout: int,
                     session_cookies: Dict[str, Any],
                     login_config: Optional[LoginConfig] = None):
    try:
        total_injections = 0
        current_injection_index = 0

        def log_callback(message: str) -> None:
            nonlocal total_injections, current_injection_index
            SCANS[scan_id]["logs"].append(message)
            
            # Step 1: Auth
            if "[AUTH]" in message:
                SCANS[scan_id]["stage"] = message.replace("[AUTH] ", "")
                SCANS[scan_id]["progress"] = 10
            # Step 2: Initialize Crawl
            elif "Starting crawl" in message:
                SCANS[scan_id]["stage"] = "지능형 크롤러 기동 (DOM/API 공격 표면 매핑 중)..."
                SCANS[scan_id]["progress"] = 15
            
            # Step 2: Dynamic Scan
            elif "[CRAWLER][DYN]" in message:
                SCANS[scan_id]["stage"] = "SPA/비동기 API 동적 공격 표면 추적 중..."
                SCANS[scan_id]["progress"] = 30
            
            # Step 3: Injection Setup (Total count identified)
            elif "Discovered" in message and "injection point" in message:
                # e.g., "[SCAN] Discovered 5 injection point(s) across 3 page(s)."
                try:
                    match = re.search(r"Discovered (\d+) injection", message)
                    if match:
                        total_injections = int(match.group(1))
                except Exception:
                    pass
                SCANS[scan_id]["stage"] = f"공격 표면 매핑 완료 ({total_injections}개 지점 탐지)."
                SCANS[scan_id]["progress"] = 90

        engine = VulnerabilityScannerEngine(
            pre_approved_domains=approved_domains,
            timeout=timeout,
            log_callback=log_callback,
            session_cookies=session_cookies or {},
            login_config=login_config,
        )
        results = engine.scan(target_url)
        scan_context = engine.last_scan_context

        SCANS[scan_id]["results"] = results
        SCANS[scan_id]["scan_context"] = scan_context
        SCANS[scan_id]["progress"] = 100
        SCANS[scan_id]["stage"] = "스캔 완료"
        SCANS[scan_id]["status"] = "completed"

        history = _load_history()
        history.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": target_url,
                "approved_domains": approved_domains,
                "timeout": timeout,
                "results": results,
            }
        )
        _save_history(history)
    except Exception as exc:
        SCANS[scan_id]["status"] = "failed"
        SCANS[scan_id]["error"] = str(exc)
        SCANS[scan_id]["stage"] = f"스캔 실패: {exc}"


@app.route("/api/scan", methods=["POST"])
def start_scan_api():
    target_url = request.form.get("target_url", "").strip()
    approved_domains_text = request.form.get("approved_domains_text", "").strip()
    cookie_text = request.form.get("session_cookies", "").strip()
    timeout = int(request.form.get("timeout", "10"))
    login_url      = request.form.get("login_url", "").strip()
    login_ufield   = request.form.get("login_username_field", "username").strip()
    login_pfield   = request.form.get("login_password_field", "password").strip()
    login_uvalue   = request.form.get("login_username_value", "").strip()
    login_pvalue   = request.form.get("login_password_value", "").strip()
    login_marker   = request.form.get("login_success_marker", "").strip()

    if not target_url:
        return jsonify({"error": "Target URL is required"}), 400

    approved_domains = _build_effective_domains(target_url, approved_domains_text)
    session_cookies = _parse_cookies_input(cookie_text)
    login_config = _build_login_config(login_url, login_ufield, login_pfield,
                                       login_uvalue, login_pvalue, login_marker)
    scan_id = str(uuid.uuid4())

    SCANS[scan_id] = {
        "status": "running",
        "progress": 5,
        "stage": "스캔 준비 중...",
        "logs": [],
        "results": [],
        "scan_context": {"sub_links": [], "input_forms": []},
        "error": None,
        "target_url": target_url,
        "approved_domains_text": ",".join(approved_domains),
        "timeout": timeout,
        "cookie_text": cookie_text,
        "login_url": login_url,
        "login_username_field": login_ufield,
        "login_password_field": login_pfield,
        "login_username_value": login_uvalue,
        "login_password_value": login_pvalue,
        "login_success_marker": login_marker,
    }

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(scan_id, target_url, approved_domains, timeout, session_cookies, login_config),
        daemon=True
    )
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan-status/<scan_id>", methods=["GET"])
def get_scan_status(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "status": scan["status"],
        "progress": scan["progress"],
        "stage": scan["stage"],
        "logs": scan["logs"],
        "error": scan["error"]
    })

>>>>>>> 56b0fd3 (fix: modify detection failure)

@app.route("/", methods=["GET", "POST"])
def index() -> str:
    scan_logs: List[str] = []

    # Stage 1 결과 (VulnerabilityFinding dicts)
    stage1_results: List[Dict[str, Any]] = []

    # Stage 2 결과 (finding + ai_analysis 병합 dicts)
    stage2_results: List[Dict[str, Any]] = []

    error_message = ""
    success_message = ""
    ai_enabled = bool(os.environ.get("GEMINI_API_KEY"))

    target_url = "http://localhost:8000/search?q=test"
    approved_domains_text = "localhost,example.com"
    cookie_text = ""
    login_url = "http://localhost:55000/login.php"
    login_username_field = "username"
    login_password_field = "password"
    login_username_value = "admin"
    login_password_value = "password"
    login_success_marker = "index.php"
    timeout = 10
    scan_context: Dict[str, Any] = {"sub_links": [], "input_forms": []}

    # If scan_id query param is supplied, load from memory or history
    selected_scan_id = request.args.get("scan_id")
    if selected_scan_id and selected_scan_id in SCANS:
        scan = SCANS[selected_scan_id]
        target_url = scan["target_url"]
        approved_domains_text = scan["approved_domains_text"]
        cookie_text = scan.get("cookie_text", "")
        login_url             = scan.get("login_url", "")
        login_username_field  = scan.get("login_username_field", "username")
        login_password_field  = scan.get("login_password_field", "password")
        login_username_value  = scan.get("login_username_value", "")
        login_password_value  = scan.get("login_password_value", "")
        login_success_marker  = scan.get("login_success_marker", "")
        timeout = scan["timeout"]
        scan_logs = scan["logs"]
        results = scan["results"]
        scan_context = scan["scan_context"]
        if scan["status"] == "completed":
            success_message = f"스캔 완료: 공격 표면 {len(results)}건 탐지"
        elif scan["status"] == "failed":
            error_message = f"스캔 실패: {scan['error']}"
    elif request.method == "POST":
        # Keep synchronous POST active for fallback compatibility
        target_url = request.form.get("target_url", target_url).strip()
        approved_domains_text = request.form.get(
            "approved_domains_text", approved_domains_text
        ).strip()
        cookie_text = request.form.get("session_cookies", "").strip()
        login_url             = request.form.get("login_url", "").strip()
        login_username_field  = request.form.get("login_username_field", "username").strip()
        login_password_field  = request.form.get("login_password_field", "password").strip()
        login_username_value  = request.form.get("login_username_value", "").strip()
        login_password_value  = request.form.get("login_password_value", "").strip()
        login_success_marker  = request.form.get("login_success_marker", "").strip()
        timeout = int(request.form.get("timeout", timeout))
        run_ai = request.form.get("run_ai") == "on"

        approved_domains = _build_effective_domains(target_url, approved_domains_text)
        approved_domains_text = ",".join(approved_domains)
        session_cookies = _parse_cookies_input(cookie_text)
        login_config = _build_login_config(login_url, login_username_field, login_password_field,
                                           login_username_value, login_password_value, login_success_marker)

        def log_callback(message: str) -> None:
            scan_logs.append(message)

        # ── Stage 1: Scanner ───────────────────────────────────────────────
        try:
            log_callback("[Stage 1] 스캐너 시작")
            engine = VulnerabilityScannerEngine(
                pre_approved_domains=approved_domains,
                timeout=timeout,
                log_callback=log_callback,
                session_cookies=session_cookies,
                login_config=login_config,
            )
            stage1_results = engine.scan(target_url)
            scan_context = engine.last_scan_context
<<<<<<< HEAD
            log_callback(f"[Stage 1] 완료 — 취약점 {len(stage1_results)}건 탐지")

            # pentest/engine.py 연동용 입력 파일 자동 저장
            if scan_context.get("input_forms"):
                PENTEST_INPUT_PATH.write_text(
                    json.dumps(scan_context["input_forms"], ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                log_callback(f"[Stage 1] pentest 입력 파일 저장: {PENTEST_INPUT_PATH}")

        except PermissionError as exc:
            error_message = f"[Stage 1] 인가되지 않은 타겟: {exc}"
=======
            success_message = f"스캔 완료: 공격 표면 {len(results)}건 탐지"
>>>>>>> 56b0fd3 (fix: modify detection failure)

        except Exception as exc:
            error_message = f"[Stage 1] 스캔 중 오류: {exc}"

        # ── Stage 1.5: pentest/engine.py 확장 스캔 ────────────────────────
        if not error_message and scan_context.get("input_forms"):
            try:
                log_callback("[Stage 1.5] pentest 확장 스캔 시작")
                pentest_engine = PentestScannerEngine(config={})
                pentest_findings = pentest_engine.run_from_form_inputs(
                    scan_context["input_forms"]
                )
                pentest_results = pentest_to_ai_input(pentest_findings)

                # (target_url, parameter, vulnerability_type)가 같은 중복 항목 제외
                existing_keys = {
                    (r.get("target_url"), r.get("parameter"), r.get("vulnerability_type"))
                    for r in stage1_results
                }
                deduped = [
                    r for r in pentest_results
                    if (r.get("target_url"), r.get("parameter"), r.get("vulnerability_type"))
                    not in existing_keys
                ]
                stage1_results.extend(deduped)
                log_callback(
                    f"[Stage 1.5] 완료 — pentest 추가 탐지 {len(deduped)}건 "
                    f"(전체 {len(stage1_results)}건)"
                )

            except Exception as exc:
                log_callback(f"[Stage 1.5] pentest 스캔 오류 (무시하고 계속): {exc}")

        # ── Stage 2: Gemini AI 분석 ────────────────────────────────────────
        if stage1_results and run_ai:
            try:
                log_callback("[Stage 2] Gemini AI 분석 시작")
                reporter = AIReporter(log_callback=log_callback)
                stage2_results = reporter.analyze_all(
                    stage1_results,
                    log_callback=log_callback,
                )
                log_callback(f"[Stage 2] 완료 — AI 리포트 {len(stage2_results)}건 생성")
                success_message = (
                    f"스캔 완료: 취약점 {len(stage1_results)}건 탐지, "
                    f"AI 분석 {len(stage2_results)}건 완료"
                )

            except EnvironmentError as exc:
                # GEMINI_API_KEY 미설정
                log_callback(f"[Stage 2] 건너뜀 — {exc}")
                stage2_results = []
                success_message = (
                    f"스캔 완료: 취약점 {len(stage1_results)}건 탐지 "
                    f"(AI 분석 미실행: API 키 없음)"
                )

            except Exception as exc:
                log_callback(f"[Stage 2] AI 분석 오류: {exc}")
                stage2_results = []
                success_message = (
                    f"스캔 완료: 취약점 {len(stage1_results)}건 탐지 "
                    f"(AI 분석 실패: {exc})"
                )

        elif stage1_results and not run_ai:
            success_message = f"스캔 완료: 취약점 {len(stage1_results)}건 탐지 (AI 분석 미선택)"

        # ── 히스토리 저장 ─────────────────────────────────────────────────
        if stage1_results:
            history = _load_history()
            history.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": target_url,
                "approved_domains": approved_domains,
                "timeout": timeout,
                "results": stage2_results if stage2_results else stage1_results,
            })
            _save_history(history)

    # Auto-extract default domain text if approved_domains_text is not configured yet
    if target_url and (approved_domains_text == "localhost,example.com" or not approved_domains_text):
        approved_domains_text = ",".join(_build_effective_domains(target_url, ""))

    history = _load_history()
    chart_data = _build_chart_data(history)

    return render_template(
        "index.html",
        target_url=target_url,
        approved_domains_text=approved_domains_text,
        cookie_text=cookie_text,
        login_url=login_url,
        login_username_field=login_username_field,
        login_password_field=login_password_field,
        login_username_value=login_username_value,
        login_password_value=login_password_value,
        login_success_marker=login_success_marker,
        timeout=timeout,
        scan_logs=scan_logs,
        # Stage 1
        stage1_results=stage1_results,
        stage1_results_json=json.dumps(stage1_results, ensure_ascii=False, indent=2),
        # Stage 2
        stage2_results=stage2_results,
        stage2_results_json=json.dumps(stage2_results, ensure_ascii=False, indent=2),
        # 공통
        ai_enabled=ai_enabled,
        history=history[::-1],
        chart_data=chart_data,
        error_message=error_message,
        success_message=success_message,
        scan_context=scan_context,
    )


if __name__ == "__main__":
    app.run(debug=True)
