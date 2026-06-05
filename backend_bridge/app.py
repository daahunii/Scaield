from __future__ import annotations

import os
import re
import sys
import threading
import time
import uuid
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, jsonify, request

DEFAULT_SCAIELD_ROOT = Path(__file__).resolve().parents[1]
SCAIELD_ROOT = Path(
    os.environ.get("SCAIELD_BACKEND_ROOT", str(DEFAULT_SCAIELD_ROOT))
).resolve()

for module_dir in ("scanner", "pentest", "LLMmodule"):
    module_path = str(SCAIELD_ROOT / module_dir)
    if module_path not in sys.path:
        sys.path.insert(0, module_path)

from adapter import findings_to_ai_input
from engine import ScannerEngine as PentestEngine
from scanner_core import LoginConfig, VulnerabilityScannerEngine

app = Flask(__name__)
SCANS: dict[str, dict[str, Any]] = {}


def _load_env_files() -> None:
    for env_path in (SCAIELD_ROOT / ".env", Path.cwd() / ".env", Path.cwd() / ".env.local"):
        if not env_path.exists():
            continue
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_env_files()

DEFAULT_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")


def _is_llm_package_available() -> bool:
    try:
        import google.genai  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "scaield-backend-bridge",
            "scaield_root": str(SCAIELD_ROOT),
            "llm_available": _is_llm_package_available(),
        }
    )


@app.after_request
def add_cors_headers(response):
    allowed_origins = {
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    }
    configured_origin = os.environ.get("FRONTEND_ORIGIN")
    if configured_origin:
        allowed_origins.add(configured_origin)

    request_origin = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Origin"] = (
        request_origin if request_origin in allowed_origins else "http://localhost:5173"
    )
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


@app.route("/scan/start", methods=["POST", "OPTIONS"])
def start_scan():
    if request.method == "OPTIONS":
        return ("", 204)

    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "current_step": "스캔 대기 중",
        "logs": [],
        "error": None,
        "result": None,
        "payload": payload,
        "started_at": datetime.now().isoformat(timespec="seconds"),
    }

    thread = threading.Thread(target=_run_scan, args=(scan_id,), daemon=True)
    thread.start()
    return jsonify({"scan_id": scan_id, "status": "running"})


@app.route("/scan/<scan_id>/status", methods=["GET"])
def scan_status(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify(
        {
            "scan_id": scan_id,
            "status": scan["status"],
            "progress": scan["progress"],
            "current_step": scan["current_step"],
            "logs": scan["logs"][-80:],
            "error": scan["error"],
        }
    )


@app.route("/scan/<scan_id>/result", methods=["GET"])
def scan_result(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan["status"] != "completed":
        return jsonify({"error": "Scan is not completed yet"}), 409
    return jsonify(scan["result"])


def _run_scan(scan_id: str) -> None:
    scan = SCANS[scan_id]
    payload = scan["payload"]
    started = time.monotonic()

    def log(message: str) -> None:
        print(f"[SCAN LOG] {message}", flush=True)
        scan["logs"].append(message)
        scan["current_step"] = _stage_from_log(message)
        scan["progress"] = max(scan["progress"], _progress_from_log(message))

    try:
        scan["status"] = "running"
        target_url = payload["target_url"]
        approved_domains = _approved_domains(target_url, payload.get("approved_domains", []))

        log("[Step 1] 하위 링크 크롤링 중")
        timeout = int(payload.get("timeout", 10))
        candidate_urls = _candidate_start_urls(target_url, timeout=timeout)
        log(f"[Step 1] SPA 후보 경로 {len(candidate_urls)}개 확인 중")

        form_inputs = []
        pages = []
        seen_inputs = set()
        skipped_external_count = 0
        for candidate_url in candidate_urls:
            crawler = VulnerabilityScannerEngine(
                pre_approved_domains=approved_domains,
                timeout=timeout,
                log_callback=log,
                login_config=_login_config(payload),
            )
            discovered_inputs = crawler.scan(candidate_url)
            for item in discovered_inputs:
                if not _is_same_origin(target_url, item.get("url", "")):
                    skipped_external_count += 1
                    continue
                key = (item.get("url"), item.get("method"), item.get("parameter"))
                if key in seen_inputs:
                    continue
                seen_inputs.add(key)
                form_inputs.append(item)
            pages.extend(crawler.last_scan_context.get("sub_links", []))

        if skipped_external_count:
            log(f"[SKIP] 외부 API 입력 지점 {skipped_external_count}개 제외")

        unique_pages = sorted(_dedupe_urls(pages))
        print(f"=== 발견된 페이지(서브 링크) 목록 (총 {len(unique_pages)}개) ===\n{json.dumps(unique_pages, ensure_ascii=False, indent=2)}\n===================", flush=True)
        if unique_pages:
            log(f"총 {len(unique_pages)}개의 하위 페이지(경로)를 발견했습니다.")

        findings: list[dict[str, Any]]
        if form_inputs:
            print(f"=== form_inputs ===\n{json.dumps(form_inputs, ensure_ascii=False, indent=2)}\n===================", flush=True)
            log(f"수집된 form_inputs 항목 확인 완료 (총 {len(form_inputs)}개)")
            log("[Step 2] SQL Injection/XSS Payload 주입 중")
            pentest = PentestEngine(
                config={"session_cookies": crawler.session.cookies.get_dict()}
            )
            findings = findings_to_ai_input(pentest.run_from_form_inputs(form_inputs))
        else:
            findings = []

        gemini_key_exists = bool(os.environ.get("GEMINI_API_KEY"))
        report_status = "AI 리포트 미실행"
        if findings and payload.get("run_ai", True) and gemini_key_exists:
            model_name = payload.get("ai_model") or DEFAULT_GEMINI_MODEL
            unique_findings = _dedupe_findings(findings, limit=5)
            log(
                f"[Step 3] LLM 리포트 생성 중 ({model_name}) — "
                f"{len(findings)}건 중 대표 {len(unique_findings)}건"
            )
            scan_report = _generate_scan_ai_report(
                target_url=target_url,
                form_inputs=form_inputs,
                findings=unique_findings,
                model_name=model_name,
            )
            findings = _attach_scan_report_to_findings(findings, scan_report)
            if all(
                (finding.get("ai_analysis") or {}).get("ai_analysis_success")
                for finding in findings
            ):
                report_status = "AI 리포트 생성 완료"
            else:
                report_status = f"AI 리포트 생성 실패: 모델/API 응답 확인 필요 ({model_name})"
        elif findings and payload.get("run_ai", True) and not gemini_key_exists:
            log("[Step 3] GEMINI_API_KEY 없음 — AI 리포트 생성 건너뜀")
            report_status = "AI 리포트 미생성: GEMINI_API_KEY 없음"
        elif findings:
            report_status = "AI 리포트 미생성: 요청 옵션 비활성화"

        scan["result"] = _build_frontend_result(
            scan_id=scan_id,
            target_url=target_url,
            findings=findings,
            form_inputs=form_inputs,
            pages=pages,
            started_at=scan["started_at"],
            scan_seconds=int(time.monotonic() - started),
            report_status=report_status,
        )
        scan["status"] = "completed"
        scan["progress"] = 100
        scan["current_step"] = "스캔 완료"
    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
        scan["current_step"] = f"스캔 실패: {exc}"


def _build_frontend_result(
    *,
    scan_id: str,
    target_url: str,
    findings: list[dict[str, Any]],
    form_inputs: list[dict[str, Any]],
    pages: list[str],
    started_at: str,
    scan_seconds: int,
    report_status: str,
) -> dict[str, Any]:
    vulnerabilities = [
        _normalize_vulnerability(index, item) for index, item in enumerate(findings)
    ]
    counts = Counter(vulnerability["type"] for vulnerability in vulnerabilities)

    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "scan_time": _format_duration(scan_seconds),
        "started_at": started_at,
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "total_pages": len(set(pages)),
        "tested_inputs": len(form_inputs),
        "detected_counts": dict(counts),
        "risk_level": _overall_risk(vulnerabilities),
        "report_status": report_status,
        "vulnerabilities": vulnerabilities,
    }


def _normalize_vulnerability(index: int, finding: dict[str, Any]) -> dict[str, Any]:
    ai = finding.get("ai_analysis") or {}
    evidence = finding.get("evidence") or {}
    risk = ai.get("risk_level") or _risk_from_confidence(finding.get("confidence"))

    return {
        "id": f"vuln-{index + 1}",
        "type": finding.get("vulnerability_type", "Unknown"),
        "risk_level": risk,
        "endpoint": finding.get("target_url", ""),
        "parameter": finding.get("parameter", ""),
        "payload": finding.get("payload", ""),
        "status_code": finding.get("status_code", 0),
        "evidence": evidence.get("detail") if isinstance(evidence, dict) else str(evidence),
        "detection_method": evidence.get("detection_method", "unknown")
        if isinstance(evidence, dict)
        else "unknown",
        "ai_report": _normalize_ai_report(finding, ai),
    }


def _normalize_ai_report(finding: dict[str, Any], ai: dict[str, Any]) -> dict[str, Any]:
    if ai:
        return {
            "vulnerability_summary": ai.get("vulnerability_summary", ""),
            "root_cause": ai.get("root_cause", ""),
            "risk_level": ai.get("risk_level", ""),
            "attack_scenario": ai.get("attack_scenario", ""),
            "secure_coding_guidance": ai.get("secure_coding_guidance", ""),
            "fixed_code_example": ai.get("fixed_code_example", ""),
            "validation_steps": ai.get("validation_steps", ""),
            "disclaimer": ai.get("disclaimer", ""),
        }

    vuln_type = finding.get("vulnerability_type", "Unknown")
    parameter = finding.get("parameter", "")
    return {
        "vulnerability_summary": f"{parameter} 파라미터에서 {vuln_type} 가능성이 탐지되었습니다.",
        "root_cause": "AI 분석이 아직 실행되지 않았습니다. 스캐너의 payload, 응답, evidence를 기준으로 수동 검토가 필요합니다.",
        "risk_level": _risk_from_confidence(finding.get("confidence")),
        "attack_scenario": "공격자는 취약한 입력 지점을 통해 의도하지 않은 쿼리 조작 또는 스크립트 실행을 시도할 수 있습니다.",
        "secure_coding_guidance": "OWASP 기준에 따라 입력 검증, 출력 인코딩, 파라미터 바인딩을 적용하세요.",
        "fixed_code_example": "소스코드가 제공되지 않아 특정 파일 기준 코드는 생성하지 않습니다.",
        "validation_steps": "동일 payload로 재검사하여 응답 차이 또는 스크립트 실행이 사라졌는지 확인하세요.",
        "disclaimer": "이 리포트는 외부 관측 기반 자동 결과이며 실제 반영 전 개발자 검토가 필요합니다.",
    }


def _dedupe_findings(findings: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for finding in sorted(findings, key=_finding_priority):
        key = _finding_group_key(finding)
        if key in seen:
            continue
        seen.add(key)
        unique.append({**finding, "ai_group_key": key})
        if len(unique) >= limit:
            break
    return unique


def _finding_priority(finding: dict[str, Any]) -> tuple[int, str]:
    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    return (
        confidence_rank.get(str(finding.get("confidence", "")).lower(), 3),
        str(finding.get("vulnerability_type", "")),
    )


def _finding_group_key(finding: dict[str, Any]) -> str:
    return "|".join(
        [
            str(finding.get("vulnerability_type", "Unknown")),
            str(finding.get("target_url", "")),
            str(finding.get("parameter", "")),
        ]
    )


def _generate_scan_ai_report(
    *,
    target_url: str,
    form_inputs: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    model_name: str,
) -> dict[str, Any]:
    results_data = {
        "meta": {
            "target_url": target_url,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "input_points": len(form_inputs),
            "total_findings": len(findings),
        },
        "findings": [
            {key: value for key, value in finding.items() if key != "ai_group_key"}
            for finding in findings
        ],
    }
    try:
        from llm import generate_report as generate_llm_report
    except ModuleNotFoundError as exc:
        if exc.name == "google.genai":
            return _fallback_scan_report(
                "google.genai 패키지가 설치되지 않아 AI 리포트를 생성하지 못했습니다. "
                "스캔 결과는 AI 리포트 없이 반환됩니다."
            )
        raise

    raw_report = generate_llm_report(results_data, model_name=model_name)
    if raw_report.startswith("An error occurred") or raw_report.startswith("Error:"):
        return _fallback_scan_report(raw_report)
    try:
        parsed = _json_loads_loose(raw_report)
    except json.JSONDecodeError as exc:
        return _fallback_scan_report(f"JSON 파싱 실패: {exc}")
    parsed["ai_analysis_success"] = True
    parsed["model"] = model_name
    return parsed


def _attach_scan_report_to_findings(
    findings: list[dict[str, Any]],
    scan_report: dict[str, Any],
) -> list[dict[str, Any]]:
    ai_analysis = _scan_report_to_ai_analysis(scan_report)
    return [
        {
            **finding,
            "ai_analysis": ai_analysis,
        }
        for finding in findings
    ]


def _scan_report_to_ai_analysis(scan_report: dict[str, Any]) -> dict[str, Any]:
    dashboard = scan_report.get("dashboard_view", {})
    pdf = scan_report.get("pdf_report_view", {})
    return {
        "vulnerability_summary": dashboard.get("brief_summary", ""),
        "root_cause": pdf.get("technical_root_cause", ""),
        "risk_level": dashboard.get("risk_level", "Unknown"),
        "attack_scenario": pdf.get("business_impact_scenario", ""),
        "secure_coding_guidance": pdf.get("remediation_guidance", ""),
        "fixed_code_example": pdf.get("secure_code_example", ""),
        "validation_steps": "\n".join(pdf.get("validation_checklist", [])),
        "disclaimer": pdf.get("disclaimer", ""),
        "ai_analysis_success": bool(scan_report.get("ai_analysis_success")),
        "model": scan_report.get("model", DEFAULT_GEMINI_MODEL),
    }


def _fallback_scan_report(reason: str) -> dict[str, Any]:
    return {
        "dashboard_view": {
            "vulnerability_title": "AI 분석 실패",
            "risk_level": "Unknown",
            "affected_parameter": "",
            "brief_summary": "AI 리포트를 생성하지 못했습니다.",
        },
        "pdf_report_view": {
            "technical_root_cause": reason,
            "business_impact_scenario": "",
            "secure_code_example": "",
            "remediation_guidance": "스캐너 1차 결과를 직접 검토하세요.",
            "validation_checklist": [],
            "disclaimer": "AI 분석 실패. 스캐너 결과만 참고하세요.",
        },
        "ai_analysis_success": False,
    }


def _fill_ai_fields(data: dict[str, Any]) -> dict[str, Any]:
    defaults = _fallback_ai_analysis("")
    defaults.pop("ai_analysis_success", None)
    defaults.pop("ai_group_key", None)
    for key, value in defaults.items():
        data.setdefault(key, value)
    return data


def _fallback_ai_analysis(reason: str) -> dict[str, Any]:
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


def _json_loads_loose(text: str) -> Any:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        repaired = _escape_invalid_json_backslashes(cleaned)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError as repaired_exc:
            raise json.JSONDecodeError(
                f"{exc.msg}; repair failed: {repaired_exc.msg}",
                cleaned,
                exc.pos,
            ) from repaired_exc


def _escape_invalid_json_backslashes(text: str) -> str:
    valid_escape_chars = set('"\\/bfnrtu')
    output = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            output.append(char)
            index += 1
            continue

        next_char = text[index + 1] if index + 1 < len(text) else ""
        if next_char in valid_escape_chars:
            output.append(char)
        else:
            output.append("\\\\")
        index += 1
    return "".join(output)


def _safe_gemini_error(response: requests.Response) -> str:
    redacted_url = response.url
    if "key=" in redacted_url:
        redacted_url = re.sub(r"key=[^&]+", "key=REDACTED", redacted_url)
    try:
        detail = response.json()
    except ValueError:
        detail = response.text
    return f"{redacted_url} {detail}"


def _dedupe_strings(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _approved_domains(target_url: str, extra_domains: Any) -> list[str]:
    parsed = urlparse(target_url)
    domains = ["localhost", "127.0.0.1"]
    if parsed.hostname:
        domains.append(parsed.hostname)
    if isinstance(extra_domains, str):
        domains.extend(item.strip() for item in extra_domains.split(","))
    elif isinstance(extra_domains, list):
        domains.extend(str(item).strip() for item in extra_domains)
    return sorted({domain for domain in domains if domain})


def _candidate_start_urls(target_url: str, timeout: int) -> list[str]:
    candidates = [target_url]
    try:
        response = requests.get(target_url, timeout=timeout)
        response.raise_for_status()
    except Exception:
        return candidates

    script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text)
    for script_url in script_urls:
        absolute_script_url = urljoin(target_url, script_url)
        if not _is_same_origin(target_url, absolute_script_url):
            continue
        try:
            script_response = requests.get(absolute_script_url, timeout=timeout)
        except Exception:
            continue
        for route in _extract_spa_routes(script_response.text):
            absolute_route = urljoin(target_url, route)
            if _is_same_origin(target_url, absolute_route):
                candidates.append(absolute_route)

    return _dedupe_urls(candidates)


def _extract_spa_routes(script_text: str) -> list[str]:
    routes = set()
    for match in re.finditer(r'["\'](/[^"\']{1,80})["\']', script_text):
        route = match.group(1)
        if route.startswith(("/static/", "/manifest", "/favicon", "/sun.png")):
            continue
        if "/:" in route or route.endswith("/:id"):
            continue
        if re.search(r"\.(png|jpg|jpeg|gif|svg|css|js|woff|ico)$", route):
            continue
        routes.add(route)
    preferred = ["/createDiary"]
    ordered = [route for route in preferred if route in routes]
    return ordered[:1]


def _is_same_origin(base_url: str, candidate_url: str) -> bool:
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return (
        candidate.scheme in {"http", "https"}
        and base.scheme == candidate.scheme
        and base.netloc == candidate.netloc
    )


def _dedupe_urls(urls: list[str]) -> list[str]:
    seen = set()
    deduped = []
    for url in urls:
        normalized = url.rstrip("/") or url
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(url)
    return deduped


def _login_config(payload: dict[str, Any]) -> LoginConfig | None:
    login = payload.get("login") or {}
    if not all(login.get(key) for key in ("login_url", "username", "password")):
        return None
    return LoginConfig(
        login_url=login["login_url"],
        username_field=login.get("username_field", "username"),
        password_field=login.get("password_field", "password"),
        username_value=login["username"],
        password_value=login["password"],
        success_marker=login.get("success_marker", ""),
    )


def _stage_from_log(message: str) -> str:
    if "LLM" in message or "[AI" in message:
        return "LLM 리포트 생성 중"
    if "Payload" in message or "SQL" in message or "XSS" in message:
        return "Payload 주입 및 응답 분석 중"
    if "Discovered" in message:
        return "입력 Form 탐색 완료"
    if "crawl" in message.lower() or "크롤링" in message:
        return "하위 링크 크롤링 중"
    return message.replace("[Step 1] ", "").replace("[Step 2] ", "").replace("[Step 3] ", "")


def _progress_from_log(message: str) -> int:
    if "LLM" in message or "[AI" in message:
        return 82
    if "Payload" in message or "SQL" in message or "XSS" in message:
        return 62
    if "Discovered" in message:
        return 46
    if "crawl" in message.lower() or "크롤링" in message:
        return 24
    return 10


def _risk_from_confidence(confidence: Any) -> str:
    return {"high": "High", "medium": "Medium", "low": "Low"}.get(
        str(confidence).lower(), "Medium"
    )


def _overall_risk(vulnerabilities: list[dict[str, Any]]) -> str:
    ranks = {"High": 3, "Medium": 2, "Low": 1}
    if not vulnerabilities:
        return "Low"
    return max(vulnerabilities, key=lambda item: ranks.get(item["risk_level"], 0))[
        "risk_level"
    ]


def _format_duration(seconds: int) -> str:
    minutes, remain = divmod(seconds, 60)
    return f"{minutes}분 {remain}초" if minutes else f"{remain}초"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=True)
