"""
Scanner AI Shield - HTML Dashboard (Flask)

Run:
    flask --app app run --debug
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from flask import Flask, render_template, request

from scanner_core import VulnerabilityScannerEngine

app = Flask(__name__)
HISTORY_PATH = Path(__file__).with_name("scan_history.json")


def _parse_domain_input(domain_text: str) -> List[str]:
    return [d.strip() for d in domain_text.split(",") if d.strip()]


def _extract_hostname(target_url: str) -> str:
    return (urlparse(target_url).hostname or "").strip().lower()


def _build_effective_domains(target_url: str, approved_domains_text: str) -> List[str]:
    merged: List[str] = []
    for domain in ["localhost", *_parse_domain_input(approved_domains_text), _extract_hostname(target_url)]:
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


@app.route("/", methods=["GET", "POST"])
def index() -> str:
    # FR8: scan logs for dashboard console panel.
    scan_logs: List[str] = []
    results: List[Dict[str, Any]] = []
    error_message = ""
    success_message = ""

    target_url = "http://localhost:8000/search?q=test"
    approved_domains_text = "localhost,example.com"
    timeout = 10
    scan_context: Dict[str, Any] = {"sub_links": [], "input_forms": []}

    if request.method == "POST":
        target_url = request.form.get("target_url", target_url).strip()
        approved_domains_text = request.form.get(
            "approved_domains_text", approved_domains_text
        ).strip()
        timeout = int(request.form.get("timeout", timeout))

        approved_domains = _build_effective_domains(target_url, approved_domains_text)
        approved_domains_text = ",".join(approved_domains)

        def log_callback(message: str) -> None:
            scan_logs.append(message)

        try:
            engine = VulnerabilityScannerEngine(
                pre_approved_domains=approved_domains,
                timeout=timeout,
                log_callback=log_callback,
            )
            results = engine.scan(target_url)
            scan_context = engine.last_scan_context
            success_message = f"스캔 완료: 취약점 {len(results)}건 탐지"

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
            error_message = f"스캔 중 오류가 발생했습니다: {exc}"

    history = _load_history()
    chart_data = _build_chart_data(history)

    return render_template(
        "index.html",
        target_url=target_url,
        approved_domains_text=approved_domains_text,
        timeout=timeout,
        scan_logs=scan_logs,
        results=results,
        results_json=json.dumps(results, ensure_ascii=False, indent=2),
        history=history[::-1],  # latest first
        chart_data=chart_data,
        error_message=error_message,
        success_message=success_message,
        scan_context=scan_context,
    )


if __name__ == "__main__":
    app.run(debug=True)
