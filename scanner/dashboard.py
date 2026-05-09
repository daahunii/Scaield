"""
Scanner AI Shield Dashboard

Run:
    streamlit run dashboard.py
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

import streamlit as st

from scanner_core import VulnerabilityScannerEngine


def _parse_domain_input(domain_text: str) -> List[str]:
    domains = []
    for item in domain_text.split(","):
        cleaned = item.strip()
        if cleaned:
            domains.append(cleaned)
    return domains


def _flatten_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in results:
        evidence = item.get("evidence", {})
        rows.append(
            {
                "vulnerability_type": item.get("vulnerability_type"),
                "target_url": item.get("target_url"),
                "parameter": item.get("parameter"),
                "payload": item.get("payload"),
                "http_method": item.get("http_method"),
                "status_code": item.get("status_code"),
                "detection_method": evidence.get("detection_method"),
            }
        )
    return rows


st.set_page_config(page_title="Scanner AI Shield", layout="wide")
st.title("Scanner AI Shield Dashboard")
st.caption("FR8 진행 로그 + FR5 표준 JSON 결과 확인용 대시보드")

with st.sidebar:
    st.header("스캔 설정")
    target_url = st.text_input("Target URL", value="http://localhost:8000/search?q=test")
    approved_domains_text = st.text_input(
        "Pre-approved Domains (comma-separated)",
        value="localhost,example.com",
    )
    timeout = st.number_input("HTTP Timeout (sec)", min_value=3, max_value=60, value=10)
    run_scan = st.button("스캔 시작", type="primary")

log_placeholder = st.empty()
log_box = st.empty()
result_container = st.container()

if "scan_logs" not in st.session_state:
    st.session_state.scan_logs = []

if run_scan:
    st.session_state.scan_logs = []
    approved_domains = _parse_domain_input(approved_domains_text)

    def log_callback(message: str) -> None:
        st.session_state.scan_logs.append(message)
        log_placeholder.info(
            f"실시간 스캔 로그 ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})"
        )
        log_box.code("\n".join(st.session_state.scan_logs[-200:]), language="text")

    try:
        engine = VulnerabilityScannerEngine(
            pre_approved_domains=approved_domains,
            timeout=int(timeout),
            log_callback=log_callback,
        )
        with st.spinner("스캔 실행 중..."):
            results = engine.scan(target_url)
    except Exception as exc:
        st.error(f"스캔 중 오류가 발생했습니다: {exc}")
        st.stop()

    with result_container:
        st.success(f"스캔 완료: 취약점 {len(results)}건 탐지")
        st.subheader("요약 테이블")
        st.dataframe(_flatten_results(results), use_container_width=True)

        st.subheader("표준 JSON 결과 (FR5 / NFR5)")
        st.code(json.dumps(results, ensure_ascii=False, indent=2), language="json")
else:
    log_placeholder.info("좌측 설정 후 '스캔 시작'을 눌러주세요.")
    if st.session_state.scan_logs:
        log_box.code("\n".join(st.session_state.scan_logs[-200:]), language="text")
