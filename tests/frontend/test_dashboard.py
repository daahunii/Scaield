from playwright.sync_api import Page, expect

# Default Vite dev server port
FRONTEND_URL = "http://localhost:5173"

def test_fr1_to_fr8_e2e_flow(page: Page):
    """
    Comprehensive E2E test scenario verifying all Functional Requirements (FR).
    Validates the entire flow from initiating a scan to checking the AI report and downloading the PDF.
    """
    # ─────────────────────────────────────────────────────────────
    # Network API Mocking (for backend-independent and deterministic E2E testing)
    # ─────────────────────────────────────────────────────────────
    def handle_scan_start(route):
        route.fulfill(json={"scan_id": "test-1234", "status": "running"})

    status_state = {"count": 0}
    def handle_scan_status(route):
        status_state["count"] += 1
        # Return 'running' state for the first 2 requests to keep the scanning UI (Radar UI) visible for a short time
        if status_state["count"] <= 2:
            route.fulfill(json={
                "scan_id": "test-1234",
                "status": "running",
                "progress": 45,
                "current_step": "Testing payload injection..."
            })
        else:
            route.fulfill(json={
                "scan_id": "test-1234",
                "status": "completed",
                "progress": 100,
                "current_step": "Scan completed"
            })

    def handle_scan_result(route):
        route.fulfill(json={
            "scan_id": "test-1234",
            "target_url": "http://localhost:8080/dvwa",
            "scan_time": "1 min 10 sec",
            "total_pages": 5,
            "tested_inputs": 10,
            "risk_level": "High",
            "report_status": "AI report generation completed",
            "vulnerabilities": [{
                "id": "vuln-1",
                "type": "SQL Injection",
                "risk_level": "High",
                "endpoint": "/login",
                "parameter": "id",
                "payload": "' OR 1=1--",
                "status_code": 200,
                "evidence": "Response difference detected",
                "detection_method": "boolean",
                "ai_report": {
                    "vulnerability_summary": "SQLi vulnerability detected",
                    "root_cause": "Lack of input validation",
                    "attack_scenario": "Database leak",
                    "secure_coding_guidance": "Use parameter binding",
                    "fixed_code_example": "SELECT * FROM users WHERE id = ?",
                    "validation_steps": "Re-verify",
                    "disclaimer": "Disclaimer"
                }
            }]
        })

    page.route("**/scan/start", handle_scan_start)
    page.route("**/scan/*/status", handle_scan_status)
    page.route("**/scan/*/result", handle_scan_result)

    page.goto(FRONTEND_URL)

    # ─────────────────────────────────────────────────────────────
    # FR1: The system shall allow users to input a target URL, select a scan type (SQLi, XSS, or All), and initiate the scan.
    # ─────────────────────────────────────────────────────────────
    # 1. Input Target URL
    url_input = page.locator("input#target-url-input")
    expect(url_input).to_be_visible()
    url_input.fill("http://localhost:8080/dvwa")

    # 2. Select Scan Type (All)
    scan_type_select = page.locator("select#scan-type-select")
    scan_type_select.select_option("all")

    # 3. Click Scan Start button
    # Note: Button name matches the actual Korean text rendered in the frontend.
    start_button = page.get_by_role("button", name="모의 진단 및 취약점 스캔 시작")
    start_button.click()

    # ─────────────────────────────────────────────────────────────
    # FR8: The frontend shall display the real-time scanning progress and completion percentage.
    # FR3, FR4: Crawling and Injecting (indirectly verified via displayed progress text)
    # ─────────────────────────────────────────────────────────────
    # Verify percentage text (.tnum) and current step text (.scanning-active-ticker) are visible
    progress_text = page.locator(".scanning-radar .tnum")
    expect(progress_text).to_be_visible()
    
    ticker_text = page.locator(".scanning-active-ticker span")
    expect(ticker_text).to_be_visible()

    # ─────────────────────────────────────────────────────────────
    # FR6: The system shall render an overall vulnerability summary dashboard...
    # ─────────────────────────────────────────────────────────────
    # Wait until the scan finishes and transitions to the Dashboard screen
    metric_card = page.locator(".dashboard-metric-card").first
    expect(metric_card).to_be_visible(timeout=10000)

    # Verify rendering of the vulnerability list header in the dashboard
    vuln_list_header = page.locator(".vuln-list-header")
    expect(vuln_list_header).to_be_visible()

    # ─────────────────────────────────────────────────────────────
    # FR5: ...receive a security report containing the root cause and an OWASP-aligned reference remediation...
    # FR6: ...and detailed LLM analysis reports for each vulnerability after the scan is complete.
    # ─────────────────────────────────────────────────────────────
    # Wait for AI Report generation and click the button
    ai_report_btn = page.get_by_role("button", name="AI Report 보러가기")
    expect(ai_report_btn).to_be_enabled(timeout=10000)
    ai_report_btn.click()

    # Verify entry into the report screen
    report_title = page.locator("h1", has_text="AI Deep Security Report")
    expect(report_title).to_be_visible()

    # Verify presence of Root cause and Remediation guidance sections
    # Note: has_text matches the actual Korean text rendered in the frontend.
    root_cause_section = page.locator(".report-section-title", has_text="발생 원인")
    expect(root_cause_section).to_be_visible()
    
    remediation_section = page.locator(".report-section-title", has_text="안전한 코딩 수칙")
    expect(remediation_section).to_be_visible()

    # ─────────────────────────────────────────────────────────────
    # FR7: The system shall allow users to download the final LLM-generated security report as a PDF file.
    # ─────────────────────────────────────────────────────────────
    # ─────────────────────────────────────────────────────────────
    # FR7: Verify PDF download is triggered when clicking the button
    # ─────────────────────────────────────────────────────────────
    pdf_btn = page.get_by_role("button", name="PDF 리포트 다운로드")
    expect(pdf_btn).to_be_visible()

    # Intercept the download event and verify a file download is initiated
    with page.expect_download() as download_info:
        pdf_btn.click()
    download = download_info.value
    # Verify that a download was started (filename should end in .pdf or be non-empty)
    assert download.suggested_filename, "PDF 다운로드 파일명이 비어있음"


def test_fr2_unauthorized_url_validation(page: Page):
    """
    FR2: The backend shall validate whether the entered URL is an authorized test environment.
    Verifies that entering an unauthorized external domain triggers backend validation and displays an error.
    """
    def handle_unauthorized(route):
        route.fulfill(status=400, json={"error": "Unauthorized test environment."})
    
    page.route("**/scan/start", handle_unauthorized)

    page.goto(FRONTEND_URL)
    url_input = page.locator("input#target-url-input")
    
    # Input an unauthorized malicious/external domain
    url_input.fill("http://evil.example.com")
    
    start_button = page.get_by_role("button", name="모의 진단 및 취약점 스캔 시작")
    start_button.click()

    # Verify rendering of the error message (backend should return an authorization failure error)
    error_msg = page.locator(".form-error")
    expect(error_msg).to_be_visible(timeout=5000)
