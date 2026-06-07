# Test Suite — Scaield Vulnerability Scanner

End-to-end and unit tests for the scan pipeline, REST API, crawler, AI reporter, and frontend.

---

## Requirements

| Item | Detail |
|---|---|
| Python | 3.12+ (use `.venv`) |
| pytest | 9.0+ |
| Flask, requests, beautifulsoup4, markupsafe | see root `requirements.txt` |
| google-genai | AI reporter tests (mocked — no real API key needed) |
| playwright + chromium | Frontend E2E tests only |

All backend dependencies are already installed in the project `.venv`.  
For frontend tests, install Playwright separately inside `.venv`:

```bash
.venv/bin/pip install playwright
.venv/bin/playwright install chromium
```

---

## Running Tests

All commands must be run from the **project root** (`Scaield/`).

### Run everything (backend tests)

```bash
.venv/bin/python -m pytest tests/ --ignore=tests/frontend -v
```

### Run frontend E2E tests

> Requires the Vite dev server to be running (`npm run dev` inside `frontend/`).

```bash
.venv/bin/python -m pytest tests/frontend/test_dashboard.py -v
```

### Run a specific test file

```bash
# Scan pipeline integration tests
.venv/bin/python -m pytest tests/test_scan_pipeline.py -v

# Detection function unit tests
.venv/bin/python -m pytest tests/test_detection_functions.py -v

# Error handling tests
.venv/bin/python -m pytest tests/test_error_handling.py -v

# Crawler tests
.venv/bin/python -m pytest tests/test_crawler.py -v

# AI reporter tests
.venv/bin/python -m pytest tests/test_ai_reporter.py -v

# Backend REST API tests
.venv/bin/python -m pytest tests/test_backend_api.py -v
```

### Run a specific test class or case

```bash
# Single endpoint detection
.venv/bin/python -m pytest "tests/test_scan_pipeline.py::test_endpoint_detection[GET_/xss-vuln_q]" -v

# All crawler external-link tests
.venv/bin/python -m pytest "tests/test_crawler.py::TestExternalLinkSkipping" -v

# AI reporter fallback tests
.venv/bin/python -m pytest "tests/test_ai_reporter.py::TestAIReporterFallback" -v

# Backend /health endpoint tests
.venv/bin/python -m pytest "tests/test_backend_api.py::TestHealth" -v
```

---

## File Structure

```
tests/
├── conftest.py                  # Session fixture: starts target_server on a random port
├── target_server.py             # Flask server with vulnerable and safe endpoints
├── expected_findings.json       # Ground-truth dataset (10 endpoints)
├── test_scan_pipeline.py        # Detection integration tests + performance metrics
├── test_detection_functions.py  # Detection function unit tests (43 cases)
├── test_error_handling.py       # Error handling tests (11 cases)
├── test_crawler.py              # Crawler behavior tests (13 cases)
├── test_ai_reporter.py          # AI adapter + LLM mock tests (21 cases)
├── test_backend_api.py          # Backend REST API tests (15 cases)
├── frontend/
│   └── test_dashboard.py        # Playwright E2E frontend tests (2 cases)
├── test_report.md               # Latest test results
└── README.md                    # This file
```

---

## How It Works

No external server setup is needed for backend tests. `conftest.py` automatically starts and stops `target_server.py` on a random port for the duration of the test session.

```
pytest
  └─► conftest.py starts target_server.py on a random port
        ├─► test_scan_pipeline.py    → Compares ScannerEngine output against ground-truth
        ├─► test_detection_functions → Unit-tests is_payload_reflected(), find_sql_error(), etc.
        ├─► test_error_handling      → Connection refused / timeout / unauthorized domain
        ├─► test_crawler.py          → IntelligentCrawler BFS, page limit, deduplication
        ├─► test_ai_reporter.py      → Adapter spec + genai.Client mock (no real API call)
        └─► test_backend_api.py      → Flask test client for backend_bridge REST API
```

Frontend tests (`test_dashboard.py`) require the Vite dev server to be running and use Playwright with a mocked backend, so they run independently.

---

## Test File Descriptions

### `test_scan_pipeline.py` — Detection Integration Tests (12 cases)

Validates that `ScannerEngine` correctly detects (or does not detect) vulnerabilities on each endpoint defined in `expected_findings.json`.

| Case type | Expected behavior |
|---|---|
| Vulnerable endpoint | Correct vuln type detected — no false negatives |
| Safe endpoint | No vuln detected — no false positives |

Performance metrics (TP / FP / FN · Precision / Recall / F1) are printed to stdout after the session.

Also includes `TestScannerAppAPI` — two integration tests that POST to `scanner/app.py`'s Flask interface directly via test client.

---

### `test_detection_functions.py` — Detection Function Unit Tests (43 cases)

Tests core scanner functions in isolation.

| Class | Target |
|---|---|
| `TestIsPayloadReflected` | XSS reflection check |
| `TestFindSqlError` | SQL error signature matching |
| `TestDiffResponses` | Response diff computation |
| `TestIsMeaningfulDiff` | Significance threshold judgment |
| `TestRateLimiter` | Consecutive failure threshold and counter reset |
| `TestParseCookiesInput` | Cookie string parsing |
| `TestBuildEffectiveDomains` | Authorized domain list construction |

---

### `test_error_handling.py` — Error Handling Tests (11 cases)

Verifies the scanner handles abnormal conditions gracefully without crashing.

| Scenario | Expected behavior |
|---|---|
| Connection refused | Returns empty findings |
| Timeout | `ScanHttpClient.request()` returns `None` |
| Unauthorized domain | Raises `PermissionError` |
| Rate limiter exceeded | Returns empty results, no exception propagated |
| Invalid URL scheme | `request()` returns `None` |

---

### `test_crawler.py` — Crawler Tests (FR3, 13 cases)

Tests `IntelligentCrawler` from `scanner/scanner_core.py` against the `/crawl-*` pages on `target_server.py`.

| Class | What is tested |
|---|---|
| `TestFormInputCollection` | GET/POST form field collection, `http_method` validation |
| `TestSkipInputTypes` | `hidden` IS collected (injectable); `submit`/`reset`/`image`/`button`/`file` are skipped |
| `TestSubLinkFollowing` | Sub-link traversal, depth-2 page collection |
| `TestExternalLinkSkipping` | Links to external hosts are not followed |
| `TestDepthLimit` | `max_pages=3` stops before depth-2; `max_pages=1` visits seed page only |
| `TestDeduplication` | `(url, http_method, parameter)` combination collected only once |

---

### `test_ai_reporter.py` — AI Reporter Tests (FR5, 21 cases)

**No real Gemini API calls are made.** `genai.Client` is replaced with `unittest.mock.patch`.

| Class | What is tested |
|---|---|
| `TestFindingToAIInput` | `adapter.py` output field spec, VulnType label mapping |
| `TestAIReporterAnalyzeAll` | `ai_analysis` key added, required fields, original fields preserved, log callback |
| `TestAIReporterFallback` | API error fallback, JSON parse failure fallback, missing env var |
| `TestFillMissingFields` | Missing fields auto-filled, existing values not overwritten |

---

### `test_backend_api.py` — Backend REST API Tests (FR1, 15 cases)

Tests `backend_bridge/app.py` endpoints via Flask test client. The actual scan thread (`_run_scan`) is patched out.

| Endpoint | What is tested |
|---|---|
| `GET /health` | 200 response, `status: ok`, `service` field present |
| `POST /scan/start` | `scan_id` returned, `status: running`, extra fields accepted |
| `POST /scan/start` (invalid) | Missing `target_url` → 400; empty string → 400 |
| `GET /scan/<id>/status` | Unknown id → 404; required status fields present |
| `GET /scan/<id>/result` | Incomplete → 409; unknown id → 404; completed → 200 |

---

### `frontend/test_dashboard.py` — E2E Frontend Tests (FR1–FR8, 2 cases)

Uses Playwright (headless Chromium) to test the full frontend flow. Network requests are intercepted and mocked — the real backend does not need to be running.

| Test | FR Coverage | What is tested |
|---|---|---|
| `test_fr1_to_fr8_e2e_flow` | FR1, FR3, FR4, FR5, FR6, FR7, FR8 | URL input → scan start → live progress → dashboard → AI report → PDF print (`window.print`) |
| `test_fr2_unauthorized_url_validation` | FR2 | Unauthorized domain → backend 400 → error message visible |

---

## Test Endpoints

| Endpoint | Method | Parameter | Expected Vuln | Notes |
|---|---|---|---|---|
| `/xss-vuln` | GET | `q` | Reflected XSS | Vulnerable |
| `/xss-safe` | GET | `q` | — | Safe |
| `/sqli-error` | GET | `id` | SQL Injection (Error-based) | Vulnerable |
| `/sqli-boolean` | GET | `id` | SQL Injection (Boolean-based) | Vulnerable |
| `/sqli-safe` | GET | `id` | — | Safe |
| `/safe` | GET | `name` | — | Safe |
| `/login` | POST | `username` | SQL Injection (Error-based) | Vulnerable |
| `/xss-post` | POST | `msg` | Reflected XSS | Vulnerable |
| `/fp-has-script` | GET | `q` | — | Safe (baseline comparison eliminates FP) |
| `/fp-has-sqlite` | GET | `q` | — | Safe (baseline comparison eliminates FP) |

---

## Adding New Test Cases

1. Add a route to `target_server.py`.
2. Add an entry to `expected_findings.json`:

```json
{
  "endpoint_path": "/new-endpoint",
  "method": "GET",
  "parameter": "param",
  "expected_vuln_types": ["Reflected XSS"],
  "description": "Short description of the endpoint"
}
```

- Safe endpoints: set `"expected_vuln_types": []`
- `test_scan_pipeline.py` reads the dataset automatically — no code changes needed.

---

## Performance Metrics

Printed to stdout after the full scan pipeline session:

```
====================================================
  Scan Pipeline Performance Metrics (full session)
====================================================
  TP (True Positive)  :    4  — Vulnerable endpoints correctly detected
  FP (False Positive) :    0  — Safe endpoints incorrectly flagged
  FN (False Negative) :    0  — Vulnerable endpoints missed
====================================================
  Precision   : 1.000  (= TP / (TP+FP))
  Recall      : 1.000  (= TP / (TP+FN))
  F1 Score    : 1.000  (harmonic mean)
====================================================
```

| Metric | Formula | Meaning |
|---|---|---|
| Precision | TP / (TP + FP) | Of all detections, how many are real vulnerabilities |
| Recall | TP / (TP + FN) | Of all real vulnerabilities, how many were detected |
| F1 Score | 2 × P × R / (P + R) | Overall scanner accuracy |
