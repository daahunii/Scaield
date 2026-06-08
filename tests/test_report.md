# Scan Pipeline Test Report

**Target:** `pentest/engine.ScannerEngine` + `scanner/app.py` Flask API + `backend_bridge/app.py` REST API  
**Test files:** `test_scan_pipeline.py` · `test_detection_functions.py` · `test_error_handling.py` · `test_crawler.py` · `test_ai_reporter.py` · `test_backend_api.py` · `frontend/test_dashboard.py`

---

## Test Environment

| Item | Detail |
|---|---|
| Test server | `tests/target_server.py` (random port, in-memory SQLite) |
| Ground-truth | `tests/expected_findings.json` (10 endpoints) |
| Run command | `pytest tests/ --ignore=tests/frontend -v` |

---

## Test Cases

### 1. Per-endpoint Detection — `test_scan_pipeline.py` (parametrize)

| # | Method | Endpoint | Parameter | Expected Vuln | Detected | Verdict |
|---|---|---|---|---|---|---|
| 1 | GET | `/xss-vuln` | `q` | Reflected XSS | Reflected XSS | PASS |
| 2 | GET | `/xss-safe` | `q` | — | — | PASS |
| 3 | GET | `/sqli-error` | `id` | SQL Injection (Error-based) | SQL Injection (Error-based) | PASS |
| 4 | GET | `/sqli-boolean` | `id` | SQL Injection (Boolean-based) | SQL Injection (Boolean-based) | PASS |
| 5 | GET | `/sqli-safe` | `id` | — | — | PASS |
| 6 | GET | `/safe` | `name` | — | — | PASS |
| 7 | POST | `/login` | `username` | SQL Injection (Error-based) | SQL Injection (Error-based) | PASS |
| 8 | POST | `/xss-post` | `msg` | Reflected XSS | Reflected XSS | PASS |
| 9 | GET | `/fp-has-script` | `q` | — | — | PASS |
| 10 | GET | `/fp-has-sqlite` | `q` | — | — | PASS |

> Cases 9 and 10 were previously XFAIL (known false-positive limitations). The scanner now eliminates these FPs via baseline response comparison before injection.

### 2. Flask Scanner API Integration Tests — `test_scan_pipeline.py`

| # | Test | Result |
|---|---|---|
| 11 | POST `/` scan request returns HTTP 200 | PASS |
| 12 | Unauthorized domain scan includes error message | PASS |

### 3. Detection Function Unit Tests — `test_detection_functions.py` (43 cases)

| Class | Cases | Description |
|---|---|---|
| `TestIsPayloadReflected` | 8 | Exact match, tag match, HTML escape, known FP case (documented behavior) |
| `TestFindSqlError` | 6 | Signature detection, case-insensitive matching, known FP case (documented behavior) |
| `TestDiffResponses` | 5 | status / body_len / keyword / DOM diff detection |
| `TestIsMeaningfulDiff` | 7 | Boundary value significance judgment |
| `TestRateLimiter` | 3 | Threshold exceeded, counter reset after raise |
| `TestParseCookiesInput` | 8 | Separator types, whitespace stripping, special chars, empty values |
| `TestBuildEffectiveDomains` | 6 | localhost inclusion, host extraction, deduplication |

### 4. Error Handling Tests — `test_error_handling.py` (11 cases)

| Class | Cases | Description |
|---|---|---|
| `TestConnectionRefused` | 2 | Unreachable server → empty results, no crash |
| `TestTimeout` | 2 | Timeout server → None returned, empty results |
| `TestUnauthorizedDomain` | 3 | PermissionError raised, authorized domain passes |
| `TestRateLimiterIntegration` | 1 | Empty results after consecutive failure threshold exceeded |
| `TestScanHttpClient` | 3 | None return guaranteed, invalid scheme, counter reset on success |

### 5. Crawler Tests — `test_crawler.py` (FR3, 13 cases)

| Class | Cases | Description |
|---|---|---|
| `TestFormInputCollection` | 4 | GET/POST form field collection, http_method validation |
| `TestSkipInputTypes` | 2 | hidden IS collected (injectable); submit/reset/image/button/file are skipped |
| `TestSubLinkFollowing` | 2 | Sub-link traversal, depth-2 page collection |
| `TestExternalLinkSkipping` | 1 | External domain links are ignored |
| `TestDepthLimit` | 2 | max_pages=3 stops before depth-2 / max_pages=1 only visits seed page |
| `TestDeduplication` | 2 | (url, http_method, parameter) deduplication, InputPoint type check |

> Migrated from `pentest/Crawler` (deleted) to `scanner/scanner_core.IntelligentCrawler`.  
> Field names updated: `method` → `http_method`, `param_name` → `parameter`.  
> `max_depth` replaced by `max_pages`. `hidden` inputs are now collected as injectable points.

### 6. AI Reporter Tests — `test_ai_reporter.py` (FR5, 21 cases)

| Class | Cases | Description |
|---|---|---|
| `TestFindingToAIInput` | 8 | Required fields present, VulnType label mapping, evidence structure, response truncation |
| `TestAIReporterAnalyzeAll` | 7 | Successful response, ai_analysis key, required fields, original field preservation, callback |
| `TestAIReporterFallback` | 4 | API error fallback, JSON parse failure fallback, missing env var raises EnvironmentError |
| `TestFillMissingFields` | 2 | Empty dict filled with all required fields, existing values preserved |

### 7. Backend API Tests — `test_backend_api.py` (FR1, 15 cases)

| Class | Cases | Description |
|---|---|---|
| `TestHealth` | 3 | GET /health → 200, status: ok, service field present |
| `TestScanStart` | 3 | scan_id returned, running status, scan_type field accepted |
| `TestScanStartValidation` | 3 | Missing target_url → 400, empty string → 400, error field present |
| `TestScanStatus` | 3 | Unknown id → 404, status fields validated, scan_id matches |
| `TestScanResult` | 3 | Incomplete scan → 409, unknown id → 404, completed scan → 200 |

### 8. Frontend E2E Tests — `frontend/test_dashboard.py` (2 cases)

> Run with: `.venv/bin/python -m pytest tests/frontend/test_dashboard.py -v`

| # | Test | FR Coverage | Result | Description |
|---|---|---|---|---|
| 1 | `test_fr1_to_fr8_e2e_flow` | FR1, FR3, FR4, FR5, FR6, FR7, FR8 | PASS | Full E2E flow: URL input → scan start → progress UI → dashboard → AI report → PDF print triggered via `window.print()` |
| 2 | `test_fr2_unauthorized_url_validation` | FR2 | PASS | Unauthorized domain → backend returns 400, error message displayed |

---

## Performance Metrics (test_scan_pipeline.py)

| Metric | Value | Formula |
|---|---|---|
| TP (True Positive) | 4 | Vulnerable endpoint correctly detected |
| FP (False Positive) | 0 | Safe endpoint incorrectly flagged |
| FN (False Negative) | 0 | Vulnerable endpoint missed |
| **Precision** | **1.000** | TP / (TP + FP) |
| **Recall** | **1.000** | TP / (TP + FN) |
| **F1 Score** | **1.000** | 2 × Precision × Recall / (Precision + Recall) |

> `/fp-has-script` and `/fp-has-sqlite` — previously XFAIL known false-positives — now correctly return no findings. FP = 0 across all 10 endpoints.

---

## Result

```
test_scan_pipeline.py       : 12 passed
test_detection_functions.py : 43 passed
test_error_handling.py      : 11 passed
test_crawler.py             : 13 passed
test_ai_reporter.py         : 21 passed
test_backend_api.py         : 15 passed
frontend/test_dashboard.py  :  2 passed             (run via .venv/bin/python)
──────────────────────────────────────────────────
Total                       : 117 passed, 0 failed
```
