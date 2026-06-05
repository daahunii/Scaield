# 스캔 파이프라인 테스트

취약점 스캐너 파이프라인 통합 테스트.  
스캐너가 취약/안전 엔드포인트를 올바르게 탐지하는지 검증한다.

---

## 사전 요구사항

| 항목 | 버전 |
|---|---|
| Python | 3.12+ |
| pytest | 9.0+ |
| Flask, requests, beautifulsoup4, markupsafe | (루트 `requirements.txt` 참고) |
| google-genai | AI 리포터 테스트 (mock 사용, 실제 API 키 불필요) |

모든 의존성은 프로젝트 `.venv`에 설치되어 있다.  
pytest가 없는 경우 아래 명령으로 설치:

```bash
.venv/bin/pip install pytest
```

---

## 파일 구조

```
tests/
├── conftest.py                  # 세션 fixture: 랜덤 포트로 target_server 자동 기동
├── target_server.py             # 취약/안전 엔드포인트를 가진 Flask 테스트 서버
├── expected_findings.json       # Ground-truth 데이터셋 (엔드포인트 11개)
├── test_scan_pipeline.py        # 탐지 통합 테스트 + 성능 메트릭 출력
├── test_detection_functions.py  # 탐지 함수 단위 테스트 (43 케이스)
├── test_error_handling.py       # 에러 핸들링 테스트 (11 케이스)
├── test_crawler.py              # 크롤러 동작 테스트 (13 케이스)
├── test_ai_reporter.py          # AI 어댑터 + LLM mock 테스트 (19 케이스)
├── test_backend_api.py          # backend_bridge REST API 테스트 (13 케이스)
├── frontend/
│   └── test_dashboard.py        # Playwright E2E 프론트엔드 테스트
├── test_report.md               # 최신 테스트 결과
└── README.md                    # 이 파일
```

---

## 동작 방식

```
pytest 실행
  └─► conftest.py가 target_server.py를 랜덤 포트로 기동
        ├─► test_scan_pipeline.py    → ScannerEngine 탐지 결과를 ground-truth와 비교
        ├─► test_detection_functions → 탐지 함수(is_payload_reflected 등) 단위 검증
        ├─► test_error_handling      → 연결 실패 / 타임아웃 / 비인가 도메인 시나리오
        ├─► test_crawler.py          → Crawler BFS 탐색 · 깊이 제한 · 중복 제거
        ├─► test_ai_reporter.py      → adapter 스펙 + genai.Client mock으로 LLM 검증
        └─► test_backend_api.py      → Flask REST API 상태 코드 및 필드 검증
```

**별도 서버 실행 불필요.** 테스트 서버는 자동으로 시작/종료된다.

---

## 테스트 실행 방법

**프로젝트 루트(`Scaield/`)에서 실행.**

### 전체 실행
```bash
.venv/bin/python -m pytest tests/ -v
```

### 파일별 실행

```bash
# 탐지 통합 테스트
.venv/bin/python -m pytest tests/test_scan_pipeline.py -v

# 탐지 함수 단위 테스트
.venv/bin/python -m pytest tests/test_detection_functions.py -v

# 에러 핸들링 테스트
.venv/bin/python -m pytest tests/test_error_handling.py -v

# 크롤러 테스트
.venv/bin/python -m pytest tests/test_crawler.py -v

# AI 어댑터 + LLM 테스트
.venv/bin/python -m pytest tests/test_ai_reporter.py -v

# Backend API 테스트
.venv/bin/python -m pytest tests/test_backend_api.py -v
```

### 특정 케이스만 실행

```bash
# XSS 취약 엔드포인트
.venv/bin/python -m pytest "tests/test_scan_pipeline.py::test_endpoint_detection[GET_/xss-vuln_q]" -v

# 크롤러 외부 링크 무시 테스트
.venv/bin/python -m pytest "tests/test_crawler.py::TestExternalLinkSkipping" -v

# AI 리포터 fallback 테스트
.venv/bin/python -m pytest "tests/test_ai_reporter.py::TestAIReporterFallback" -v

# Backend API /health 테스트
.venv/bin/python -m pytest "tests/test_backend_api.py::TestHealth" -v
```

---

## 테스트 파일 설명

### `test_scan_pipeline.py` — 탐지 통합 테스트

`expected_findings.json` ground-truth 데이터셋을 기준으로 `ScannerEngine`이 올바른 취약점을 탐지하는지 검증한다.

| 케이스 유형 | 설명 |
|---|---|
| 취약 엔드포인트 | XSS/SQLi가 탐지돼야 함 (FN 없음) |
| 안전 엔드포인트 | 아무 취약점도 탐지되지 않아야 함 (FP 없음) |
| XFAIL 엔드포인트 | 알려진 스캐너 한계로 오탐 발생 — 문서화 목적으로 허용 |

테스트 완료 후 TP / FP / FN · Precision / Recall / F1이 stdout에 출력된다.

---

### `test_detection_functions.py` — 탐지 함수 단위 테스트

스캐너 내부 함수를 독립적으로 검증한다.

| 클래스 | 대상 |
|---|---|
| `TestIsPayloadReflected` | XSS 반사 판정 함수 |
| `TestFindSqlError` | SQL 에러 시그니처 탐지 함수 |
| `TestDiffResponses` | 두 응답 차이 계산 함수 |
| `TestIsMeaningfulDiff` | 유의미한 차이 판단 함수 |
| `TestRateLimiter` | 연속 실패 임계치 · 카운터 리셋 |
| `TestParseCookiesInput` | 쿠키 문자열 파싱 |
| `TestBuildEffectiveDomains` | 인가 도메인 목록 생성 |

---

### `test_error_handling.py` — 에러 핸들링 테스트

스캐너가 비정상 환경에서 크래시 없이 동작하는지 검증한다.

| 시나리오 | 기대 동작 |
|---|---|
| 연결 불가 서버 | 빈 findings 반환 |
| 타임아웃 서버 | `ScanHttpClient.request()` → `None` 반환 |
| 비인가 도메인 | `PermissionError` 발생 |
| Rate Limiter 초과 | 빈 결과 반환, 크래시 없음 |
| 잘못된 URL 스킴 | `request()` → `None` 반환 |

---

### `test_crawler.py` — 크롤러 테스트 (FR3)

`pentest/crawler.py`의 `Crawler` 클래스를 `target_server.py`의 `/crawl-*` 페이지를 대상으로 검증한다.

| 클래스 | 검증 항목 |
|---|---|
| `TestFormInputCollection` | GET/POST 폼 필드 수집, `param_type` 검증 |
| `TestSkipInputTypes` | `hidden` · `submit` 타입 미수집 |
| `TestSubLinkFollowing` | 서브링크 탐색, depth-2 페이지 수집 |
| `TestExternalLinkSkipping` | 외부 도메인 링크 무시 |
| `TestDepthLimit` | `max_depth=1/0` 깊이 제한 |
| `TestDeduplication` | `(url, method, param_name)` 중복 제거 |

---

### `test_ai_reporter.py` — AI 어댑터 + LLM 테스트 (FR5)

**실제 Gemini API를 호출하지 않는다.** `unittest.mock.patch`로 `genai.Client`를 교체해 API 키 없이 실행 가능하다.

| 클래스 | 검증 항목 |
|---|---|
| `TestFindingToAIInput` | `adapter.py` 출력 필드 스펙, VulnType 레이블 매핑 3종 |
| `TestAIReporterAnalyzeAll` | `ai_analysis` 키 추가, 필수 필드, 원본 필드 보존, 콜백 |
| `TestAIReporterFallback` | API 오류 · JSON 파싱 실패 시 fallback 반환 |
| `TestFillMissingFields` | 누락 필드 자동 채움, 기존 값 유지 |

---

### `test_backend_api.py` — Backend API 테스트 (FR1)

`backend_bridge/app.py`의 REST 엔드포인트를 Flask 테스트 클라이언트로 검증한다. 실제 스캔 스레드는 `unittest.mock.patch`로 차단한다.

| 엔드포인트 | 검증 항목 |
|---|---|
| `GET /health` | 200, `status: ok`, `service` 필드 존재 |
| `POST /scan/start` | `scan_id` 반환, `status: running`, `scan_type` 필드 허용 |
| `POST /scan/start` (오류) | `target_url` 없음 → 400, 빈 문자열 → 400 |
| `GET /scan/<id>/status` | 없는 id → 404, 상태 필드 검증 |
| `GET /scan/<id>/result` | 미완료 → 409, 없는 id → 404, 완료 → 200 |

---

### `frontend/test_dashboard.py` — E2E 프론트엔드 테스트

Playwright를 사용해 프론트엔드 전체 흐름을 검증한다. 네트워크 요청을 mock으로 대체해 백엔드 없이 실행 가능하다.

> **별도 설치 필요:** `pip install playwright && playwright install chromium`

| 테스트 | 검증 항목 |
|---|---|
| `test_fr1_to_fr8_e2e_flow` | URL 입력 → 스캔 시작 → 진행률 표시 → 대시보드 → AI 리포트 → PDF 다운로드 |
| `test_fr2_unauthorized_url_validation` | 비인가 도메인 입력 시 에러 메시지 표시 |

```bash
# 프론트엔드 테스트 실행 (Vite dev 서버 실행 중이어야 함)
.venv/bin/python -m pytest tests/frontend/ -v
```

---

## 테스트 엔드포인트 목록

| 엔드포인트 | 메서드 | 파라미터 | 기대 취약점 | 비고 |
|---|---|---|---|---|
| `/xss-vuln` | GET | `q` | Reflected XSS | 취약 |
| `/xss-safe` | GET | `q` | — | 안전 |
| `/sqli-error` | GET | `id` | SQL Injection (Error-based) | 취약 |
| `/sqli-boolean` | GET | `id` | SQL Injection (Boolean-based) | 취약 |
| `/sqli-safe` | GET | `id` | — | 안전 |
| `/safe` | GET | `name` | — | 안전 |
| `/login` | POST | `username` | SQL Injection (Error-based) | 취약 |
| `/xss-post` | POST | `msg` | Reflected XSS | 취약 |
| `/fp-has-script` | GET | `q` | — | XFAIL (알려진 오탐) |
| `/fp-has-sqlite` | GET | `q` | — | XFAIL (알려진 오탐) |
| `/crawl-root` | GET | — | — | 크롤러 테스트용 |

---

## 테스트 케이스 추가 방법

1. `target_server.py`에 라우트 추가.
2. `expected_findings.json`에 항목 추가:

```json
{
  "endpoint_path": "/추가할-엔드포인트",
  "method": "GET",
  "parameter": "파라미터명",
  "expected_vuln_types": ["Reflected XSS"],
  "description": "엔드포인트 설명"
}
```

안전한 엔드포인트는 `"expected_vuln_types": []`로 설정.  
알려진 스캐너 한계는 `"known_scanner_limitation": true` 추가.  
`test_scan_pipeline.py`는 수정 불필요 — 데이터셋을 자동으로 읽는다.

---

## 성능 메트릭

전체 테스트 완료 후 stdout에 아래 메트릭이 출력된다:

```
====================================================
  스캔 파이프라인 성능 메트릭 (전체 세션)
====================================================
  TP (정탐)   :    4  — 취약 엔드포인트 정확히 탐지
  FP (오탐)   :    0  — 안전 엔드포인트를 취약으로 잘못 탐지
  FN (미탐)   :    0  — 취약 엔드포인트 탐지 실패
====================================================
  Precision   : 1.000  (= TP / (TP+FP))
  Recall      : 1.000  (= TP / (TP+FN))
  F1 Score    : 1.000  (조화평균)
====================================================
```

| 지표 | 산식 | 의미 |
|---|---|---|
| Precision | TP / (TP + FP) | 탐지 결과 중 실제 취약점 비율 |
| Recall | TP / (TP + FN) | 실제 취약점 중 탐지된 비율 |
| F1 Score | 2 × P × R / (P + R) | 스캐너 전체 정확도 |
