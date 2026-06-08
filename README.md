# Scaield

Scaield는 웹 애플리케이션을 크롤링하고 SQL Injection/XSS 취약점을 탐지한 뒤, Gemini 기반 AI 보안 리포트까지 생성하는 DAST 보안 진단 플랫폼입니다.
React 프론트엔드, Flask 백엔드 브릿지, Pentest/Scanner 엔진, LLM 리포트 모듈로 구성되어 있습니다.

---

## 1. 실행 구조

실행 시 보통 터미널을 3개 사용합니다.

| 구분           | 역할                                        | 기본 주소               |
| -------------- | ------------------------------------------- | ----------------------- |
| Test Server    | 스캔 대상 취약 웹 서버                      | `http://127.0.0.1:5000` |
| Backend Bridge | 프론트와 스캐너/AI 모듈을 연결하는 API 서버 | `http://localhost:8000` |
| Frontend       | React + Vite 대시보드                       | `http://localhost:5173` |

프론트엔드에서 입력할 기본 Target URL은 다음과 같습니다.

```text
http://127.0.0.1:5000
```

---

## 2. 대표 폴더 역할

| 폴더              | 역할                                                                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `frontend/`       | React + Vite 기반 웹 대시보드입니다. URL 입력, 스캔 시작, 진행 상태, 결과 대시보드, AI 리포트, PDF 출력 UI를 담당합니다. |
| `backend_bridge/` | Flask API 서버입니다. 프론트 요청을 받아 `scanner`, `pentest`, `LLMmodule`을 순서대로 실행하고 결과를 API로 반환합니다.  |
| `scanner/`        | 대상 웹사이트를 크롤링하고 입력 폼, 링크, 파라미터 등 공격 가능한 진입점을 수집합니다.                                   |
| `pentest/`        | 수집된 입력점에 SQLi/XSS payload를 주입하고 응답을 분석해 취약점 후보를 탐지합니다.                                      |
| `LLMmodule/`      | Gemini API를 호출해 탐지 결과를 개발자용 보안 리포트 형태로 요약합니다.                                                  |
| `testServer/`     | 스캐너 검증용 로컬 취약 Flask 서버입니다. XSS와 SQL Injection 테스트 엔드포인트가 포함되어 있습니다.                     |
| `pipeline/`       | 과거 CLI 기반 실행 파이프라인과 결과 JSON/리포트 산출물이 들어 있습니다.                                                 |
| `common/`         | 공통 리소스 및 보조 파일을 보관하는 폴더입니다.                                                                          |
| `tests/`          | 유닛 테스트와 통합 테스트 코드가 있는 폴더입니다.                                                                        |

---

## 3. 사전 준비

아래 프로그램이 설치되어 있어야 합니다.

- Python 3.10 이상 권장, 현재 프로젝트는 Python 3.12 사용 권장
- Node.js 및 npm
- Chrome 또는 Chromium 계열 브라우저

Python 가상환경은 프로젝트 루트에 `.venv`로 생성합니다.
아래 명령의 `PROJECT_ROOT`에는 사용자가 압축을 풀거나 다운로드한 Scaield 프로젝트 폴더 경로를 넣으면 됩니다.

```bash
export PROJECT_ROOT="/path/to/Scaield"
cd "$PROJECT_ROOT"
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install google-genai
```

---

## 4. Gemini 환경변수 설정

프로젝트 루트에 `.env` 파일을 생성합니다.

```bash
cd "$PROJECT_ROOT"
touch .env
```

`.env` 파일 내용은 아래 형식으로 작성합니다.

```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
PORT=8000
FRONTEND_ORIGIN=http://localhost:5173
```

---

## 5. Test Server 실행

프로젝트의 `testServer/` 폴더는 스캐너 검증용 취약 Flask 서버입니다.
의도적으로 XSS와 SQL Injection 취약점이 포함되어 있으므로 로컬에서만 실행하세요.

폴더 위치:

```text
$PROJECT_ROOT/testServer
```

실행합니다.

```bash
cd "$PROJECT_ROOT/testServer"
python3.12 -m venv .venv
source .venv/bin/activate
pip install flask
python test.py
```

만약 zip 파일에서 다시 압축을 풀어야 하는 경우에는 아래처럼 진행합니다.

```bash
export ZIP_DIR="/path/to/download-folder"
cd "$ZIP_DIR"
unzip testServer.zip
cd testServer
python3.12 -m venv .venv
source .venv/bin/activate
pip install flask
python test.py
```

정상 실행되면 다음 주소에서 테스트 서버가 열립니다.

```text
http://127.0.0.1:5000
```

포함된 취약 테스트 경로:

- `GET /search?q=hello` : Reflected XSS 취약
- `GET /search-safe?q=hello` : XSS 방어 예시
- `GET, POST /login` : Error-based SQL Injection 취약
- `GET /user?id=1` : Boolean-based/Error-based SQL Injection 취약
- `GET /user-safe?id=1` : SQL Injection 방어 예시

---

## 6. Backend Bridge 실행

새 터미널을 열고 Scaield 백엔드 브릿지를 실행합니다.

```bash
cd "$PROJECT_ROOT"
source .venv/bin/activate
python backend_bridge/app.py
```

정상 실행 확인:

```text
http://localhost:8000/health
```

프론트엔드는 이 백엔드에 아래 API를 호출합니다.

- `POST /scan/start`
- `GET /scan/{scan_id}/status`
- `GET /scan/{scan_id}/result`
- `GET /scan/list`

---

## 7. Frontend 실행

새 터미널을 열고 프론트엔드를 실행합니다.

```bash
cd "$PROJECT_ROOT/frontend"
npm install
cp .env.example .env
npm run dev
```

프론트엔드 `.env`는 아래 값을 사용합니다.

```env
VITE_API_BASE_URL=http://localhost:8000
```

브라우저에서 접속합니다.

```text
http://localhost:5173
```

프론트 화면의 Target URL에는 테스트 서버 주소를 입력합니다.

```text
http://127.0.0.1:5000
```

---

## 8. 전체 실행 순서 요약

### 터미널 1: Test Server

```bash
cd "$PROJECT_ROOT/testServer"
source .venv/bin/activate
python test.py
```

### 터미널 2: Backend Bridge

```bash
cd "$PROJECT_ROOT"
source .venv/bin/activate
python backend_bridge/app.py
```

### 터미널 3: Frontend

```bash
cd "$PROJECT_ROOT/frontend"
npm run dev
```

### 브라우저

```text
http://localhost:5173
```

Target URL:

```text
http://127.0.0.1:5000
```

---

## 9. 빌드 명령어

프론트엔드 빌드:

```bash
cd "$PROJECT_ROOT/frontend"
npm run build
```

백엔드 문법 확인:

```bash
cd "$PROJECT_ROOT"
source .venv/bin/activate
python -m py_compile backend_bridge/app.py
```

---
