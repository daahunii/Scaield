# Scaield Backend Bridge

React 프론트엔드와 기존 Scaield 모듈(`scanner`, `pentest`, `LLMmodule`)을 연결하는 Flask 브릿지 서버입니다.

이 폴더는 Scaield 루트에 새로 추가된 백엔드 브릿지 전용 폴더입니다. 기존 `scanner`, `pentest`, `LLMmodule`, `pipeline`, 루트 README는 수정하지 않고 참조만 합니다.

## 제공 API

- `GET /health`
- `POST /scan/start`
- `GET /scan/{scan_id}/status`
- `GET /scan/{scan_id}/result`

## 설치

Scaield 루트에서 Python 가상환경을 만들고 의존성을 설치합니다. 기존 Scaield 모듈은 `str | None` 타입 문법을 사용하므로 Python 3.10 이상이 필요합니다.

```bash
cd /Users/jonghyun/Desktop/Scaield
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 환경변수

필요하면 `.env.example`을 복사해 로컬 환경 파일을 만듭니다.

```bash
cd /Users/jonghyun/Desktop/Scaield/backend_bridge
cp .env.example .env
```

기본값:

```env
PORT=8000
FRONTEND_ORIGIN=http://localhost:5173
```

AI 리포트까지 생성하려면 `/Users/jonghyun/Desktop/Scaield/.env` 또는 `backend_bridge/.env`에 `GEMINI_API_KEY`를 설정합니다. 실제 API key나 비밀값은 커밋하지 마세요.

AI 리포트를 실제 Gemini API로 생성하려면 추가 패키지도 설치합니다.

```bash
pip install google-genai
```

이 패키지가 없어도 브릿지 서버와 기본 스캔 API는 실행됩니다. 이 경우 AI 리포트는 fallback 안내 문구로 표시됩니다.

## 실행

```bash
cd /Users/jonghyun/Desktop/Scaield
source .venv/bin/activate
python backend_bridge/app.py
```

서버가 켜지면 다음 URL로 상태를 확인할 수 있습니다.

```text
http://localhost:8000/health
```

프론트엔드는 `/Users/jonghyun/Desktop/Scaield/frontend/.env`에서 다음 값을 사용합니다.

```env
VITE_API_BASE_URL=http://localhost:8000
```

## 실행 순서 예시

터미널 1:

```bash
cd /Users/jonghyun/Desktop/Scaield
source .venv/bin/activate
python backend_bridge/app.py
```

터미널 2:

```bash
cd /Users/jonghyun/Desktop/Scaield/frontend
npm run dev
```

터미널 3, 스캔 대상이 필요할 때:

```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```
