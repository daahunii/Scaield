# Scaield Frontend

Scaield의 React + Vite 기반 프론트엔드 전용 폴더입니다. URL 입력, 스캔 시작, 진행 상태 조회, 결과 대시보드, 취약점 상세, AI 리포트 표시, PDF 다운로드 UI를 제공합니다.

이 폴더는 기존 `/Users/[username]/Desktop/Scaield` 프로젝트의 crawler, pentest, LLMmodule, scanner, prompt, backend 로직과 루트 README를 수정하지 않고 추가된 프론트엔드 전용 작업 공간입니다.

## 설치 방법

```bash
cd /Users/[username]/Desktop/Scaield/frontend
npm install
```

## 환경변수 설정 방법

`.env.example`을 복사해서 `.env`를 만들고 API base URL을 설정합니다.

```bash
cp .env.example .env
```

기본 API 주소는 다음과 같습니다.

```env
VITE_API_BASE_URL=http://localhost:8000
```

프론트엔드는 기본적으로 다음 API 엔드포인트를 호출합니다.

- `POST /scan/start`
- `GET /scan/{scan_id}/status`
- `GET /scan/{scan_id}/result`

실제 API key나 비밀값은 프론트엔드 `.env`에 넣지 말고 백엔드에서 관리하세요.

## 백엔드 실행 전제

프론트엔드를 정상 연동하려면 Scaield 백엔드 또는 브릿지 API가 먼저 실행 중이어야 합니다. 기본 설정에서는 `http://localhost:8000`에서 백엔드가 동작한다고 가정합니다.

## 실행 방법

```bash
cd /Users/[username]/Desktop/Scaield/frontend
npm install
cp .env.example .env
npm run dev
```

브라우저에서 `http://localhost:5173`에 접속합니다.

## 프론트 실행 명령어

```bash
npm run dev
```

## 빌드 명령어

```bash
npm run build
```
