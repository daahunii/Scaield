# 🛡️ Scaield LLM 리포트 생성기 모듈
**모듈 경로:** `/LLMmodule`  
**역할:** Scaield DAST 스캐너 분석 데이터 처리 및 AI 기반 구조화 리포트 생성  
**동작 원리:** 로컬 DAST 결과 (`results.json`) ➡️ Gemini LLM 분석 ➡️ 프론트엔드 연동용 JSON (`report.json`)  

안녕하세요! Scaield 프로젝트의 AI 분석 핵심을 담당하는 **LLMmodule** 안내서입니다. 

본 모듈은 DAST 스캐너가 수집한 원시 보안 취약점 증거(Raw Evidence) JSON 데이터를 인공지능(Gemini API)을 활용해 심층 분석하고, 프론트엔드 대시보드와 PDF 다운로드 화면에 완벽하게 대응 가능한 **구조화된 JSON 리포트**를 생성합니다.

---

## 1. 모듈 개요 (Executive Summary)

| 기능 분류 | 주요 기술 스택 | 입력 데이터 | 출력 데이터 | 주요 목적 |
| :--- | :--- | :--- | :--- | :--- |
| 🧠 **AI 분석 엔진** | **google-generativeai** <br> (Gemini 3.5 Flash) | `pipeline/results.json` <br> (로컬 스캔 원시 데이터) | `pipeline/report.json` <br> (스키마 준수 JSON) | 대시보드 렌더링 및 PDF 상세 리포트 정보 구조화 |
| 🛡️ **보안 지침** | **OWASP Secure Coding** | 스캔 증거 페이로드 | 프레임워크 맞춤형 대응 코드 | 실무 개발자가 즉시 패치할 수 있는 시큐어 코딩 가이드 제공 |
| ⚙️ **데이터 정제** | **Python JSON Parser** | LLM API 원시 텍스트 | 정제된 정적 JSON | 마크다운 코드 블록 제거 및 구문 예외 처리 (강건성 확보) |

---

## 2. 세부 동작 원리 및 시큐어 코딩 리포팅 구조

---

### [동작 1] Gemini Prompt 기반 JSON 구조화 

#### 🔍 분석 및 생성 스키마 (JSON Schema)
LLM 엔진은 전달받은 스캔 증거를 분석하여 프론트엔드가 대시보드 렌더링용(`dashboard_view`)과 PDF 파일 생성용(`pdf_report_view`)으로 각각 분리하여 사용할 수 있는 통합 JSON 구조를 생성합니다.

* **Dashboard View (`dashboard_view`):**
  * `vulnerability_title`: 취약점 공식 명칭 (예: `SQL Injection (Error-based)`)
  * `risk_level`: 위험 등급 (`High`, `Medium`, `Low`)
  * `affected_parameter`: 취약한 파라미터명 또는 요청 엔드포인트
  * `brief_summary`: 대시보드 메인 화면에 1~2줄로 축약할 요약 정보
* **PDF Report View (`pdf_report_view`):**
  * `technical_root_cause`: 증거 기반의 근본적인 기술적 원인 설명
  * `business_impact_scenario`: 비즈니스에 미칠 수 있는 영향도 및 공격 시나리오
  * `secure_code_example`: 마크다운 형식의 프레임워크 맞춤형 시큐어 코딩 방어 코드 스니펫
  * `remediation_guidance`: 코드를 패치하기 위한 단계별 조치 가이드
  * `validation_checklist`: 취약점이 성공적으로 고쳐졌는지 확인하기 위한 QA 체크리스트
  * `disclaimer`: 법적 면책 조항 문구

---

### [동작 2] 예외 처리를 통한 견고한 JSON 데이터 확보

#### 💡 발생할 수 있는 오류 상황
LLM API 호출 시 프롬프트에 아무리 마크다운 기호를 생략하라고 명시하더라도, LLM 모델이 자동으로 ```` ```json ````과 같은 백틱 코드 블록 기호나 불필요한 서두/맺음말을 포함하는 현상이 종종 발생합니다. 이 경우 파일에 그대로 텍스트를 저장하면 파싱 에러를 유발하여 시스템이 오작동하게 됩니다.

#### 🛠️ 대응 방법: 정규화 및 파싱 처리 (`clean_and_parse_json`)
`llm.py`는 유효한 JSON을 완벽히 보장하기 위해 출력 정제 헬퍼 함수를 구현하고 있습니다.

##### ❌ 문제 상황 예시 (가공 전 LLM 날것의 응답)
```markdown
```json
{
  "dashboard_view": { ... },
  "pdf_report_view": { ... }
}
```
```

##### 🟢 안전한 정제 처리 및 검증 코드 (`llm.py` 내 적용 로직)
```python
# 1. 마크다운 코드 블록 감싸기 기호(Backticks) 자동 식별 및 제거
def clean_and_parse_json(raw_text: str) -> dict | None:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    
    # 2. JSON 구문 분석(Parse)을 거쳐 완벽한 포맷 검증 수행
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None
```

---

## 3. 설치 및 실행 가이드

### 1단계: API 키 및 환경 변수 설정
프로젝트 루트 디렉토리의 `.env` 파일에 발급받은 Gemini API 키를 저장합니다.
```env
GEMINI_API_KEY=your_actual_gemini_api_key_here
```

### 2단계: 모듈 실행
가상환경이 활성화된 상태에서 아래 명령어로 모듈을 단독 실행하여 동작을 테스트할 수 있습니다.
```bash
python LLMmodule/llm.py
```
* **동작 순서:**
  1. `pipeline/results.json`에 저장된 모의 침투 스캔 데이터를 읽어옵니다.
  2. 설정된 `GEMINI_API_KEY`를 바탕으로 모델을 호출합니다.
  3. LLM 출력을 파싱 및 가공하여 완벽한 규격의 **`pipeline/report.json`** 파일로 최종 저장합니다.

---

> [!IMPORTANT]
> **면책 조항 (Disclaimer)**  
> 본 모듈을 통해 생성된 리포트와 시큐어 코딩 제안은 외부에서 관측된 보안 취약점 증거를 바탕으로 구성된 참고용 가이드라인입니다. 실제 개발 코드나 프로덕션 환경에 반영하기 전에 반드시 유관 보안 팀 및 사내 시니어 개발자의 꼼꼼한 검토를 마친 뒤 적용해 주시기 바랍니다.
