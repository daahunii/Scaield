# 🛡️ Scaield 보안 분석 리포트
**수신:** 개발팀  
**발신:** Scaield 수석 웹 애플리케이션 보안 전문가 (Senior AppSec Engineer)  
**분석 대상:** `http://127.0.0.1:5000` (스캔 일시: 2026-05-29T15:37:01)

안녕하세요! 개발자 여러분의 안전한 개발을 돕는 보안 코치 **Scaield**입니다. 

DAST 스캐너가 수집한 원시 데이터를 기반으로, 현재 애플리케이션에서 발견된 보안 취약점을 분석하고 구체적인 조치 방안을 정리했습니다. 제공된 증거 데이터를 바탕으로 **SQL 인젝션(SQL Injection)**과 **반사형 XSS(Reflected Cross-Site Scripting)** 취약점이 식별되었습니다.

개발 단계에서 즉시 적용할 수 있는 안전한 코딩 가이드와 함께 아래의 리포트를 제공해 드립니다.

---

## 1. 종합 요약 (Executive Summary)

| 위험도 | 취약점 유형 | 영향받는 엔드포인트 (파라미터) | 주요 영향 |
| :--- | :--- | :--- | :--- |
| 🔥 **CRITICAL** | **SQL Injection (Error-based)** | `/login` (`username`, `password`) <br> `/user` (`id`) | 데이터베이스 비인가 조회, 인증 우회, 데이터 유출 및 변조 |
| ⚠️ **HIGH** | **Reflected XSS** | `/search` (`q`) | 사용자 세션 탈취, 악성 스크립트 실행, 피싱 공격 |
| ℹ️ **INFO** | **Reflected XSS (정오탐 확인 필요)** | `/search-safe` (`q`), `/user-safe` (`id`) | 브라우저 컨텍스트 내 단순 반사 (안전하게 인코딩됨) |

---

## 2. 상세 분석 및 시큐어 코딩 가이드

---

### [취약점 1] SQL Injection (Error-based) 

#### 🔍 탐지 증거 (Evidence)
*   **대상 엔드포인트:** 
    1. `POST /login` (파라미터: `username`, `password`)
    2. `GET /user` (파라미터: `id`)
*   **출력된 에러 메시지 (SQLite):**
    *   `SQLite error: unrecognized token: "''' AND password = ''"`
    *   `SQLite error: near ":alert(1)": syntax error`
*   **실패한 쿼리 원문:** 
    *   `SELECT id, username, email FROM users WHERE username = ''' AND password = ''`
    *   `SELECT id, username, password, email FROM users WHERE id = javascript:alert(1)`

#### 💡 발생 원인
사용자가 입력한 값(`username`, `password`, `id`)을 검증이나 필터링 없이 SQL 쿼리 문자열에 **직접 결합(String Concatenation)**하여 실행하고 있습니다. 이로 인해 싱글 쿼터(`'`)나 악성 페이로드가 SQL 문법으로 해석되어 데이터베이스 에러가 발생하며, 공격자가 쿼리 구조를 임의로 변경할 수 있는 상태입니다.

#### 🛠️ OWASP 기반 대응 방안: 매개변수화된 쿼리 (Parameterized Query) 사용
SQL 인젝션을 방어하는 가장 확실한 방법은 **SQL 쿼리와 데이터를 완전히 분리**하는 것입니다. DBMS 파서가 사용자 입력을 명령어가 아닌 단순 '데이터'로만 처리하도록 **Prepared Statement(매개변수화된 쿼리)**를 적용해야 합니다.

##### ❌ 취약한 코드 예시 (추정)
```python
# 사용자 입력을 문자열 포맷팅으로 직접 쿼리에 삽입하는 방식 (절대 금지)
query = f"SELECT id, username, email FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

#####  안전한 시큐어 코딩 적용 예시 (Python/SQLite 문맥 기준)
```python
# 1. 매개변수화된 쿼리(Parameterized Query) 적용
query = "SELECT id, username, email FROM users WHERE username = ? AND password = ?"

# 2. 데이터를 튜플 형태로 안전하게 바인딩하여 실행
cursor.execute(query, (username, password))
```
> **Tip:** 정수형인 `id` 값의 경우, 입력 단에서 정수형(Integer) 데이터 타입 검증(`int()` 변환 등)을 수행하는 단계를 추가하면 더욱 안전합니다.

---

### [취약점 2] Reflected XSS (반사형 크로스 사이트 스크립팅)

#### 🔍 탐지 증거 (Evidence)
*   **대상 엔드포인트:** `GET /search` (파라미터: `q`)
*   **입력 페이로드:** `<script>alert('XSS_TEST')</script>`
*   **반환된 Response Body (일부):**
    ```html
    <div>Results for: <script>alert('XSS_TEST')</script></div>
    ```

#### 💡 발생 원인
사용자가 파라미터 `q`에 입력한 악성 스크립트 문자열이 HTML 엔티티 인코딩(Entity Encoding) 처리를 거치지 않고, 브라우저 화면의 HTML 영역(`<div>`)에 그대로 출력되고 있습니다. 이 경우 사용자의 브라우저는 전달받은 페이로드를 실행 가능한 스크립트로 오인하여 즉시 실행하게 됩니다.

> **참고 (`/search-safe`, `/user-safe` 관련):** 
> 해당 엔드포인트는 입력값이 HTML 속성값(`<input value="...">`) 내부에만 머물러 즉각적인 스크립트 실행으로 이어지지 않거나 기본 이스케이핑이 동작하고 있는 것으로 보입니다. 그러나 안전한 브라우징을 위해 일관된 출력 인코딩 처리가 권장됩니다.

#### 🛠️ OWASP 기반 대응 방안: HTML 엔티티 인코딩 (HTML Entity Encoding)
HTML 본문에 동적 콘텐츠를 출력할 때는 예약어(예: `<`, `>`, `&`, `"`, `'`)를 안전한 문자 표현식으로 변환(HTML Encoding)해야 합니다.

##### ❌ 취약한 코드 예시 (추정)
```html
<!-- HTML 템플릿 엔진에서 이스케이핑을 비활성화하거나 수동으로 문자열을 더해 출력하는 경우 -->
<div>Results for: {{ q | safe }}</div>  <!-- (예: Jinja2 등에서 safe 필터 오용) -->
```

#####  안전한 시큐어 코딩 적용 예시
동적으로 사용자 입력을 렌더링할 때는 개발 프레임워크가 제공하는 자동 이스케이핑(Auto-escaping) 기능을 신뢰하고 수동 해제를 지양해야 합니다. 수동으로 안전한 문자열 변환이 필요할 경우 아래와 같이 인코딩 처리를 거쳐야 합니다.

*   **HTML 변경 예시:**
    *   `<` ➡️ `&lt;`
    *   `>` ➡️ `&gt;`
    *   `&` ➡️ `&amp;`
    *   `"` ➡️ `&quot;`
    *   `'` ➡️ `&#x27;`
*   **변환 후 안전하게 출력된 결과:**
    ```html
    <!-- 브라우저가 스크립트로 실행하지 않고 텍스트로만 화면에 렌더링함 -->
    <div>Results for: &lt;script&gt;alert(&#39;XSS_TEST&#39;)&lt;/script&gt;</div>
    ```

---

## 3. 개발자 자가 검증 체크리스트

보안 조치를 완료한 후, 다음 체크리스트를 통해 정상적으로 조치가 되었는지 확인해 보세요.

- [ ] `/login` 및 `/user` 엔드포인트에서 로그인 시 아이디/비밀번호에 싱글 쿼터(`'`)를 입력했을 때 더 이상 500 내부 서버 에러 및 SQLite 에러 메시지가 나타나지 않는가?
- [ ] 데이터베이스 조회 시 모든 SQL 쿼리가 플레이스홀더(`?` 또는 `%s`)를 사용하는 매개변수화된 방식으로 작성되었는가?
- [ ] `/search` 페이지에 `<script>alert(1)</script>`을 입력하고 검색했을 때, 알림창이 뜨지 않고 화면에 문자열 그대로 출력되는가?

---

*본 리포트와 제안된 코드는 스캐너의 외부 관측 증거를 바탕으로 작성된 참고용 예시입니다. 실제 프로덕션 서비스에 적용하기 전 반드시 개발자 및 보안 담당자의 검토가 필요합니다.*