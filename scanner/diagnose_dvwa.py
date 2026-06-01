"""
DVWA 스캔 진단 스크립트 — 단계별로 어디서 실패하는지 찾아냄
"""
import sys
import json
sys.path.insert(0, "/Users/hong/Desktop/scaield/scanner")

import requests
from bs4 import BeautifulSoup

DVWA_BASE = "http://localhost:55000"
LOGIN_URL  = f"{DVWA_BASE}/login.php"
XSS_URL    = f"{DVWA_BASE}/vulnerabilities/xss_d/?default=English"
USERNAME   = "admin"
PASSWORD   = "password"

session = requests.Session()

print("=" * 60)
print("STEP 1: DVWA 서버 접근 확인")
try:
    r = session.get(DVWA_BASE, timeout=5)
    print(f"  ✅ 응답: {r.status_code}  최종 URL: {r.url}")
except Exception as e:
    print(f"  ❌ 연결 실패: {e}")
    sys.exit(1)

print()
print("STEP 2: 로그인 페이지 파싱 (모든 폼 필드 추출)")
try:
    r = session.get(LOGIN_URL, timeout=5)
    soup = BeautifulSoup(r.text, "html.parser")
    # Find the form containing the password field
    login_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"name": "password"}):
            login_form = form
            break
    if login_form is None:
        login_form = soup.find("form")

    post_data = {}
    if login_form:
        for inp in login_form.find_all("input"):
            n = inp.get("name")
            t = (inp.get("type") or "text").lower()
            v = inp.get("value", "")
            if n and t not in ("checkbox", "radio"):
                post_data[n] = v
    print(f"  ✅ 폼 필드: {post_data}")
except Exception as e:
    print(f"  ❌ 실패: {e}")
    sys.exit(1)

print()
print("STEP 3: 로그인 POST 시도 (submit 버튼 값 포함)")
post_data["username"] = USERNAME
post_data["password"] = PASSWORD
try:
    r = session.post(LOGIN_URL, data=post_data, timeout=5, allow_redirects=True)
    print(f"  응답코드: {r.status_code}  최종 URL: {r.url}")
    if "login" in r.url.lower():
        print("  ❌ 여전히 로그인 페이지에 있음 → 자격증명 오류")
        soup = BeautifulSoup(r.text, "html.parser")
        err = soup.find("div", {"id": "login_messages"})
        if err:
            print(f"     DVWA 오류: {err.text.strip()}")
    else:
        print("  ✅ 로그인 성공")
    print(f"  쿠키: { {c.name: c.value for c in session.cookies} }")
except Exception as e:
    print(f"  ❌ 실패: {e}")
    sys.exit(1)

print()
print("STEP 4: security=low 쿠키 강제 주입")
session.cookies.set("security", "low", domain="localhost")
print(f"  쿠키 (강제 후): { {c.name: c.value for c in session.cookies} }")

print()
print("STEP 5: XSS 페이지 접근 확인")
try:
    r = session.get(XSS_URL, timeout=5)
    print(f"  응답코드: {r.status_code}  최종 URL: {r.url}")
    if "login" in r.url.lower():
        print("  ❌ XSS 페이지 → 로그인으로 리다이렉트됨 (인증 실패)")
    else:
        print("  ✅ XSS 페이지 정상 접근")
        # Check if there's a form or select box
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        print(f"  폼 개수: {len(forms)}")
        for frm in forms:
            print(f"    action={frm.get('action')} method={frm.get('method')}")
            for inp in frm.find_all(["input","select","textarea"]):
                print(f"      name={inp.get('name')} type={inp.get('type')}")
except Exception as e:
    print(f"  ❌ 실패: {e}")
    sys.exit(1)

print()
print("STEP 6: 페이로드 반영(Reflection) 테스트")
MARKER = "XSS_TEST"
payload = f"<script>alert('{MARKER}')</script>"
test_url = f"{DVWA_BASE}/vulnerabilities/xss_d/?default={requests.utils.quote(payload)}"
try:
    r = session.get(test_url, timeout=5)
    if MARKER in r.text:
        print(f"  ✅ 서버 응답에 마커 '{MARKER}' 반영됨 → Reflection XSS 탐지 가능")
    else:
        print(f"  ⚠️  서버 응답에 마커 없음 → DOM XSS (JavaScript 처리 방식)")
        # Show snippet of page
        idx = r.text.find("default")
        if idx >= 0:
            print(f"     HTML 스니펫: ...{r.text[max(0,idx-50):idx+100]}...")
except Exception as e:
    print(f"  ❌ 실패: {e}")

print()
print("STEP 7: SVG 페이로드 반영 테스트 (DOM XSS 대안)")
svg_payload = "<svg onload=alert(1)>"
test_url2 = f"{DVWA_BASE}/vulnerabilities/xss_d/?default={requests.utils.quote(svg_payload)}"
try:
    r = session.get(test_url2, timeout=5)
    # DOM XSS: server won't reflect, check source
    print(f"  응답 길이: {len(r.text)}")
    if "login" in r.url.lower():
        print("  ❌ 여전히 로그인 리다이렉트 — security 쿠키 적용 실패")
    else:
        print("  ✅ XSS 페이지 응답 수신 — Selenium 검증 필요")
except Exception as e:
    print(f"  ❌ 실패: {e}")

print()
print("진단 완료.")
