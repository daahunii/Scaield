"""
target_server.py — 취약점 스캐너 테스트용 Flask 서버

스캐너가 탐지해야 할 취약한 엔드포인트와
탐지하면 안 되는 안전한 엔드포인트를 모두 제공한다.

엔드포인트 목록
---------------
취약한 엔드포인트:
  GET  /xss-vuln?q=        — Reflected XSS (입력값 비이스케이프 출력)
  GET  /sqli-error?id=     — SQLi Error-based (raw string concat + 에러 노출)
  GET  /sqli-boolean?id=   — SQLi Boolean-based (raw numeric concat + 결과 차이)
  POST /login              — SQLi Error-based (POST username 파라미터)

안전한 엔드포인트:
  GET  /xss-safe?q=        — XSS 안전 (HTML 이스케이프 적용)
  GET  /sqli-safe?id=      — SQLi 안전 (파라미터화 쿼리)
  GET  /safe?name=         — 완전 안전 (이스케이프 + 파라미터화)
"""

from __future__ import annotations

import sqlite3
from markupsafe import escape
from flask import Flask, request


def create_app() -> Flask:
    app = Flask(__name__)

    # ── 인메모리 SQLite DB 초기화 ─────────────────────────────────────
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)"
    )
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        [
            (1, "admin", "admin@example.com", "admin"),
            (2, "alice", "alice@example.com", "user"),
            (3, "bob",   "bob@example.com",   "user"),
        ],
    )
    conn.commit()

    # ── 취약한 엔드포인트 ─────────────────────────────────────────────

    @app.route("/xss-vuln")
    def xss_vuln():
        """Reflected XSS: 입력값을 HTML 이스케이프 없이 그대로 출력."""
        q = request.args.get("q", "")
        return (
            f"<html><body>"
            f"<h1>Search Results</h1>"
            f"<p>You searched for: {q}</p>"
            f"</body></html>"
        )

    @app.route("/sqli-error")
    def sqli_error():
        """SQLi Error-based: raw string concat으로 SQLite 에러 메시지 노출."""
        id_ = request.args.get("id", "1")
        try:
            cur = conn.execute(
                f"SELECT name, email, role FROM users WHERE id = '{id_}'"
            )
            rows = cur.fetchall()
            if rows:
                name, email, role = rows[0]
                return (
                    f"<html><body>"
                    f"<p>Name: {escape(name)}</p>"
                    f"<p>Email: {escape(email)}</p>"
                    f"<p>Role: {escape(role)}</p>"
                    f"</body></html>"
                )
            return "<html><body><p>No user found.</p></body></html>"
        except sqlite3.OperationalError as exc:
            # 의도적으로 SQLite 에러 메시지를 응답에 포함 → 스캐너가 탐지해야 함
            return (
                f"<html><body>"
                f"<p>SQLite error: {exc}</p>"
                f"</body></html>"
            ), 500

    @app.route("/sqli-boolean")
    def sqli_boolean():
        """SQLi Boolean-based: 숫자형 파라미터 raw concat → 참/거짓 결과 크기 차이."""
        id_ = request.args.get("id", "1")
        try:
            cur = conn.execute(
                f"SELECT name, email, role FROM users WHERE id = {id_}"
            )
            rows = cur.fetchall()
            if rows:
                name, email, role = rows[0]
                # 참 조건: 내용이 많음 → 거짓 조건 응답보다 본문 길이가 크게 다름
                return (
                    f"<html><body>"
                    f"<p>User Found</p>"
                    f"<p>Name: {escape(name)}, Email: {escape(email)}, Role: {escape(role)}</p>"
                    f"<p>Status: Active</p>"
                    f"</body></html>"
                )
            # 거짓 조건: 내용이 적음
            return "<html><body><p>No user found.</p></body></html>"
        except sqlite3.OperationalError:
            return "<html><body><p>No user found.</p></body></html>"

    @app.route("/login", methods=["POST"])
    def login():
        """SQLi Error-based (POST): username 파라미터 raw string concat."""
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            cur = conn.execute(
                f"SELECT id, name FROM users WHERE name = '{username}'"
            )
            rows = cur.fetchall()
            if rows:
                return "<html><body><p>Login successful.</p></body></html>"
            return "<html><body><p>Login failed: invalid credentials.</p></body></html>"
        except sqlite3.OperationalError as exc:
            return (
                f"<html><body>"
                f"<p>SQLite error: {exc}</p>"
                f"</body></html>"
            ), 500

    @app.route("/xss-post", methods=["POST"])
    def xss_post():
        """XSS 취약 (POST): msg 파라미터를 비이스케이프 출력."""
        msg = request.form.get("msg", "")
        return (
            f"<html><body>"
            f"<p>Message: {msg}</p>"
            f"</body></html>"
        )

    # ── 오탐 위험 엔드포인트 (알려진 스캐너 한계 문서화용) ───────────

    @app.route("/fp-has-script")
    def fp_has_script():
        """
        [FP 위험] XSS 안전(이스케이프 적용)하지만 페이지에 <script> 태그 존재.
        is_payload_reflected()의 토큰 매칭 로직이 오탐할 수 있다.
        """
        q = request.args.get("q", "")
        return (
            "<html>"
            "<head><script>var analytics = 'GA-TRACKING-ID';</script></head>"
            "<body>"
            f"<p>Result: {escape(q)}</p>"
            "<script src='/static/app.js'></script>"
            "</body></html>"
        )

    @app.route("/fp-has-sqlite")
    def fp_has_sqlite():
        """
        [FP 위험] SQLi 안전(파라미터화 쿼리)하지만 페이지에 'SQLite' 문자열 존재.
        find_sql_error()의 시그니처 매칭 로직이 오탐할 수 있다.
        """
        q = request.args.get("q", "")
        cur = conn.execute("SELECT name FROM users WHERE id = ?", (1,))
        row = cur.fetchone()
        return (
            "<html><body>"
            "<p>This application uses SQLite for data storage.</p>"
            f"<p>Result: {escape(q)}</p>"
            f"<p>Admin: {escape(row[0] if row else '')}</p>"
            "</body></html>"
        )

    # ── FR3 크롤러 테스트용 페이지 ──────────────────────────────────

    @app.route("/crawl-root")
    def crawl_root():
        """크롤러 루트: 서브링크 2개 + GET 폼 1개."""
        return (
            "<html><body>"
            "<h1>Crawl Root</h1>"
            "<a href='/crawl-page'>Sub Page</a> "
            "<a href='/crawl-external-link'>External Link Page</a>"
            "<form action='/crawl-root' method='GET'>"
            "  <input name='root_query' type='text'>"
            "  <input type='submit' value='Search'>"
            "</form>"
            "</body></html>"
        )

    @app.route("/crawl-page")
    def crawl_page():
        """크롤러 서브페이지: POST 폼 + hidden/submit 타입 입력."""
        return (
            "<html><body>"
            "<h1>Sub Page</h1>"
            "<a href='/crawl-deep'>Deep Link</a>"
            "<form action='/crawl-page' method='POST'>"
            "  <input name='username' type='text'>"
            "  <input name='password' type='password'>"
            "  <input name='csrf' type='hidden' value='token123'>"
            "  <input type='submit' value='Login'>"
            "</form>"
            "</body></html>"
        )

    @app.route("/crawl-deep")
    def crawl_deep():
        """크롤러 깊이 2 페이지: GET 폼 1개."""
        return (
            "<html><body>"
            "<h1>Deep Page</h1>"
            "<form action='/crawl-deep' method='GET'>"
            "  <input name='deep_param' type='text'>"
            "  <input type='submit' value='Go'>"
            "</form>"
            "</body></html>"
        )

    @app.route("/crawl-external-link")
    def crawl_external_link():
        """크롤러 외부 링크 테스트: 외부 도메인 링크 + 자체 폼."""
        return (
            "<html><body>"
            "<a href='http://external.example.com/page'>External</a>"
            "<form action='/crawl-external-link' method='GET'>"
            "  <input name='q' type='text'>"
            "</form>"
            "</body></html>"
        )

    @app.route("/slow")
    def slow_endpoint():
        """타임아웃 테스트용: delay 파라미터(초)만큼 응답을 지연시킨다."""
        import time
        delay = min(float(request.args.get("delay", "3")), 10.0)
        time.sleep(delay)
        return "<html><body><p>Slow response</p></body></html>"

    # ── 안전한 엔드포인트 ─────────────────────────────────────────────

    @app.route("/xss-safe")
    def xss_safe():
        """XSS 안전: markupsafe.escape()로 HTML 이스케이프."""
        q = request.args.get("q", "")
        return (
            f"<html><body>"
            f"<h1>Search Results</h1>"
            f"<p>You searched for: {escape(q)}</p>"
            f"</body></html>"
        )

    @app.route("/sqli-safe")
    def sqli_safe():
        """SQLi 안전: 파라미터화 쿼리 사용."""
        id_ = request.args.get("id", "1")
        try:
            cur = conn.execute(
                "SELECT name, email, role FROM users WHERE id = ?", (id_,)
            )
            rows = cur.fetchall()
            if rows:
                name, email, role = rows[0]
                return (
                    f"<html><body>"
                    f"<p>Name: {escape(name)}</p>"
                    f"<p>Email: {escape(email)}</p>"
                    f"<p>Role: {escape(role)}</p>"
                    f"</body></html>"
                )
            return "<html><body><p>No user found.</p></body></html>"
        except sqlite3.OperationalError:
            return "<html><body><p>Database error.</p></body></html>", 500

    @app.route("/safe")
    def safe_page():
        """완전히 안전한 페이지: 이스케이프 + 파라미터화."""
        name = request.args.get("name", "")
        return (
            f"<html><body>"
            f"<p>Hello, {escape(name)}!</p>"
            f"</body></html>"
        )

    return app


if __name__ == "__main__":
    create_app().run(port=9999, debug=True)
