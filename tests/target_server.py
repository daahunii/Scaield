"""
target_server.py — Flask test server for vulnerability scanner tests

Exposes a mix of vulnerable and safe endpoints so the scanner's detection
accuracy can be validated against a known ground-truth.

Endpoints
---------
Vulnerable:
  GET  /xss-vuln?q=        — Reflected XSS (unescaped output)
  GET  /sqli-error?id=     — SQLi error-based (raw string concat + error exposed)
  GET  /sqli-boolean?id=   — SQLi boolean-based (numeric raw concat)
  POST /login              — SQLi error-based on username field

Safe:
  GET  /xss-safe?q=        — XSS safe (HTML-escaped output)
  GET  /sqli-safe?id=      — SQLi safe (parameterized query)
  GET  /safe?name=         — Fully safe (escaped + parameterized)

False-positive canaries:
  GET  /fp-has-script?q=   — Safe but page contains a <script> tag
  GET  /fp-has-sqlite?q=   — Safe but page body mentions "SQLite"

Crawler test pages:
  GET  /crawl-root         — Root page with a GET form and two sub-links
  GET  /crawl-page         — POST form + hidden/submit inputs
  GET  /crawl-deep         — Depth-2 page with a GET form
  GET  /crawl-external-link — Page with an external domain link

Misc:
  GET  /slow?delay=N       — Responds after N seconds (timeout testing)
"""

from __future__ import annotations

import sqlite3
from markupsafe import escape
from flask import Flask, request


def create_app() -> Flask:
    app = Flask(__name__)

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

    # ── Vulnerable endpoints ───────────────────────────────────────────

    @app.route("/xss-vuln")
    def xss_vuln():
        q = request.args.get("q", "")
        return f"<html><body><h1>Search Results</h1><p>You searched for: {q}</p></body></html>"

    @app.route("/sqli-error")
    def sqli_error():
        id_ = request.args.get("id", "1")
        try:
            cur = conn.execute(f"SELECT name, email, role FROM users WHERE id = '{id_}'")
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
            # Intentionally expose the SQLite error message for scanner detection
            return f"<html><body><p>SQLite error: {exc}</p></body></html>", 500

    @app.route("/sqli-boolean")
    def sqli_boolean():
        id_ = request.args.get("id", "1")
        try:
            cur = conn.execute(f"SELECT name, email, role FROM users WHERE id = {id_}")
            rows = cur.fetchall()
            if rows:
                name, email, role = rows[0]
                return (
                    f"<html><body>"
                    f"<p>User Found</p>"
                    f"<p>Name: {escape(name)}, Email: {escape(email)}, Role: {escape(role)}</p>"
                    f"<p>Status: Active</p>"
                    f"</body></html>"
                )
            return "<html><body><p>No user found.</p></body></html>"
        except sqlite3.OperationalError:
            return "<html><body><p>No user found.</p></body></html>"

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username", "")
        try:
            cur = conn.execute(f"SELECT id, name FROM users WHERE name = '{username}'")
            rows = cur.fetchall()
            if rows:
                return "<html><body><p>Login successful.</p></body></html>"
            return "<html><body><p>Login failed: invalid credentials.</p></body></html>"
        except sqlite3.OperationalError as exc:
            return f"<html><body><p>SQLite error: {exc}</p></body></html>", 500

    @app.route("/xss-post", methods=["POST"])
    def xss_post():
        msg = request.form.get("msg", "")
        return f"<html><body><p>Message: {msg}</p></body></html>"

    # ── False-positive canary endpoints ───────────────────────────────

    @app.route("/fp-has-script")
    def fp_has_script():
        """Safe (escaped), but the page contains a <script> tag — baseline comparison must filter this."""
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
        """Safe (parameterized query), but the page mentions 'SQLite' — baseline comparison must filter this."""
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

    # ── Crawler test pages ─────────────────────────────────────────────

    @app.route("/crawl-root")
    def crawl_root():
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
        return (
            "<html><body>"
            "<a href='http://external.example.com/page'>External</a>"
            "<form action='/crawl-external-link' method='GET'>"
            "  <input name='q' type='text'>"
            "</form>"
            "</body></html>"
        )

    # ── Misc ───────────────────────────────────────────────────────────

    @app.route("/slow")
    def slow_endpoint():
        """Delays the response by `delay` seconds — used for timeout testing."""
        import time
        delay = min(float(request.args.get("delay", "3")), 10.0)
        time.sleep(delay)
        return "<html><body><p>Slow response</p></body></html>"

    # ── Safe endpoints ─────────────────────────────────────────────────

    @app.route("/xss-safe")
    def xss_safe():
        q = request.args.get("q", "")
        return f"<html><body><h1>Search Results</h1><p>You searched for: {escape(q)}</p></body></html>"

    @app.route("/sqli-safe")
    def sqli_safe():
        id_ = request.args.get("id", "1")
        try:
            cur = conn.execute("SELECT name, email, role FROM users WHERE id = ?", (id_,))
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
        name = request.args.get("name", "")
        return f"<html><body><p>Hello, {escape(name)}!</p></body></html>"

    return app


if __name__ == "__main__":
    create_app().run(port=9999, debug=True)
