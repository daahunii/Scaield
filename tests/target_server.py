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
        """Reflected XSS: user input rendered without HTML escaping."""
        q = request.args.get("q", "")
        return (
            f"<html><body>"
            f"<h1>Search Results</h1>"
            f"<p>You searched for: {q}</p>"
            f"</body></html>"
        )

    @app.route("/sqli-error")
    def sqli_error():
        """SQLi error-based: raw string concatenation exposes SQLite error messages."""
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
            # Intentionally expose the SQLite error message so the scanner can detect it
            return (
                f"<html><body>"
                f"<p>SQLite error: {exc}</p>"
                f"</body></html>"
            ), 500

    @app.route("/sqli-boolean")
    def sqli_boolean():
        """SQLi boolean-based: numeric raw concatenation causes response size difference between true/false conditions."""
        id_ = request.args.get("id", "1")
        try:
            cur = conn.execute(
                f"SELECT name, email, role FROM users WHERE id = {id_}"
            )
            rows = cur.fetchall()
            if rows:
                name, email, role = rows[0]
                # True condition: larger response body than the false condition
                return (
                    f"<html><body>"
                    f"<p>User Found</p>"
                    f"<p>Name: {escape(name)}, Email: {escape(email)}, Role: {escape(role)}</p>"
                    f"<p>Status: Active</p>"
                    f"</body></html>"
                )
            # False condition: minimal response body
            return "<html><body><p>No user found.</p></body></html>"
        except sqlite3.OperationalError:
            return "<html><body><p>No user found.</p></body></html>"

    @app.route("/login", methods=["POST"])
    def login():
        """SQLi error-based (POST): raw string concatenation on the username parameter."""
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
        """XSS vulnerable (POST): msg parameter rendered without escaping."""
        msg = request.form.get("msg", "")
        return (
            f"<html><body>"
            f"<p>Message: {msg}</p>"
            f"</body></html>"
        )

    # ── False-positive canary endpoints (documents known scanner limitations) ──

    @app.route("/fp-has-script")
    def fp_has_script():
        """
        [FP risk] XSS-safe (escaped), but the page contains a <script> tag.
        The token-matching logic in is_payload_reflected() may produce a false positive.
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
        [FP risk] SQLi-safe (parameterized query), but the page body contains the word 'SQLite'.
        The signature-matching logic in find_sql_error() may produce a false positive.
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

    # ── Crawler test pages ─────────────────────────────────────────────

    @app.route("/crawl-root")
    def crawl_root():
        """Crawler root: two sub-links + one GET form."""
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
        """Crawler sub-page: POST form with hidden and submit inputs."""
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
        """Crawler depth-2 page: one GET form."""
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
        """Crawler external-link test: external domain link + own GET form."""
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
        """XSS-safe: output is HTML-escaped via markupsafe.escape()."""
        q = request.args.get("q", "")
        return (
            f"<html><body>"
            f"<h1>Search Results</h1>"
            f"<p>You searched for: {escape(q)}</p>"
            f"</body></html>"
        )

    @app.route("/sqli-safe")
    def sqli_safe():
        """SQLi-safe: uses a parameterized query."""
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
        """Fully safe: escaped output + parameterized query."""
        name = request.args.get("name", "")
        return (
            f"<html><body>"
            f"<p>Hello, {escape(name)}!</p>"
            f"</body></html>"
        )

    return app


if __name__ == "__main__":
    create_app().run(port=9999, debug=True)
