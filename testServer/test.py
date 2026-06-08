"""
Vulnerable Test Server — Scanner Validation Lab
================================================

WARNING:
  This server is INTENTIONALLY VULNERABLE to SQL Injection and XSS.
  - DO NOT deploy to a public network
  - DO NOT use real credentials or user data
  - Bind to 127.0.0.1 only (default below)
  - Use ONLY to validate your own scanner against known vulnerabilities

Run:
  pip install flask
  python vuln_test_server.py
  # then visit http://127.0.0.1:5000
"""

import os
import sqlite3
# pyrefly: ignore [missing-import]
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = "test.db"


# ----------------------------------------------------------------------
# DB setup — fresh sqlite db on each launch so test state is reproducible
# ----------------------------------------------------------------------
def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
        """
    )
    cur.executemany(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        [
            ("alice", "password1", "alice@example.com"),
            ("bob", "password2", "bob@example.com"),
            ("charlie", "password3", "charlie@example.com"),
        ],
    )
    conn.commit()
    conn.close()


def get_db():
    return sqlite3.connect(DB_PATH)


# ----------------------------------------------------------------------
# Templates (inline so the lab fits in a single file)
# ----------------------------------------------------------------------
INDEX_TMPL = """
<!doctype html>
<html><head><title>Scanner Test Lab</title></head><body>
<h1>Scanner Test Lab</h1>
<p><b>Intentionally vulnerable.</b> Local use only.</p>
<ul>
  <li><a href="/search?q=hello">/search</a> — Reflected XSS (vulnerable)</li>
  <li><a href="/search-safe?q=hello">/search-safe</a> — Reflected XSS (escaped, clean)</li>
  <li><a href="/login">/login</a> — Error-based SQLi (POST form)</li>
  <li><a href="/user?id=1">/user?id=1</a> — Boolean-based SQLi (and error-based)</li>
  <li><a href="/user-safe?id=1">/user-safe?id=1</a> — Parameterized query (clean)</li>
</ul>
</body></html>
"""

# NOTE: |safe filter disables Jinja autoescape — that's the XSS vulnerability.
SEARCH_VULN_TMPL = """
<!doctype html>
<html><body>
<h2>Search (vulnerable)</h2>
<form method="GET" action="/search">
  <input name="q" value="{{ q }}">
  <button type="submit">Search</button>
</form>
{% if q %}<div>Results for: {{ q | safe }}</div>{% endif %}
<p><a href="/">home</a></p>
</body></html>
"""

SEARCH_SAFE_TMPL = """
<!doctype html>
<html><body>
<h2>Search (safe — autoescaped)</h2>
<form method="GET" action="/search-safe">
  <input name="q" value="{{ q }}">
  <button type="submit">Search</button>
</form>
{% if q %}<div>Results for: {{ q }}</div>{% endif %}
<p><a href="/">home</a></p>
</body></html>
"""

LOGIN_TMPL = """
<!doctype html>
<html><body>
<h2>Login (vulnerable to error-based SQLi)</h2>
<form method="POST" action="/login">
  <input name="username" placeholder="username">
  <input name="password" placeholder="password" type="password">
  <button type="submit">Login</button>
</form>
{% if message %}<div>{{ message }}</div>{% endif %}
{% if error %}<pre style="color:red;">{{ error }}</pre>{% endif %}
<p><a href="/">home</a></p>
</body></html>
"""

USER_VULN_TMPL = """
<!doctype html>
<html><body>
<h2>User Lookup (vulnerable to SQLi)</h2>
<form method="GET" action="/user">
  <input name="id" value="{{ raw_id }}">
  <button type="submit">Lookup</button>
</form>
{% if user %}
  <div>Found: id={{ user[0] }}, username={{ user[1] }}, email={{ user[3] }}</div>
{% else %}
  <div>No user found</div>
{% endif %}
{% if error %}<pre style="color:red;">{{ error }}</pre>{% endif %}
<p><a href="/">home</a></p>
</body></html>
"""

USER_SAFE_TMPL = """
<!doctype html>
<html><body>
<h2>User Lookup (parameterized, safe)</h2>
<form method="GET" action="/user-safe">
  <input name="id" value="{{ raw_id }}">
  <button type="submit">Lookup</button>
</form>
{% if user %}
  <div>Found: id={{ user[0] }}, username={{ user[1] }}, email={{ user[3] }}</div>
{% else %}
  <div>No user found</div>
{% endif %}
<p><a href="/">home</a></p>
</body></html>
"""


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------
@app.route("/")
def index():
    return render_template_string(INDEX_TMPL)


@app.route("/search")
def search_vuln():
    """Reflected XSS — q is rendered through |safe (no escaping)."""
    q = request.args.get("q", "")
    return render_template_string(SEARCH_VULN_TMPL, q=q)


@app.route("/search-safe")
def search_safe():
    """Same shape, but Jinja autoescape protects against XSS."""
    q = request.args.get("q", "")
    return render_template_string(SEARCH_SAFE_TMPL, q=q)


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Error-based SQLi:
    - Vulnerable: raw string concatenation
    - On exception, leak the SQLite error message AND the failing query.
      The leaked text contains the substring 'SQLite' which matches one of
      your scanner's SQL_ERROR_SIGNATURES.
    """
    if request.method == "GET":
        return render_template_string(LOGIN_TMPL, message=None, error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # INTENTIONALLY VULNERABLE
    query = (
        f"SELECT id, username, email FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query)
        row = cur.fetchone()
        conn.close()
        if row:
            return render_template_string(
                LOGIN_TMPL, message=f"Welcome, {row[1]}", error=None
            )
        return render_template_string(
            LOGIN_TMPL, message="Invalid credentials", error=None
        )
    except sqlite3.Error as e:
        # Leak the error so error-based scanners can detect it.
        leaked = f"SQLite error: {e} | failing query: {query}"
        return (
            render_template_string(LOGIN_TMPL, message=None, error=leaked),
            500,
        )


@app.route("/user")
def user_vuln():
    """
    Boolean-based SQLi:
    - 'id' is concatenated raw into the query.
    - Response varies clearly between TRUE (user row rendered) and
      FALSE (no user found), so boolean-based diffing should fire.
    - On a syntax error we ALSO leak it, so error-based fires too.

    Try:
      /user?id=1 AND 1=1   -> 'Found: ...'
      /user?id=1 AND 1=2   -> 'No user found'
      /user?id=1'           -> SQLite syntax error leaked
    """
    user_id = request.args.get("id", "1")
    query = f"SELECT id, username, password, email FROM users WHERE id = {user_id}"

    user = None
    error = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(query)
        user = cur.fetchone()
        conn.close()
    except sqlite3.Error as e:
        error = f"SQLite error: {e} | failing query: {query}"

    return render_template_string(
        USER_VULN_TMPL, user=user, error=error, raw_id=user_id
    )


@app.route("/user-safe")
def user_safe():
    """Parameterized — your scanner should NOT report a finding here."""
    user_id = request.args.get("id", "1")
    user = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password, email FROM users WHERE id = ?",
            (user_id,),
        )
        user = cur.fetchone()
        conn.close()
    except sqlite3.Error:
        pass
    return render_template_string(USER_SAFE_TMPL, user=user, raw_id=user_id)


# ----------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    banner = (
        "============================================================\n"
        " VULNERABLE TEST SERVER -- LOCAL USE ONLY\n"
        " Listening on http://127.0.0.1:5000\n"
        "============================================================"
    )
    print(banner)
    # debug=False on purpose — debug mode adds its own attack surface.
    app.run(host="127.0.0.1", port=5000, debug=False)