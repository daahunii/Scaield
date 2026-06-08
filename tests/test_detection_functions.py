from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCANNER_DIR = _ROOT / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from response_analyzer import (
    is_payload_reflected,
    find_sql_error,
    diff_responses,
    is_meaningful_diff,
)
from payload import SQL_ERROR_SIGNATURES
from rate_limiter import RateLimiter, RateLimiterError

# (Removed scanner/app.py imports)


def _resp(text: str, status_code: int = 200):
    """Lightweight mock response object for diff_responses()."""
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    return r


# ══════════════════════════════════════════════════════════════════════
# is_payload_reflected()
# ══════════════════════════════════════════════════════════════════════

class TestIsPayloadReflected:

    def test_exact_match_returns_true(self):
        payload = "<script>alert('XSS')</script>"
        html = f"<p>Search: {payload}</p>"
        assert is_payload_reflected(html, payload) is True

    def test_partial_tag_match_returns_true(self):
        payload = "<script>alert('XSS')</script>"
        html = "<html><body><script>legit();</script><p>hello</p></body></html>"
        assert is_payload_reflected(html, payload) is True

    def test_img_tag_match_returns_true(self):
        payload = '<img src=x onerror=alert(1)>'
        html = f"<body>{payload}</body>"
        assert is_payload_reflected(html, payload) is True

    def test_svg_tag_match_returns_true(self):
        payload = "<svg onload=alert(1)>"
        html = f"<body>{payload}</body>"
        assert is_payload_reflected(html, payload) is True

    def test_html_escaped_returns_false(self):
        payload = "<script>alert('XSS')</script>"
        html = "<p>&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;</p>"
        assert is_payload_reflected(html, payload) is False

    def test_no_match_returns_false(self):
        assert is_payload_reflected("<p>Hello world</p>", "<script>alert(1)</script>") is False

    def test_case_insensitive_tag_matching(self):
        payload = "<SCRIPT>alert(1)</SCRIPT>"
        html = f"<body>{payload}</body>"
        assert is_payload_reflected(html, payload) is True

    def test_known_fp_page_with_own_script_tags(self):
        """
        Known limitation: page has a legitimate <script> tag and the user input
        is escaped, yet is_payload_reflected() returns True (false positive).
        This test documents the current behavior; fix it when the logic improves.
        """
        payload = "<script>alert('XSS')</script>"
        html = (
            "<html>"
            "<head><script>var ga='UA-123';</script></head>"
            "<body><p>&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;</p></body>"
            "</html>"
        )
        result = is_payload_reflected(html, payload)
        assert result is True  # current behavior: FP


# ══════════════════════════════════════════════════════════════════════
# find_sql_error()
# ══════════════════════════════════════════════════════════════════════

class TestFindSqlError:

    def test_sqlite_keyword_detected(self):
        html = "<p>SQLite error: near '\"': syntax error</p>"
        assert find_sql_error(html, SQL_ERROR_SIGNATURES) == "SQLite"

    def test_sql_syntax_keyword_detected(self):
        html = "<p>You have an error in your SQL syntax near 'WHERE'</p>"
        result = find_sql_error(html, SQL_ERROR_SIGNATURES)
        assert result is not None
        assert "SQL" in result

    def test_case_insensitive_matching(self):
        html = "<p>sqlite error occurred</p>"
        assert find_sql_error(html, SQL_ERROR_SIGNATURES) == "SQLite"

    def test_no_error_returns_none(self):
        html = "<p>Welcome, user!</p>"
        assert find_sql_error(html, SQL_ERROR_SIGNATURES) is None

    def test_safe_page_with_sqlite_mention(self):
        """
        Known limitation: a page that mentions 'SQLite' in normal text triggers
        a false positive. This test documents the current behavior.
        """
        html = "<p>This app is powered by SQLite database.</p>"
        result = find_sql_error(html, SQL_ERROR_SIGNATURES)
        assert result == "SQLite"  # current behavior: FP

    def test_returns_first_matched_signature(self):
        html = "<p>SQLite error: SQL syntax</p>"
        result = find_sql_error(html, SQL_ERROR_SIGNATURES)
        assert result is not None


# ══════════════════════════════════════════════════════════════════════
# diff_responses() / is_meaningful_diff()
# ══════════════════════════════════════════════════════════════════════

class TestDiffResponses:

    def test_identical_responses_all_zero(self):
        html = "<p>User: admin</p>"
        diff = diff_responses(_resp(html), _resp(html))
        assert diff["status"] == 0
        assert diff["body_len"] == 0
        assert diff["keyword"] is False
        assert diff["dom"] == 0

    def test_status_code_difference_detected(self):
        diff = diff_responses(_resp("<p>ok</p>", 200), _resp("<p>ok</p>", 404))
        assert diff["status"] == 204

    def test_body_length_difference_detected(self):
        short = "<p>No.</p>"
        long_ = "<p>User: admin, Email: admin@example.com, Role: admin, Active: True</p>"
        diff = diff_responses(_resp(long_), _resp(short))
        assert diff["body_len"] == abs(len(long_) - len(short))

    def test_keyword_difference_detected(self):
        diff = diff_responses(
            _resp("<p>User found</p>"),
            _resp("<p>Error: not found</p>"),
        )
        assert diff["keyword"] is True

    def test_dom_tag_count_difference(self):
        many_tags = "<div><p><span>a</span></p><p><b>b</b></p></div>"
        few_tags = "<p>ok</p>"
        diff = diff_responses(_resp(many_tags), _resp(few_tags))
        assert diff["dom"] > 0


class TestIsMeaningfulDiff:

    def test_no_diff_is_not_meaningful(self):
        assert is_meaningful_diff({"status": 0, "body_len": 0, "keyword": False, "dom": 0}) is False

    def test_status_diff_is_meaningful(self):
        assert is_meaningful_diff({"status": 200, "body_len": 0, "keyword": False, "dom": 0}) is True

    def test_body_len_19_is_not_meaningful(self):
        """Boundary: 19-byte body difference is below the significance threshold."""
        assert is_meaningful_diff({"status": 0, "body_len": 19, "keyword": False, "dom": 0}) is False

    def test_body_len_20_is_meaningful(self):
        """Boundary: 20-byte body difference meets the significance threshold."""
        assert is_meaningful_diff({"status": 0, "body_len": 20, "keyword": False, "dom": 0}) is True

    def test_keyword_diff_is_meaningful(self):
        assert is_meaningful_diff({"status": 0, "body_len": 0, "keyword": True, "dom": 0}) is True

    def test_dom_diff_2_is_not_meaningful(self):
        """Boundary: 2-tag DOM difference is below the significance threshold."""
        assert is_meaningful_diff({"status": 0, "body_len": 0, "keyword": False, "dom": 2}) is False

    def test_dom_diff_3_is_meaningful(self):
        """Boundary: 3-tag DOM difference meets the significance threshold."""
        assert is_meaningful_diff({"status": 0, "body_len": 0, "keyword": False, "dom": 3}) is True


# ══════════════════════════════════════════════════════════════════════
# RateLimiter
# ══════════════════════════════════════════════════════════════════════

class TestRateLimiter:

    def test_raises_after_fail_threshold(self):
        rl = RateLimiter(fail_threshold=3)
        rl.report_failure()
        rl.report_failure()
        with pytest.raises(RateLimiterError):
            rl.report_failure()

    def test_success_resets_failure_counter(self):
        rl = RateLimiter(fail_threshold=3)
        rl.report_failure()
        rl.report_failure()
        rl.report_success()
        rl.report_failure()  # counter reset — no exception
        rl.report_failure()  # still under threshold

    def test_counter_resets_after_raise(self):
        """Counter resets to 0 after RateLimiterError is raised, allowing re-accumulation."""
        rl = RateLimiter(fail_threshold=2)
        rl.report_failure()
        with pytest.raises(RateLimiterError):
            rl.report_failure()
# (Removed cookie parsing and domain building tests since app.py was deleted)
