"""
test_detection_functions.py — 핵심 탐지 함수 유닛 테스트

대상 함수
---------
pentest/response_analyzer.py
  - is_payload_reflected()
  - find_sql_error()
  - diff_responses()
  - is_meaningful_diff()

pentest/rate_limiter.py
  - RateLimiter.report_failure() (임계치 초과 시 RateLimiterError)
  - RateLimiter.report_success() (카운터 리셋)

scanner/app.py
  - _parse_cookies_input()
  - _build_effective_domains()
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── 경로 추가 (conftest.py가 pentest/를 추가하지만 명시적으로 재확인) ──
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
from app import _parse_cookies_input, _build_effective_domains


# ── 테스트용 Mock Response 헬퍼 ───────────────────────────────────────

def _resp(text: str, status_code: int = 200):
    """diff_responses()용 경량 mock Response 객체."""
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    return r


# ══════════════════════════════════════════════════════════════════════
# is_payload_reflected()
# ══════════════════════════════════════════════════════════════════════

class TestIsPayloadReflected:

    def test_exact_match_returns_true(self):
        """페이로드가 HTML에 그대로 포함되면 True."""
        payload = "<script>alert('XSS')</script>"
        html = f"<p>Search: {payload}</p>"
        assert is_payload_reflected(html, payload) is True

    def test_partial_tag_match_returns_true(self):
        """페이로드의 위험 태그(<script>)가 응답 HTML에 존재하면 True."""
        payload = "<script>alert('XSS')</script>"
        html = "<html><body><script>legit();</script><p>hello</p></body></html>"
        # <script> 토큰이 페이로드와 HTML 모두에 존재 → True
        assert is_payload_reflected(html, payload) is True

    def test_img_tag_match_returns_true(self):
        """<img> 계열 페이로드가 응답에 반사되면 True."""
        payload = '<img src=x onerror=alert(1)>'
        html = f"<body>{payload}</body>"
        assert is_payload_reflected(html, payload) is True

    def test_svg_tag_match_returns_true(self):
        """<svg> 계열 페이로드가 응답에 반사되면 True."""
        payload = "<svg onload=alert(1)>"
        html = f"<body>{payload}</body>"
        assert is_payload_reflected(html, payload) is True

    def test_html_escaped_returns_false(self):
        """페이로드가 HTML 이스케이프된 경우 False."""
        payload = "<script>alert('XSS')</script>"
        html = "<p>&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;</p>"
        assert is_payload_reflected(html, payload) is False

    def test_no_match_returns_false(self):
        """페이로드가 응답에 전혀 없으면 False."""
        assert is_payload_reflected("<p>Hello world</p>", "<script>alert(1)</script>") is False

    def test_case_insensitive_tag_matching(self):
        """태그 비교는 대소문자를 구분하지 않는다."""
        payload = "<SCRIPT>alert(1)</SCRIPT>"
        html = f"<body>{payload}</body>"
        assert is_payload_reflected(html, payload) is True

    def test_known_fp_page_with_own_script_tags(self):
        """
        [알려진 한계 — FP 위험]
        페이지에 정상적인 <script> 태그가 있고 사용자 입력은 이스케이프됐음에도
        is_payload_reflected()가 True를 반환하는 오탐 케이스를 문서화한다.
        """
        payload = "<script>alert('XSS')</script>"
        html = (
            "<html>"
            "<head><script>var ga='UA-123';</script></head>"
            "<body><p>&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;</p></body>"
            "</html>"
        )
        # 페이로드의 <script>와 HTML의 정상 <script>가 모두 존재 → 오탐(True) 반환
        # 이 동작은 스캐너의 알려진 한계이며, 개선 시 이 테스트가 바뀌어야 함
        result = is_payload_reflected(html, payload)
        assert result is True  # 현재 동작: FP 발생


# ══════════════════════════════════════════════════════════════════════
# find_sql_error()
# ══════════════════════════════════════════════════════════════════════

class TestFindSqlError:

    def test_sqlite_keyword_detected(self):
        """'SQLite' 시그니처 탐지."""
        html = "<p>SQLite error: near '\"': syntax error</p>"
        assert find_sql_error(html, SQL_ERROR_SIGNATURES) == "SQLite"

    def test_sql_syntax_keyword_detected(self):
        """'SQL syntax' 시그니처 탐지."""
        html = "<p>You have an error in your SQL syntax near 'WHERE'</p>"
        result = find_sql_error(html, SQL_ERROR_SIGNATURES)
        assert result is not None
        assert "SQL" in result

    def test_case_insensitive_matching(self):
        """대소문자 구분 없이 탐지한다."""
        html = "<p>sqlite error occurred</p>"
        assert find_sql_error(html, SQL_ERROR_SIGNATURES) == "SQLite"

    def test_no_error_returns_none(self):
        """SQL 에러 시그니처가 없으면 None 반환."""
        html = "<p>Welcome, user!</p>"
        assert find_sql_error(html, SQL_ERROR_SIGNATURES) is None

    def test_safe_page_with_sqlite_mention(self):
        """
        [알려진 한계 — FP 위험]
        페이지가 'SQLite'를 일반 텍스트로 언급할 경우 오탐 발생.
        """
        html = "<p>This app is powered by SQLite database.</p>"
        # 정상 콘텐츠임에도 'SQLite' 시그니처가 매칭됨 → 알려진 FP
        result = find_sql_error(html, SQL_ERROR_SIGNATURES)
        assert result == "SQLite"  # 현재 동작: FP 발생

    def test_returns_first_matched_signature(self):
        """여러 시그니처가 있을 때 첫 번째 매칭을 반환한다."""
        html = "<p>SQLite error: SQL syntax</p>"
        result = find_sql_error(html, SQL_ERROR_SIGNATURES)
        assert result is not None


# ══════════════════════════════════════════════════════════════════════
# diff_responses() / is_meaningful_diff()
# ══════════════════════════════════════════════════════════════════════

class TestDiffResponses:

    def test_identical_responses_all_zero(self):
        """동일한 응답 → 모든 diff 값이 0."""
        html = "<p>User: admin</p>"
        diff = diff_responses(_resp(html), _resp(html))
        assert diff["status"] == 0
        assert diff["body_len"] == 0
        assert diff["keyword"] is False
        assert diff["dom"] == 0

    def test_status_code_difference_detected(self):
        """HTTP 상태 코드 차이를 탐지한다."""
        diff = diff_responses(_resp("<p>ok</p>", 200), _resp("<p>ok</p>", 404))
        assert diff["status"] == 204

    def test_body_length_difference_detected(self):
        """본문 길이 차이를 탐지한다."""
        short = "<p>No.</p>"
        long_ = "<p>User: admin, Email: admin@example.com, Role: admin, Active: True</p>"
        diff = diff_responses(_resp(long_), _resp(short))
        assert diff["body_len"] == abs(len(long_) - len(short))

    def test_keyword_difference_detected(self):
        """에러 키워드가 한쪽에만 있을 때 탐지한다."""
        diff = diff_responses(
            _resp("<p>User found</p>"),
            _resp("<p>Error: not found</p>"),
        )
        assert diff["keyword"] is True

    def test_dom_tag_count_difference(self):
        """HTML 태그 수 차이를 탐지한다."""
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
        """경계값: body_len 차이 19바이트는 유의미하지 않다."""
        assert is_meaningful_diff({"status": 0, "body_len": 19, "keyword": False, "dom": 0}) is False

    def test_body_len_20_is_meaningful(self):
        """경계값: body_len 차이 20바이트는 유의미하다."""
        assert is_meaningful_diff({"status": 0, "body_len": 20, "keyword": False, "dom": 0}) is True

    def test_keyword_diff_is_meaningful(self):
        assert is_meaningful_diff({"status": 0, "body_len": 0, "keyword": True, "dom": 0}) is True

    def test_dom_diff_2_is_not_meaningful(self):
        """경계값: DOM 태그 차이 2개는 유의미하지 않다."""
        assert is_meaningful_diff({"status": 0, "body_len": 0, "keyword": False, "dom": 2}) is False

    def test_dom_diff_3_is_meaningful(self):
        """경계값: DOM 태그 차이 3개는 유의미하다."""
        assert is_meaningful_diff({"status": 0, "body_len": 0, "keyword": False, "dom": 3}) is True


# ══════════════════════════════════════════════════════════════════════
# RateLimiter
# ══════════════════════════════════════════════════════════════════════

class TestRateLimiter:

    def test_raises_after_fail_threshold(self):
        """연속 실패 횟수가 임계치에 도달하면 RateLimiterError를 발생시킨다."""
        rl = RateLimiter(fail_threshold=3)
        rl.report_failure()
        rl.report_failure()
        with pytest.raises(RateLimiterError):
            rl.report_failure()  # 3번째 → 예외

    def test_success_resets_failure_counter(self):
        """성공 보고 시 연속 실패 카운터가 초기화된다."""
        rl = RateLimiter(fail_threshold=3)
        rl.report_failure()
        rl.report_failure()
        rl.report_success()    # 카운터 리셋
        rl.report_failure()    # 다시 1회 → 예외 없음
        rl.report_failure()    # 2회 → 예외 없음

    def test_counter_resets_after_raise(self):
        """RateLimiterError 발생 후 카운터가 리셋돼 다시 누적 가능하다."""
        rl = RateLimiter(fail_threshold=2)
        rl.report_failure()
        with pytest.raises(RateLimiterError):
            rl.report_failure()  # 2번째 → 예외 + 리셋
        # 리셋됐으므로 다음 실패는 예외 없음
        rl.report_failure()  # 1회 → 예외 없음


# ══════════════════════════════════════════════════════════════════════
# _parse_cookies_input()
# ══════════════════════════════════════════════════════════════════════

class TestParseCookiesInput:

    def test_semicolon_separated(self):
        result = _parse_cookies_input("PHPSESSID=abc123; security=low")
        assert result == {"PHPSESSID": "abc123", "security": "low"}

    def test_newline_separated(self):
        result = _parse_cookies_input("session=xyz\ntoken=123")
        assert result == {"session": "xyz", "token": "123"}

    def test_empty_string_returns_empty_dict(self):
        assert _parse_cookies_input("") == {}

    def test_whitespace_only_returns_empty_dict(self):
        assert _parse_cookies_input("   ") == {}

    def test_strips_whitespace_around_key_value(self):
        result = _parse_cookies_input("  key  =  value  ")
        assert result == {"key": "value"}

    def test_value_with_equals_sign(self):
        """값에 = 기호가 포함된 경우 (Base64 등)."""
        result = _parse_cookies_input("token=abc=def==")
        assert result["token"] == "abc=def=="

    def test_key_without_value(self):
        result = _parse_cookies_input("key=")
        assert result == {"key": ""}

    def test_mixed_separators(self):
        result = _parse_cookies_input("a=1; b=2\nc=3")
        assert result == {"a": "1", "b": "2", "c": "3"}


# ══════════════════════════════════════════════════════════════════════
# _build_effective_domains()
# ══════════════════════════════════════════════════════════════════════

class TestBuildEffectiveDomains:

    def test_always_includes_localhost(self):
        domains = _build_effective_domains("http://example.com/path", "")
        assert "localhost" in domains

    def test_extracts_host_from_target_url(self):
        domains = _build_effective_domains("http://example.com/path", "")
        assert "example.com" in domains

    def test_merges_approved_domains(self):
        domains = _build_effective_domains("http://example.com/", "staging.com,dev.local")
        assert "staging.com" in domains
        assert "dev.local" in domains

    def test_no_duplicates(self):
        """localhost가 approved_domains에도 있으면 중복 없이 한 번만 포함."""
        domains = _build_effective_domains("http://localhost/path", "localhost")
        assert domains.count("localhost") == 1

    def test_target_already_in_approved_no_duplicate(self):
        domains = _build_effective_domains("http://example.com/", "example.com")
        assert domains.count("example.com") == 1

    def test_empty_approved_domains(self):
        domains = _build_effective_domains("http://mysite.com/", "")
        assert "localhost" in domains
        assert "mysite.com" in domains
