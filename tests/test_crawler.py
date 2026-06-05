"""
test_crawler.py — FR3: 크롤러 동작 검증

대상: pentest/crawler.py Crawler 클래스

검증 항목
---------
1. 폼 입력점 수집 — GET/POST 폼의 text/password 필드를 InputPoint로 수집
2. hidden · submit 타입 건너뜀 — _SKIP_INPUT_TYPES에 포함된 타입 미수집
3. 서브링크 따라가기 — depth=1 페이지 링크를 타고 폼 수집
4. 외부 링크 무시 — 다른 호스트 링크는 탐색하지 않음
5. 깊이 제한 — max_depth=1 로 설정하면 depth-2 페이지 미탐색
6. 중복 제거 — 같은 (action_url, method, param_name) 조합은 한 번만 수집

실행
----
    pytest tests/test_crawler.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import pytest

# ── pentest 모듈 경로는 conftest.py에서 sys.path에 추가됨 ─────────────
from crawler import Crawler
from http_client import ScanHttpClient
from models import InputPoint
from rate_limiter import RateLimiter


# ══════════════════════════════════════════════════════════════════════
# 헬퍼
# ══════════════════════════════════════════════════════════════════════

def _make_crawler(timeout: int = 5) -> Crawler:
    """기본 Crawler 인스턴스를 반환한다."""
    return Crawler(http=ScanHttpClient(RateLimiter(), timeout=timeout))


def _param_names(points: List[InputPoint]) -> set[str]:
    return {p.param_name for p in points}


def _endpoints(points: List[InputPoint]) -> set[str]:
    return {p.url for p in points}


# ══════════════════════════════════════════════════════════════════════
# FR3-1: 폼 입력점 수집 (GET/POST)
# ══════════════════════════════════════════════════════════════════════

class TestFormInputCollection:

    def test_collects_get_form_field(self, target_server: str) -> None:
        """GET 폼의 text 입력 필드가 InputPoint로 수집돼야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        assert any(p.param_name == "root_query" and p.method == "GET" for p in points), (
            "crawl-root의 GET 폼 파라미터 'root_query'가 수집되지 않음"
        )

    def test_collects_post_form_fields(self, target_server: str) -> None:
        """POST 폼의 text/password 입력 필드가 InputPoint로 수집돼야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "username" in names, "crawl-page의 POST 폼 파라미터 'username' 미수집"
        assert "password" in names, "crawl-page의 POST 폼 파라미터 'password' 미수집"

    def test_get_input_point_has_query_param_type(self, target_server: str) -> None:
        """GET 폼에서 수집한 InputPoint의 param_type은 'query'여야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        get_points = [p for p in points if p.param_name == "root_query"]
        assert get_points, "root_query InputPoint가 없음"
        assert get_points[0].param_type == "query"

    def test_post_input_point_has_form_param_type(self, target_server: str) -> None:
        """POST 폼에서 수집한 InputPoint의 param_type은 'form'이어야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        post_points = [p for p in points if p.param_name == "username"]
        assert post_points, "username InputPoint가 없음"
        assert post_points[0].param_type == "form"


# ══════════════════════════════════════════════════════════════════════
# FR3-2: skip 타입 필터링
# ══════════════════════════════════════════════════════════════════════

class TestSkipInputTypes:

    def test_hidden_input_not_collected(self, target_server: str) -> None:
        """hidden 타입 입력 필드(csrf)는 수집되지 않아야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "csrf" not in names, "hidden 입력 'csrf'가 InputPoint에 포함됨 (오탐)"

    def test_submit_input_not_collected(self, target_server: str) -> None:
        """submit 타입 입력 필드는 수집되지 않아야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        # submit 버튼은 보통 name이 없지만, 혹시 'submit' param_type이 있으면 안 됨
        # type="submit" 필드는 param_type 검사보다 param_name으로 확인
        assert all(
            p.param_name not in {"", "submit"} for p in points
        ), "name 없는 또는 submit 필드가 포함됨"


# ══════════════════════════════════════════════════════════════════════
# FR3-3: 서브링크 따라가기
# ══════════════════════════════════════════════════════════════════════

class TestSubLinkFollowing:

    def test_follows_anchor_link_to_subpage(self, target_server: str) -> None:
        """crawl-root의 <a href='/crawl-page'> 링크를 따라 crawl-page의 폼도 수집해야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        # crawl-page에만 있는 username, password가 수집돼야 함
        assert "username" in names and "password" in names, (
            "서브링크 crawl-page의 폼 파라미터가 수집되지 않음"
        )

    def test_reaches_depth_2_page(self, target_server: str) -> None:
        """depth=2 기본값으로 crawl-deep의 폼(deep_param)도 수집해야 한다."""
        crawler = _make_crawler()  # max_depth=2 기본값
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "deep_param" in names, "depth-2 페이지 crawl-deep의 파라미터 미수집"


# ══════════════════════════════════════════════════════════════════════
# FR3-4: 외부 링크 무시
# ══════════════════════════════════════════════════════════════════════

class TestExternalLinkSkipping:

    def test_does_not_follow_external_links(self, target_server: str) -> None:
        """crawl-external-link의 <a href='http://external.example.com/...'>는 따라가지 않아야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        # 수집된 모든 InputPoint URL이 target_server 호스트여야 함
        base_host = target_server.split("//")[1]  # "127.0.0.1:PORT"
        for p in points:
            host = p.url.split("//")[1].split("/")[0]
            assert host == base_host, (
                f"외부 호스트 InputPoint 발견: {p.url}"
            )


# ══════════════════════════════════════════════════════════════════════
# FR3-5: 깊이 제한
# ══════════════════════════════════════════════════════════════════════

class TestDepthLimit:

    def test_max_depth_1_does_not_reach_depth2_page(self, target_server: str) -> None:
        """max_depth=1로 설정하면 depth-2 페이지 crawl-deep의 파라미터를 수집하지 않는다."""
        crawler = Crawler(
            http=ScanHttpClient(RateLimiter(), timeout=5),
            max_depth=1,
        )
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "deep_param" not in names, (
            "max_depth=1인데 depth-2 페이지 crawl-deep의 파라미터가 수집됨"
        )

    def test_max_depth_0_only_collects_root_page(self, target_server: str) -> None:
        """max_depth=0이면 시작 페이지의 폼만 수집하고 링크는 따라가지 않는다."""
        crawler = Crawler(
            http=ScanHttpClient(RateLimiter(), timeout=5),
            max_depth=0,
        )
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        # crawl-root 폼의 root_query만 수집
        assert "root_query" in names, "root_query가 수집되지 않음"
        assert "username" not in names, "depth-1 페이지의 username이 수집됨 (max_depth=0 위반)"


# ══════════════════════════════════════════════════════════════════════
# FR3-6: 중복 제거
# ══════════════════════════════════════════════════════════════════════

class TestDeduplication:

    def test_no_duplicate_input_points(self, target_server: str) -> None:
        """같은 (url, method, param_name) 조합이 중복 수집되지 않아야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        keys = [(p.url, p.method, p.param_name) for p in points]
        assert len(keys) == len(set(keys)), (
            f"중복 InputPoint 발견: {[k for k in keys if keys.count(k) > 1]}"
        )

    def test_returns_list_of_input_points(self, target_server: str) -> None:
        """crawl() 반환값은 InputPoint 객체 리스트여야 한다."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        assert isinstance(points, list)
        for p in points:
            assert isinstance(p, InputPoint), f"InputPoint가 아닌 객체 발견: {type(p)}"
