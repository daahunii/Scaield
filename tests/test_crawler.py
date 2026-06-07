from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import pytest
import requests as _requests

# ── scanner_core 경로 추가 ──────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
_SCANNER_DIR = _ROOT / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from scanner_core import IntelligentCrawler, InputPoint


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def _make_crawler(max_pages: int = 30) -> IntelligentCrawler:
    """Return a default IntelligentCrawler instance (dynamic/Selenium disabled)."""
    return IntelligentCrawler(
        session=_requests.Session(),
        dynamic_enabled=False,
        max_pages=max_pages,
    )


def _param_names(points: List[InputPoint]) -> set[str]:
    return {p.parameter for p in points}


def _endpoints(points: List[InputPoint]) -> set[str]:
    return {p.url for p in points}


# ══════════════════════════════════════════════════════════════════════
# FR3-1: Form input collection (GET/POST)
# ══════════════════════════════════════════════════════════════════════

class TestFormInputCollection:

    def test_collects_get_form_field(self, target_server: str) -> None:
        """GET form text input is collected as an InputPoint."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        assert any(p.parameter == "root_query" and p.http_method == "GET" for p in points), (
            "GET form parameter 'root_query' from /crawl-root was not collected"
        )

    def test_collects_post_form_fields(self, target_server: str) -> None:
        """POST form text/password inputs are collected as InputPoints."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "username" in names, "POST form parameter 'username' not collected"
        assert "password" in names, "POST form parameter 'password' not collected"

    def test_get_input_point_has_get_method(self, target_server: str) -> None:
        """InputPoint from a GET form has http_method == 'GET'."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        get_points = [p for p in points if p.parameter == "root_query"]
        assert get_points, "root_query InputPoint not found"
        assert get_points[0].http_method == "GET"

    def test_post_input_point_has_post_method(self, target_server: str) -> None:
        """InputPoint from a POST form has http_method == 'POST'."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        post_points = [p for p in points if p.parameter == "username"]
        assert post_points, "username InputPoint not found"
        assert post_points[0].http_method == "POST"


# ══════════════════════════════════════════════════════════════════════
# FR3-2: Non-injectable input type filtering
# ══════════════════════════════════════════════════════════════════════

class TestSkipInputTypes:

    def test_hidden_input_is_collected(self, target_server: str) -> None:
        """
        hidden type inputs ARE collected as injectable points.

        Hidden fields can carry injectable values (e.g. CSRF token bypass,
        parameter tampering), so IntelligentCrawler includes them.
        Only non-injectable control types (submit, reset, image, button, file)
        are excluded.
        """
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "csrf" in names, (
            "hidden input 'csrf' should be collected as an injectable point"
        )
        # Verify the input_type is preserved
        csrf_points = [p for p in points if p.parameter == "csrf"]
        assert csrf_points[0].input_type == "hidden"

    def test_submit_input_not_collected(self, target_server: str) -> None:
        """submit type inputs are not collected as InputPoints."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        # submit inputs have no name attribute in the test server HTML,
        # and even if named, type=submit must be excluded.
        assert all(
            p.input_type not in {"submit", "reset", "image", "button", "file"}
            for p in points
        ), "Non-injectable input type (submit/reset/image/button/file) found in results"


# ══════════════════════════════════════════════════════════════════════
# FR3-3: Sub-link following
# ══════════════════════════════════════════════════════════════════════

class TestSubLinkFollowing:

    def test_follows_anchor_link_to_subpage(self, target_server: str) -> None:
        """Crawler follows <a href='/crawl-page'> and collects its forms."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "username" in names and "password" in names, (
            "Sub-page /crawl-page form parameters not collected"
        )

    def test_reaches_depth_2_page(self, target_server: str) -> None:
        """With sufficient max_pages, depth-2 page /crawl-deep is also crawled."""
        crawler = _make_crawler(max_pages=30)
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "deep_param" in names, "Depth-2 page /crawl-deep parameter not collected"


# ══════════════════════════════════════════════════════════════════════
# FR3-4: External link skipping
# ══════════════════════════════════════════════════════════════════════

class TestExternalLinkSkipping:

    def test_does_not_follow_external_links(self, target_server: str) -> None:
        """<a href='http://external.example.com/...'> is not followed."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        base_host = target_server.split("//")[1]  # "127.0.0.1:PORT"
        for p in points:
            host = p.url.split("//")[1].split("/")[0]
            assert host == base_host, (
                f"External host InputPoint found: {p.url}"
            )


# ══════════════════════════════════════════════════════════════════════
# FR3-5: Page limit (replaces max_depth)
# ══════════════════════════════════════════════════════════════════════

class TestDepthLimit:

    def test_max_pages_3_does_not_reach_depth2_page(self, target_server: str) -> None:
        """
        With max_pages=3 the BFS visits root + 2 depth-1 pages and stops,
        so depth-2 page /crawl-deep (and its 'deep_param') is not reached.

        BFS order from /crawl-root:
          visit 1: /crawl-root        → enqueues /crawl-page, /crawl-external-link
          visit 2: /crawl-page        → enqueues /crawl-deep
          visit 3: /crawl-external-link → max_pages reached, stop
        """
        crawler = _make_crawler(max_pages=3)
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "deep_param" not in names, (
            "max_pages=3 should not reach /crawl-deep"
        )

    def test_max_pages_1_only_collects_root_page(self, target_server: str) -> None:
        """max_pages=1 visits only the seed page and collects only its forms."""
        crawler = _make_crawler(max_pages=1)
        points = crawler.crawl(f"{target_server}/crawl-root")

        names = _param_names(points)
        assert "root_query" in names, "root_query not collected on seed page"
        assert "username" not in names, (
            "max_pages=1 should not follow links to /crawl-page"
        )


# ══════════════════════════════════════════════════════════════════════
# FR3-6: Deduplication
# ══════════════════════════════════════════════════════════════════════

class TestDeduplication:

    def test_no_duplicate_input_points(self, target_server: str) -> None:
        """The same (url, http_method, parameter) combination is collected only once."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        keys = [(p.url, p.http_method, p.parameter) for p in points]
        assert len(keys) == len(set(keys)), (
            f"Duplicate InputPoints found: {[k for k in keys if keys.count(k) > 1]}"
        )

    def test_returns_list_of_input_points(self, target_server: str) -> None:
        """crawl() returns a list of InputPoint objects."""
        crawler = _make_crawler()
        points = crawler.crawl(f"{target_server}/crawl-root")

        assert isinstance(points, list)
        for p in points:
            assert isinstance(p, InputPoint), f"Non-InputPoint object found: {type(p)}"
