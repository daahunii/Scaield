"""
conftest.py — pytest 공용 fixture

target_server fixture:
  - target_server.py의 Flask 앱을 별도 스레드에서 실행
  - 랜덤 포트를 배정해 포트 충돌을 방지
  - session scope → 전체 테스트 세션에서 서버 하나를 공유
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

# ── pentest 모듈 경로를 sys.path에 추가 ───────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
_PENTEST_DIR = _ROOT / "pentest"
_TESTS_DIR = _ROOT / "tests"

for _p in [str(_PENTEST_DIR), str(_TESTS_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _find_free_port() -> int:
    """OS가 배정 가능한 빈 TCP 포트를 반환한다."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(host: str, port: int, timeout: float = 10.0) -> None:
    """서버가 포트를 리슨할 때까지 최대 timeout초 대기한다."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Test server did not start within {timeout}s on {host}:{port}")


@pytest.fixture(scope="session")
def target_server() -> str:
    """
    취약점 스캐너 테스트용 Flask 서버를 세션 전체에서 공유하는 fixture.

    Returns
    -------
    str
        서버 base URL (예: "http://127.0.0.1:54321")
    """
    from target_server import create_app  # tests/ 디렉터리의 target_server.py

    port = _find_free_port()
    host = "127.0.0.1"
    app = create_app()

    thread = threading.Thread(
        target=lambda: app.run(host=host, port=port, use_reloader=False, threaded=True),
        daemon=True,
    )
    thread.start()
    _wait_for_server(host, port)

    return f"http://{host}:{port}"
