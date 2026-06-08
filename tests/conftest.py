from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PENTEST_DIR = _ROOT / "pentest"
_TESTS_DIR = _ROOT / "tests"

for _p in [str(_PENTEST_DIR), str(_TESTS_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(host: str, port: int, timeout: float = 10.0) -> None:
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
    """Start the test Flask server and return its base URL (e.g. 'http://127.0.0.1:54321')."""
    from target_server import create_app

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
