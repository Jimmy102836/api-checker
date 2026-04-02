"""pytest configuration and shared fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure src/ is on the path so `api_relay_audit` imports work
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from tests.fixtures.mock_relay import (
    EvilConfig,
    create_app,
    evil_config,
    get_evil_config,
    set_evil_config,
    start_mock_server,
)


# ---------------------------------------------------------------------------
# Mock server fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def evil_cfg():
    """Fresh EvilConfig for each test (all behaviors disabled)."""
    cfg = EvilConfig()
    set_evil_config(cfg)
    yield cfg
    # Reset to defaults after test
    set_evil_config(EvilConfig())


@pytest.fixture(scope="function")
def mock_server(evil_cfg):
    """Real HTTP mock server running on a free port.

    Yields (base_url, EvilConfig) so tests can toggle behaviors and make
    direct httpx/requests calls against it.
    """
    import socket

    def find_free_port():
        with socket.socket() as s:
            s.bind(("localhost", 0))
            return s.getsockname()[1]

    port = find_free_port()
    srv = start_mock_server(port=port, config=evil_cfg)
    base_url = f"http://localhost:{port}"
    yield base_url, evil_cfg
    srv.shutdown()


@pytest.fixture(scope="function")
def flask_client(evil_cfg):
    """Flask test client (no real HTTP needed).

    Use this for fast unit tests that don't require network I/O.
    Yields (test_client, EvilConfig).
    """
    app = create_app(evil_cfg)
    with app.test_client() as client:
        yield client, evil_cfg


# ---------------------------------------------------------------------------
# Detector fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_endpoint(mock_server):
    """Returns base_url for the running mock server.

    Use this when you need real HTTP (e.g., httpx integration tests).
    """
    base_url, _ = mock_server
    return base_url


@pytest.fixture
def make_adapter():
    """Factory that builds an AutoAdapter pointing at a given base URL."""
    from api_relay_audit.adapter.auto_adapter import AutoAdapter

    def _make(base_url: str, api_key: str = "test-key"):
        return AutoAdapter(base_url=base_url, api_key=api_key)

    return _make


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def default_config():
    """Return a default AppConfig for testing."""
    from api_relay_audit.config.schema import AppConfig, GlobalSettings

    return AppConfig(
        global_settings=GlobalSettings(
            api_key="test-key",
            default_model="test-model",
            timeout_seconds=10,
            max_retries=1,
        ),
        endpoints=[],
    )
