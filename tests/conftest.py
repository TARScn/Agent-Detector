"""Shared test fixtures: temporary database, service container, API client."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_detector.console.api.app import create_app
from agent_detector.console.api.deps import Services, set_services
from agent_detector.storage.database import make_engine


@pytest.fixture
def engine(tmp_path):
    return make_engine(tmp_path / "db.sqlite3")


@pytest.fixture
def services(engine):
    container = Services(engine)
    set_services(container)
    try:
        yield container
    finally:
        container.shutdown()
        set_services(None)


@pytest.fixture
def client(services):
    """API client without the static console mount (API-only tests)."""
    return TestClient(create_app(serve_console=False))


@pytest.fixture
def home(tmp_path):
    """Fake user home so hook installation never touches the real config."""
    path = tmp_path / "home"
    path.mkdir()
    return path