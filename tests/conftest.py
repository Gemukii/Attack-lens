"""Shared fixtures for the AttackLens tests."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from attacklens.storage import Store
from attacklens.web import api


@pytest.fixture(autouse=True)
def isolated_agent_identity(tmp_path, monkeypatch) -> None:
    """Keep the tests away from the identity of the agent of this machine."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


@pytest.fixture
def store(tmp_path) -> Store:
    """Return an empty database."""
    return Store(tmp_path / "attacklens.db")


@pytest.fixture
def client(store) -> Iterator[TestClient]:
    """Return an API client bound to the temporary database."""
    api.app.dependency_overrides[api.get_store] = lambda: store
    yield TestClient(api.app, base_url="http://localhost")
    api.app.dependency_overrides.clear()
