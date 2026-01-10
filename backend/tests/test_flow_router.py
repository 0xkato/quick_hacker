"""Tests for investigation flow endpoints."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from main import app
from middleware.auth import AuthContext, require_auth


async def mock_require_auth() -> AuthContext:
    return AuthContext(is_authenticated=True)


async def mock_init_db() -> None:
    return None


@pytest.fixture(scope="module")
def client():
    """Create test client with mocked auth and DB init."""
    app.dependency_overrides[require_auth] = mock_require_auth
    with patch("main.init_db", new=mock_init_db):
        with TestClient(app) as test_client:
            yield test_client
    app.dependency_overrides.clear()


def test_get_flow_returns_empty_when_missing(client):
    response = client.get("/api/agents/nonexistent-agent/flow")
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == "nonexistent-agent"
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data["current_node_id"] is None


def test_get_flow_stats_returns_zero_when_missing(client):
    response = client.get("/api/agents/nonexistent-agent/flow/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_nodes"] == 0
    assert data["total_edges"] == 0
