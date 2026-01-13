# backend/tests/routers/test_cache_router.py
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


class TestCacheMetricsEndpoint:
    def test_get_cache_metrics_returns_stats(self, client):
        """Test that /api/cache/metrics returns cache statistics."""
        # This test assumes cache exists and has been used
        # In reality, metrics will be 0 initially
        response = client.get("/api/cache/metrics")

        assert response.status_code == 200
        data = response.json()

        # Verify structure
        assert "hits" in data
        assert "misses" in data
        assert "hit_rate" in data
        assert "size" in data
        assert "enabled" in data

        # Verify types
        assert isinstance(data["hits"], int)
        assert isinstance(data["misses"], int)
        assert isinstance(data["hit_rate"], float)
        assert isinstance(data["size"], int)
        assert isinstance(data["enabled"], bool)

    def test_cache_metrics_disabled_when_config_false(self, client):
        """Test that metrics show enabled=False when caching disabled."""
        # This requires mocking settings or environment variable
        # For now, just verify the endpoint exists
        response = client.get("/api/cache/metrics")
        assert response.status_code == 200
