# backend/tests/routers/test_cache_router.py
import pytest
import uuid
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from main import app


class TestCacheMetricsEndpoint:
    @pytest.fixture
    def client(self):
        """Create test client with auth override."""
        app.dependency_overrides.clear()
        from middleware.auth import require_auth, AuthContext

        def mock_auth():
            return AuthContext(
                user_id=uuid.UUID("12345678-1234-5678-1234-567812345678"),
                username="test_user",
                is_authenticated=True
            )

        app.dependency_overrides[require_auth] = mock_auth
        yield TestClient(app)
        app.dependency_overrides.clear()

    def test_get_cache_metrics_returns_stats(self, client):
        """Test that /api/cache/metrics returns cache statistics."""
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
        with patch("routers.cache.settings") as mock_settings:
            mock_settings.tool_cache_enabled = False

            response = client.get("/api/cache/metrics")
            assert response.status_code == 200

            data = response.json()
            assert data["enabled"] is False
            assert data["hits"] == 0
            assert data["misses"] == 0
            assert data["hit_rate"] == 0.0
            assert data["size"] == 0

    def test_cache_metrics_requires_auth(self):
        """Test that unauthenticated requests are rejected."""
        app.dependency_overrides.clear()
        client = TestClient(app)

        response = client.get("/api/cache/metrics")
        assert response.status_code in [401, 403]  # Unauthorized or Forbidden

    def test_cache_metrics_with_agents_without_cache(self, client):
        """Test metrics when some agents lack cache."""
        mock_metrics = {
            "total_hits": 0,
            "total_misses": 0,
            "total_size": 0,
            "cache_count": 0,
        }

        with patch("routers.cache.agent_orchestrator.get_cache_metrics", return_value=mock_metrics):
            response = client.get("/api/cache/metrics")
            assert response.status_code == 200

            data = response.json()
            assert data["cache_count"] == 0
            assert data["enabled"] is True
