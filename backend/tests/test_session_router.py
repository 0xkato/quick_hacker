"""Tests for session router endpoints."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime

from main import app
from middleware.auth import require_auth, AuthContext
from models.schemas import SnapshotInfo


# Mock auth context that always passes
async def mock_require_auth():
    return AuthContext(is_authenticated=True, is_legacy_token=True)


@pytest.fixture(scope="module")
def client():
    """Create test client with mocked auth (module-scoped to avoid event loop issues)."""
    # Override the auth dependency
    app.dependency_overrides[require_auth] = mock_require_auth
    with patch("main.init_db", new=AsyncMock()), \
        patch("main.initialize_triage_availability", new=AsyncMock()), \
        patch("main.settings_service.initialize", new=AsyncMock()), \
        patch("main.project_service.initialize", new=AsyncMock()):
        with TestClient(app) as c:
            yield c
    # Clean up after all tests in module
    app.dependency_overrides.clear()


@pytest.fixture
def mock_project_service():
    """Mock project service."""
    with patch("routers.session.project_service") as mock:
        mock.get_current_project_path.return_value = "/tmp/test_project"
        yield mock


@pytest.fixture
def mock_session_service():
    """Mock session service."""
    with patch("routers.session.session_service") as mock:
        yield mock


def test_get_snapshot_exists(client, mock_project_service, mock_session_service):
    """Test getting snapshot info when it exists."""
    mock_session_service.get_snapshot_info.return_value = SnapshotInfo(
        timestamp=datetime.utcnow(),
        agent_count=2,
        findings_count=5,
        pending_files=10,
    )

    response = client.get("/api/session/snapshot")
    assert response.status_code == 200
    data = response.json()
    assert data["agent_count"] == 2
    assert data["findings_count"] == 5


def test_get_snapshot_not_found(client, mock_project_service, mock_session_service):
    """Test getting snapshot when none exists."""
    mock_session_service.get_snapshot_info.return_value = None

    response = client.get("/api/session/snapshot")
    assert response.status_code == 200
    assert response.json() is None


def test_delete_snapshot(client, mock_project_service, mock_session_service):
    """Test deleting a snapshot."""
    mock_session_service.delete_snapshot.return_value = True

    response = client.delete("/api/session/snapshot")
    assert response.status_code == 200
    mock_session_service.delete_snapshot.assert_called_once()
