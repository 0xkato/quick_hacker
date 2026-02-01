"""Tests for validation profile API endpoints."""
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock

from middleware.auth import AuthContext
from routers import projects as projects_router


async def mock_require_auth() -> AuthContext:
    return AuthContext(is_authenticated=True)


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(
        projects_router.router,
        prefix="/api",
        dependencies=[Depends(mock_require_auth)],
    )
    return app


@pytest.fixture
def client():
    app = _build_app()
    return TestClient(app)


@pytest.fixture
def mock_project_service():
    with patch("routers.projects.project_service") as mock:
        # Create a mock project
        mock_project = MagicMock()
        mock_project.id = "test-123"
        mock_project.name = "Test"
        mock_project.validation_profile = None
        mock_project.get_validation_profile = MagicMock(
            return_value=MagicMock(
                excluded_paths=[],
                model_dump=MagicMock(return_value={"excluded_paths": []})
            )
        )
        mock.get_project = AsyncMock(return_value=mock_project)
        mock.update_project = AsyncMock(return_value=mock_project)
        mock._save_projects = AsyncMock()
        yield mock


class TestValidationProfileRoutes:
    def test_get_validation_profile(self, client, mock_project_service):
        response = client.get("/api/projects/test-123/validation-profile")
        assert response.status_code == 200
        data = response.json()
        assert "excluded_paths" in data

    def test_put_validation_profile(self, client, mock_project_service):
        profile_data = {
            "excluded_paths": ["tools/", "test/"],
            "attacker_roles": {},
            "trust_boundaries": {},
            "evidence_gates": {},
            "enabled_verifiers": [],
            "default_verdict": "not_actionable",
            "require_shipped_reachability": True,
        }
        response = client.put(
            "/api/projects/test-123/validation-profile",
            json=profile_data,
        )
        assert response.status_code == 200

    def test_apply_preset(self, client, mock_project_service):
        response = client.post(
            "/api/projects/test-123/validation-profile/apply-preset",
            json={"preset": "webapp"},
        )
        assert response.status_code == 200

    def test_apply_preset_unknown(self, client, mock_project_service):
        response = client.post(
            "/api/projects/test-123/validation-profile/apply-preset",
            json={"preset": "nonexistent"},
        )
        assert response.status_code == 404

    def test_list_presets(self, client):
        response = client.get("/api/projects/validation-presets")
        assert response.status_code == 200
        data = response.json()
        assert "large_c_codebase" in data
        assert "webapp" in data
