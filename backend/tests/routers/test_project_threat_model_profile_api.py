from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from middleware.auth import AuthContext
from routers import projects as projects_router
from services.project_service import ProjectService


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


def _create_project(service: ProjectService) -> str:
    project = asyncio.run(service.create_project(name="p"))
    return project.id


def test_put_mark_reviewed_requires_expected_profile_hash(tmp_path: Path) -> None:
    service = ProjectService(data_dir=str(tmp_path))
    asyncio.run(service.initialize())
    project_id = _create_project(service)

    app = _build_app()
    with patch("routers.projects.project_service", service), TestClient(app) as client:
        resp = client.put(f"/api/projects/{project_id}/threat-model-profile", json={"action": "mark_reviewed"})
        assert resp.status_code == 400
        body = resp.json()
        assert body.get("error_code") == "MISSING_EXPECTED_PROFILE_HASH"
        assert body.get("retryable") is True


def test_put_mark_reviewed_409_on_hash_mismatch(tmp_path: Path) -> None:
    service = ProjectService(data_dir=str(tmp_path))
    asyncio.run(service.initialize())
    project_id = _create_project(service)

    app = _build_app()
    with patch("routers.projects.project_service", service), TestClient(app) as client:
        resp = client.put(
            f"/api/projects/{project_id}/threat-model-profile",
            json={"action": "mark_reviewed", "expected_profile_hash": "deadbeef"},
        )
        assert resp.status_code == 409
        body = resp.json()
        assert body.get("error_code") == "PROFILE_HASH_MISMATCH"
        assert body.get("retryable") is True
        assert body.get("current_profile_hash")

