from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.project_service import ProjectService


@pytest.mark.asyncio
async def test_create_project_autopopulates_threat_model_profile(tmp_path: Path) -> None:
    svc = ProjectService(data_dir=str(tmp_path))
    await svc.initialize()

    project = await svc.create_project(name="x")
    assert project.threat_model_preset == project.threat_model
    assert project.threat_model_profile is not None
    assert project.profile_review_status == "unreviewed"


@pytest.mark.asyncio
async def test_load_projects_migrates_missing_profile_fields(tmp_path: Path) -> None:
    projects_file = tmp_path / "projects.json"
    projects_file.write_text(
        json.dumps(
            {
                "projects": [
                    {
                        "id": "p1",
                        "name": "p",
                        "threat_model": "AB",
                        "path": str(tmp_path / "projects" / "p1"),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    svc = ProjectService(data_dir=str(tmp_path))
    await svc.initialize()

    proj = await svc.get_project("p1")
    assert proj is not None
    assert proj.threat_model_preset == "AB"
    assert proj.threat_model_profile is not None

