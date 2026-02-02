"""Tests for session service."""
import pytest
import json
import os
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch, AsyncMock

from services.session_service import SessionService
from models.schemas import (
    SessionSnapshot,
    SessionSnapshotAgent,
    SessionSnapshotUIState,
    SnapshotInfo,
)


@pytest.fixture
def temp_project_path(tmp_path):
    """Create a temporary project directory."""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    return str(project_dir)


@pytest.fixture
def session_service():
    """Create a session service instance."""
    return SessionService()


@pytest.fixture
def sample_snapshot():
    """Create a sample snapshot."""
    return SessionSnapshot(
        version=1,
        timestamp=datetime.utcnow(),
        project_id="proj123",
        agents=[
            SessionSnapshotAgent(
                id="agent1",
                agent_type="deep_audit",
                status="paused",
                target_files=["a.py", "b.py"],
                processed_files=["a.py"],
                pending_files=["b.py"],
                current_file=None,
                config={},
            )
        ],
        findings=[{"id": "f1", "title": "Test finding"}],
        llm_context=[],
        ui_state=SessionSnapshotUIState(
            active_view="explorer",
            selected_file=None,
            open_panels=[],
            selected_agent_id=None,
        ),
    )


def test_get_snapshot_path(session_service, temp_project_path):
    """Test snapshot path generation."""
    path = session_service.get_snapshot_path(temp_project_path)
    assert path.endswith(".quickhack/session-snapshot.json")
    assert temp_project_path in path


def test_save_snapshot(session_service, temp_project_path, sample_snapshot):
    """Test saving a snapshot to disk."""
    session_service.save_snapshot(temp_project_path, sample_snapshot)

    snapshot_path = session_service.get_snapshot_path(temp_project_path)
    assert os.path.exists(snapshot_path)

    with open(snapshot_path) as f:
        data = json.load(f)

    assert data["version"] == 1
    assert data["project_id"] == "proj123"
    assert len(data["agents"]) == 1


def test_load_snapshot(session_service, temp_project_path, sample_snapshot):
    """Test loading a snapshot from disk."""
    session_service.save_snapshot(temp_project_path, sample_snapshot)

    loaded = session_service.load_snapshot(temp_project_path)
    assert loaded is not None
    assert loaded.project_id == "proj123"
    assert len(loaded.agents) == 1
    assert loaded.agents[0].id == "agent1"


def test_load_snapshot_not_found(session_service, temp_project_path):
    """Test loading when no snapshot exists."""
    loaded = session_service.load_snapshot(temp_project_path)
    assert loaded is None


def test_get_snapshot_info(session_service, temp_project_path, sample_snapshot):
    """Test getting snapshot metadata."""
    session_service.save_snapshot(temp_project_path, sample_snapshot)

    info = session_service.get_snapshot_info(temp_project_path)
    assert info is not None
    assert info.agent_count == 1
    assert info.findings_count == 1
    assert info.pending_files == 1


def test_delete_snapshot(session_service, temp_project_path, sample_snapshot):
    """Test deleting a snapshot."""
    session_service.save_snapshot(temp_project_path, sample_snapshot)

    snapshot_path = session_service.get_snapshot_path(temp_project_path)
    assert os.path.exists(snapshot_path)

    session_service.delete_snapshot(temp_project_path)
    assert not os.path.exists(snapshot_path)
