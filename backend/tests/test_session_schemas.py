"""Tests for session snapshot schemas."""
import pytest
from datetime import datetime
from models.schemas import (
    SessionSnapshot,
    SessionSnapshotAgent,
    SessionSnapshotLLMContext,
    SessionSnapshotUIState,
    SnapshotInfo,
)


def test_session_snapshot_agent_schema():
    """Test SessionSnapshotAgent validates correctly."""
    agent = SessionSnapshotAgent(
        id="abc123",
        agent_type="deep_audit",
        status="paused",
        target_files=["src/main.py"],
        processed_files=["src/utils.py"],
        pending_files=["src/main.py"],
        current_file=None,
        config={"provider": "anthropic", "model": "claude-3"},
    )
    assert agent.id == "abc123"
    assert agent.status == "paused"


def test_session_snapshot_llm_context():
    """Test SessionSnapshotLLMContext validates correctly."""
    ctx = SessionSnapshotLLMContext(
        agent_id="abc123",
        messages=[{"role": "user", "content": "test"}],
    )
    assert ctx.agent_id == "abc123"
    assert len(ctx.messages) == 1


def test_session_snapshot_ui_state():
    """Test SessionSnapshotUIState validates correctly."""
    ui = SessionSnapshotUIState(
        active_view="explorer",
        selected_file="src/main.py",
        open_panels=["agents", "findings"],
        selected_agent_id="abc123",
    )
    assert ui.active_view == "explorer"


def test_session_snapshot_full():
    """Test full SessionSnapshot schema."""
    snapshot = SessionSnapshot(
        version=1,
        timestamp=datetime.utcnow(),
        project_id="proj123",
        agents=[],
        findings=[],
        llm_context=[],
        ui_state=SessionSnapshotUIState(
            active_view="explorer",
            selected_file=None,
            open_panels=[],
            selected_agent_id=None,
        ),
    )
    assert snapshot.version == 1
    assert snapshot.project_id == "proj123"


def test_snapshot_info():
    """Test SnapshotInfo schema for metadata."""
    info = SnapshotInfo(
        timestamp=datetime.utcnow(),
        agent_count=2,
        findings_count=5,
        pending_files=10,
    )
    assert info.agent_count == 2
