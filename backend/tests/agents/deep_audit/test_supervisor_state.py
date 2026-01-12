# backend/tests/agents/deep_audit/test_supervisor_state.py
import pytest
from datetime import datetime, timedelta
from agents.deep_audit.state import SupervisorState


def test_supervisor_state_initialization():
    """Test SupervisorState can be created with required fields."""
    deadline = datetime.utcnow() + timedelta(minutes=15)

    state = SupervisorState(
        project_id="test_proj_123",
        scan_tier="medium",
        deadline=deadline.timestamp(),
    )

    assert state.project_id == "test_proj_123"
    assert state.scan_tier == "medium"
    assert state.deadline == deadline.timestamp()
    assert state.repo_profile_path == "/memories/repo_profile.json"
    assert state.scope_plan == []
    assert state.completed_scopes == []
    assert state.coverage_map == {}
    assert state.signal_queue == []
    assert state.active_case_ids == []
    assert state.max_signals == 100
    assert state.max_findings == 50
    assert state.signal_count == 0
    assert state.finding_count == 0


def test_supervisor_state_tracks_scopes():
    """Test SupervisorState can track scope completion."""
    deadline = datetime.utcnow() + timedelta(minutes=15)

    state = SupervisorState(
        project_id="test_proj",
        scan_tier="medium",
        deadline=deadline.timestamp(),
        scope_plan=[
            {"scope_id": "auth", "path": "/repo/auth", "status": "pending"},
            {"scope_id": "api", "path": "/repo/api", "status": "pending"},
        ],
        completed_scopes=["auth"],
    )

    assert len(state.scope_plan) == 2
    assert "auth" in state.completed_scopes
    assert "api" not in state.completed_scopes


def test_supervisor_state_tracks_coverage():
    """Test SupervisorState tracks file coverage."""
    deadline = datetime.utcnow() + timedelta(minutes=15)

    state = SupervisorState(
        project_id="test_proj",
        scan_tier="medium",
        deadline=deadline.timestamp(),
        coverage_map={
            "/repo/auth/db.py": True,
            "/repo/api/routes.py": True,
            "/repo/utils/helpers.py": False,
        }
    )

    assert state.coverage_map["/repo/auth/db.py"] is True
    assert state.coverage_map["/repo/utils/helpers.py"] is False

    # Calculate coverage percentage
    covered = sum(1 for v in state.coverage_map.values() if v)
    total = len(state.coverage_map)
    coverage_pct = (covered / total * 100) if total > 0 else 0
    assert coverage_pct == pytest.approx(66.67, rel=0.1)


def test_supervisor_state_serialization():
    """Test SupervisorState can be serialized/deserialized."""
    deadline = datetime.utcnow() + timedelta(minutes=15)

    original = SupervisorState(
        project_id="test_proj",
        scan_tier="advanced",
        deadline=deadline.timestamp(),
        signal_queue=["sql_inj_001", "xss_002"],
        signal_count=2,
        finding_count=1,
    )

    # Serialize to dict
    data = original.model_dump()

    # Deserialize from dict
    restored = SupervisorState(**data)

    assert restored.project_id == original.project_id
    assert restored.scan_tier == original.scan_tier
    assert restored.signal_queue == original.signal_queue
    assert restored.signal_count == 2
    assert restored.finding_count == 1
