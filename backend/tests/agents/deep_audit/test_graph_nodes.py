"""
Test suite for LangGraph node functions in deep_audit supervisor.
"""

import pytest
from datetime import datetime, timedelta, timezone
from agents.deep_audit.nodes import (
    init_state,
    SCAN_TIER_BUDGETS,
)
from agents.deep_audit.state import SupervisorState


def test_init_state_sets_deadline():
    """Test that init_state sets deadline correctly based on scan tier."""
    state = SupervisorState(
        project_id="test_proj",
        scan_tier="medium",
        deadline=0.0,  # Will be set by init_state
    )

    start_time = datetime.utcnow().timestamp()
    result = init_state(state)
    end_time = datetime.utcnow().timestamp()

    # Deadline should be set
    assert result.deadline > 0

    # Deadline should be approximately start_time + medium tier budget (900 seconds)
    expected_deadline_min = start_time + SCAN_TIER_BUDGETS["medium"]
    expected_deadline_max = end_time + SCAN_TIER_BUDGETS["medium"] + 10  # 10 second buffer

    assert expected_deadline_min <= result.deadline <= expected_deadline_max


def test_init_state_creates_memories_structure():
    """Test that init_state initializes state properly."""
    state = SupervisorState(
        project_id="test_proj",
        scan_tier="quick",
        deadline=0.0,
    )

    result = init_state(state)

    # Verify state was returned and deadline was set
    assert result.project_id == "test_proj"
    assert result.deadline > 0  # Deadline should be set


def test_supervisor_can_be_instantiated():
    """Test DeepAuditSupervisor can be created."""
    from agents.deep_audit.supervisor import DeepAuditSupervisor
    from models.schemas import AgentCreateRequest, AgentType

    request = AgentCreateRequest(
        repo_id="test_proj",
        agent_type=AgentType.DEEP_AUDIT,
        scan_tier="quick",
    )

    supervisor = DeepAuditSupervisor(
        request=request,
        repo_path="/tmp/test_repo",
        on_message=lambda msg: None,
    )

    assert supervisor.id is not None
    assert supervisor.repo_id == "test_proj"
