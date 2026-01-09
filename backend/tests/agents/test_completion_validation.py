import pytest
from services.coverage_tracker import CoverageTracker, PathStatus
from agents.depth_enforcement import (
    DepthEnforcementConfig,
    validate_completion_request,
    CompletionValidationResult
)

def test_completion_rejected_when_no_files_examined():
    """Completion should be rejected if no files were examined."""
    tracker = CoverageTracker("test-agent")
    config = DepthEnforcementConfig()

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined=set(),  # Empty
        iteration_count=5,
        pending_investigations=0
    )

    assert not result.can_complete
    assert "files" in result.rejection_reason.lower()

def test_completion_rejected_when_insufficient_iterations():
    """Completion should be rejected if not enough iterations."""
    tracker = CoverageTracker("test-agent")
    config = DepthEnforcementConfig(min_iterations=10)

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=3,  # Less than 10
        pending_investigations=0
    )

    assert not result.can_complete
    assert "iteration" in result.rejection_reason.lower()

def test_completion_rejected_when_pending_investigations():
    """Completion should be rejected if investigation queue not empty."""
    tracker = CoverageTracker("test-agent")
    config = DepthEnforcementConfig()

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=15,
        pending_investigations=5  # Still pending
    )

    assert not result.can_complete
    assert "pending" in result.rejection_reason.lower() or "queue" in result.rejection_reason.lower()

def test_completion_rejected_when_low_coverage():
    """Completion should be rejected if coverage below threshold."""
    tracker = CoverageTracker("test-agent")
    # Register paths but don't trace them
    tracker.register_path("a.py", 10, "handler", "b.py", 20, "sql", "execute")
    tracker.register_path("a.py", 30, "handler2", "c.py", 40, "cmd", "system")

    config = DepthEnforcementConfig(min_coverage_percent=80.0)

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=15,
        pending_investigations=0
    )

    assert not result.can_complete
    assert "coverage" in result.rejection_reason.lower()

def test_completion_allowed_when_all_requirements_met():
    """Completion should be allowed when all requirements are met."""
    tracker = CoverageTracker("test-agent")
    # Register and trace paths
    path_id = tracker.register_path("a.py", 10, "handler", "b.py", 20, "sql", "execute")
    tracker.update_status(path_id, PathStatus.TRACED_SAFE, "No injection possible")

    config = DepthEnforcementConfig(min_coverage_percent=80.0)

    result = validate_completion_request(
        coverage_tracker=tracker,
        config=config,
        files_examined={"a.py", "b.py", "c.py", "d.py", "e.py"},
        iteration_count=15,
        pending_investigations=0
    )

    assert result.can_complete
    assert result.rejection_reason is None
