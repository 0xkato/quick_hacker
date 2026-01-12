import pytest
from pathlib import Path
from services.tool_core import ToolCore
from models.sink_signals import CandidateStatus


@pytest.fixture
def tool_core(tmp_path):
    """Create a ToolCore instance for testing."""
    return ToolCore(
        repo_path=str(tmp_path),
        project_id="test-project"
    )


def test_finalize_finding_requires_all_answers(tool_core):
    """Test that all 6 disprove questions must be answered."""
    result = tool_core.finalize_finding(
        signal_id="sig-1",
        classification=CandidateStatus.VALIDATED_VULNERABILITY,
        disprove_answers={
            "q1": "yes",
            "q2": "yes",
            "q3": "yes",
            "q4": "no",
            "q5": "yes"
            # Missing q6
        },
        reasoning="Test reasoning"
    )

    assert result["success"] is False
    assert "6 questions" in result["error"].lower()


def test_finalize_finding_validated_vulnerability_success(tool_core):
    """Test successful finalization of VALIDATED_VULNERABILITY."""
    result = tool_core.finalize_finding(
        signal_id="sig-1",
        classification=CandidateStatus.VALIDATED_VULNERABILITY,
        disprove_answers={
            "q1": "yes",
            "q2": "yes",
            "q3": "yes",
            "q4": "no",
            "q5": "yes",
            "q6": "yes"
        },
        reasoning="Complete source→sink dataflow traced with evidence"
    )

    assert result["success"] is True
    assert result["classification"] == CandidateStatus.VALIDATED_VULNERABILITY
    assert "disprove_answers" in result
    assert "reasoning" in result


def test_finalize_finding_downgrade_classification(tool_core):
    """Test finalizing with a downgrade classification."""
    result = tool_core.finalize_finding(
        signal_id="sig-1",
        classification=CandidateStatus.NEEDS_HUMAN_REVIEW,
        disprove_answers={
            "q1": "yes",
            "q2": "yes",
            "q3": "yes",
            "q4": "no",
            "q5": "yes",
            "q6": "no"  # Safer interpretation exists
        },
        reasoning="Cannot determine framework behavior statically"
    )

    assert result["success"] is True
    assert result["classification"] == CandidateStatus.NEEDS_HUMAN_REVIEW


def test_finalize_finding_invalid_classification(tool_core):
    """Test error when using invalid classification."""
    result = tool_core.finalize_finding(
        signal_id="sig-1",
        classification="invalid_status",
        disprove_answers={
            "q1": "yes",
            "q2": "yes",
            "q3": "yes",
            "q4": "no",
            "q5": "yes",
            "q6": "yes"
        },
        reasoning="Test"
    )

    assert result["success"] is False
    assert "invalid" in result["error"].lower()


def test_finalize_finding_pending_not_allowed(tool_core):
    """Test that PENDING classification is not allowed for finalization."""
    result = tool_core.finalize_finding(
        signal_id="sig-1",
        classification=CandidateStatus.PENDING,
        disprove_answers={
            "q1": "yes",
            "q2": "yes",
            "q3": "yes",
            "q4": "no",
            "q5": "yes",
            "q6": "yes"
        },
        reasoning="Test"
    )

    assert result["success"] is False
    assert "pending" in result["error"].lower()


def test_finalize_finding_empty_answer_rejected(tool_core):
    """Test that empty answer values are rejected."""
    result = tool_core.finalize_finding(
        signal_id="sig-1",
        classification=CandidateStatus.VALIDATED_VULNERABILITY,
        disprove_answers={
            "q1": "",  # Empty string should be rejected
            "q2": "yes",
            "q3": "yes",
            "q4": "no",
            "q5": "yes",
            "q6": "yes"
        },
        reasoning="Valid reasoning"
    )

    assert result["success"] is False
    assert "non-empty" in result["error"].lower()
    assert "q1" in result["error"]


def test_finalize_finding_whitespace_answer_rejected(tool_core):
    """Test that whitespace-only answer values are rejected."""
    result = tool_core.finalize_finding(
        signal_id="sig-1",
        classification=CandidateStatus.VALIDATED_VULNERABILITY,
        disprove_answers={
            "q1": "yes",
            "q2": "yes",
            "q3": "   ",  # Whitespace-only should be rejected
            "q4": "no",
            "q5": "yes",
            "q6": "yes"
        },
        reasoning="Valid reasoning"
    )

    assert result["success"] is False
    assert "non-empty" in result["error"].lower()
    assert "q3" in result["error"]
