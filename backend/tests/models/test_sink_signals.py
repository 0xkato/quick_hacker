import pytest
from models.sink_signals import CandidateStatus

def test_candidate_status_enum_values():
    """Test CandidateStatus enum has all required values."""
    assert CandidateStatus.PENDING == "pending"
    assert CandidateStatus.VALIDATED_VULNERABILITY == "validated_vulnerability"
    assert CandidateStatus.NEEDS_HUMAN_REVIEW == "needs_human_review"
    assert CandidateStatus.HARDENING_OPPORTUNITY == "hardening_opportunity"
    assert CandidateStatus.NOT_A_VULNERABILITY == "not_a_vulnerability"
    assert CandidateStatus.DUPLICATE == "duplicate"

def test_candidate_status_is_str_enum():
    """Test CandidateStatus values are strings."""
    assert isinstance(CandidateStatus.PENDING.value, str)
