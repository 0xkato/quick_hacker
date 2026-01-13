"""Tests for investigation trace data models"""
import pytest
from datetime import datetime
from models.investigation_trace import Span, SpanType, SpanState, SpanOutcome, FocusGap

def test_span_creation():
    """Span should be created with required fields"""
    span = Span(
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Investigate SQL injection",
        state=SpanState.OPEN
    )

    assert span.span_id == "span_123"
    assert span.span_type == SpanType.HYPOTHESIS
    assert span.hypothesis_id == "hyp_1"
    assert span.label == "Investigate SQL injection"
    assert span.state == SpanState.OPEN
    assert span.parent_span_id is None
    assert span.outcome is None
    assert span.event_ids == []
    assert span.artifact_ids == []

def test_span_with_parent():
    """Span should support parent_span_id for hierarchy"""
    parent = Span(
        span_id="span_parent",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_parent",
        label="Parent hypothesis",
        state=SpanState.OPEN
    )

    child = Span(
        span_id="span_child",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_child",
        label="Child hypothesis",
        state=SpanState.OPEN,
        parent_span_id=parent.span_id
    )

    assert child.parent_span_id == "span_parent"

def test_span_lifecycle():
    """Span should transition through states and track outcomes"""
    span = Span(
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN
    )

    # OPEN spans typically have None outcome
    assert span.state == SpanState.OPEN
    assert span.outcome is None

    # Complete the span with CONFIRMED outcome
    span.state = SpanState.COMPLETED
    span.outcome = SpanOutcome.CONFIRMED
    span.completed_at = datetime.utcnow()

    assert span.state == SpanState.COMPLETED
    assert span.outcome == SpanOutcome.CONFIRMED
    assert span.completed_at is not None

    # Test different outcomes work correctly
    span.outcome = SpanOutcome.REFUTED
    assert span.outcome == SpanOutcome.REFUTED

    span.outcome = SpanOutcome.INCONCLUSIVE
    assert span.outcome == SpanOutcome.INCONCLUSIVE

def test_span_serialization():
    """to_dict() should serialize all fields correctly"""
    # Test with all required fields and None optionals
    span = Span(
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test hypothesis",
        state=SpanState.OPEN
    )

    result = span.to_dict()

    # Verify required fields
    assert result["span_id"] == "span_123"
    assert result["hypothesis_id"] == "hyp_1"
    assert result["label"] == "Test hypothesis"

    # Verify enums serialize to strings (using .value)
    assert result["span_type"] == "hypothesis"
    assert isinstance(result["span_type"], str)
    assert result["state"] == "open"
    assert isinstance(result["state"], str)

    # Verify None enums serialize to None (not crash)
    assert result["outcome"] is None
    assert result["focus_gap"] is None

    # Verify None datetime serializes correctly
    assert result["completed_at"] is None

    # Verify empty lists
    assert result["event_ids"] == []
    assert result["artifact_ids"] == []

    # Verify all expected fields appear in output dict
    expected_fields = {
        "span_id", "span_type", "hypothesis_id", "label", "state",
        "parent_span_id", "outcome", "created_turn_id", "completed_at",
        "focus_gap", "focus_note", "stage", "event_ids", "artifact_ids", "metadata"
    }
    assert set(result.keys()) == expected_fields

def test_span_serialization_with_optional_fields():
    """to_dict() should serialize optional fields correctly"""
    completed_time = datetime(2026, 1, 13, 12, 30, 45)

    span = Span(
        span_id="span_456",
        span_type=SpanType.CRITIC_PASS,
        hypothesis_id="hyp_2",
        label="Review finding",
        state=SpanState.COMPLETED,
        parent_span_id="span_parent",
        outcome=SpanOutcome.CONFIRMED,
        created_turn_id=5,
        completed_at=completed_time,
        focus_gap=FocusGap.DATAFLOW_EVIDENCED,
        focus_note="Check data flow path",
        stage="triage",
        event_ids=["event_1", "event_2"],
        artifact_ids=["artifact_1"],
        metadata={"key": "value"}
    )

    result = span.to_dict()

    # Verify optional enum fields serialize to strings
    assert result["outcome"] == "confirmed"
    assert isinstance(result["outcome"], str)
    assert result["focus_gap"] == "dataflow_evidenced"
    assert isinstance(result["focus_gap"], str)

    # Verify DateTime serializes to ISO format
    assert result["completed_at"] == "2026-01-13T12:30:45"
    assert isinstance(result["completed_at"], str)

    # Verify other optional fields
    assert result["parent_span_id"] == "span_parent"
    assert result["created_turn_id"] == 5
    assert result["focus_note"] == "Check data flow path"
    assert result["stage"] == "triage"
    assert result["event_ids"] == ["event_1", "event_2"]
    assert result["artifact_ids"] == ["artifact_1"]
    assert result["metadata"] == {"key": "value"}

def test_span_enum_serialization():
    """Verify all enum types serialize correctly to their string values"""
    span = Span(
        span_id="span_789",
        span_type=SpanType.HYPOTHESIS_VISIT,
        hypothesis_id="hyp_3",
        label="Test enums",
        state=SpanState.DISCARDED,
        outcome=SpanOutcome.REFUTED,
        focus_gap=FocusGap.REACHABLE
    )

    result = span.to_dict()

    # Test SpanType enum serialization
    assert result["span_type"] == "hypothesis_visit"

    # Test SpanState enum serialization
    assert result["state"] == "discarded"

    # Test SpanOutcome enum serialization
    assert result["outcome"] == "refuted"

    # Test FocusGap enum serialization
    assert result["focus_gap"] == "reachable"

    # All should be strings, not enum objects
    assert all(isinstance(result[key], str) for key in ["span_type", "state", "outcome", "focus_gap"])
