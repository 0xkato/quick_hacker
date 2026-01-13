"""Tests for investigation trace data models"""
import pytest
from datetime import datetime, timezone
from models.investigation_trace import Span, SpanType, SpanState, SpanOutcome, FocusGap
from models.investigation_trace import Artifact, ArtifactType
from models.investigation_trace import (
    TurnPlan, HypothesisInfo, HypothesisActivity, HypothesisState
)

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
    span.completed_at = datetime.now(timezone.utc)

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

def test_span_focus_note_validation():
    """Span should enforce focus_note max length of 120 chars"""
    valid_note = "A" * 120  # Exactly 120 chars - should work

    span = Span(
        span_id="span_test",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN,
        focus_note=valid_note
    )
    assert span.focus_note == valid_note

    # Test that >120 chars raises ValueError
    invalid_note = "A" * 121  # 121 chars - should fail
    with pytest.raises(ValueError, match="focus_note must be ≤120 chars"):
        Span(
            span_id="span_test2",
            span_type=SpanType.HYPOTHESIS,
            hypothesis_id="hyp_1",
            label="Test",
            state=SpanState.OPEN,
            focus_note=invalid_note
        )

def test_artifact_creation():
    """Artifact should be created with content hash ID"""
    artifact = Artifact(
        artifact_id="sha256_abc123",
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="def vulnerable_function():\n    pass",
        summary="File snippet from auth.py:45-50"
    )

    assert artifact.artifact_id == "sha256_abc123"
    assert artifact.artifact_type == ArtifactType.FILE_SNIPPET
    assert artifact.content == "def vulnerable_function():\n    pass"
    assert artifact.summary == "File snippet from auth.py:45-50"

def test_artifact_with_references():
    """Artifact should support file references"""
    artifact = Artifact(
        artifact_id="sha256_abc123",
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="code here",
        summary="File snippet",
        file_path="app/auth.py",
        line_start=45,
        line_end=50
    )

    assert artifact.file_path == "app/auth.py"
    assert artifact.line_start == 45
    assert artifact.line_end == 50

def test_artifact_content_hash_generation():
    """Artifact ID should be deterministic content hash"""
    from models.investigation_trace import generate_artifact_id

    content = "def test(): pass"
    id1 = generate_artifact_id(content)
    id2 = generate_artifact_id(content)

    assert id1 == id2
    assert id1.startswith("art_")
    assert len(id1) == 20  # "art_" + 16 hex chars

def test_artifact_summary_validation():
    """Artifact should enforce summary max length of 200 chars"""
    valid_summary = "A" * 200  # Exactly 200 chars - should work

    artifact = Artifact(
        artifact_id="art_test",
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="test",
        summary=valid_summary
    )
    assert artifact.summary == valid_summary

    # Test that >200 chars raises ValueError
    invalid_summary = "A" * 201  # 201 chars - should fail
    with pytest.raises(ValueError, match="summary must be ≤200 chars"):
        Artifact(
            artifact_id="art_test2",
            artifact_type=ArtifactType.FILE_SNIPPET,
            content="test",
            summary=invalid_summary
        )

def test_artifact_dict_content_hashing():
    """Artifact ID generation should handle dict content and be order-independent"""
    from models.investigation_trace import generate_artifact_id

    # Test dict content
    dict_content_1 = {"key1": "value1", "key2": "value2"}
    dict_content_2 = {"key2": "value2", "key1": "value1"}  # Different order

    id1 = generate_artifact_id(dict_content_1)
    id2 = generate_artifact_id(dict_content_2)

    # Should generate same ID regardless of dict key order
    assert id1 == id2
    assert id1.startswith("art_")
    assert len(id1) == 20

def test_artifact_serialization():
    """Artifact should serialize to dict correctly"""
    artifact = Artifact(
        artifact_id="art_abc123",
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="code here",
        summary="Test artifact",
        file_path="app/auth.py",
        line_start=45,
        line_end=50,
        created_at=datetime(2026, 1, 13, 12, 30, 45, tzinfo=timezone.utc),
        size_bytes=100
    )

    artifact.producer_spans.add("span_1")
    artifact.consumer_spans.add("span_2")

    result = artifact.to_dict()

    # Verify all fields present
    assert result["artifact_id"] == "art_abc123"
    assert result["artifact_type"] == "file_snippet"  # Enum serialized to string
    assert result["content"] == "code here"
    assert result["summary"] == "Test artifact"
    assert result["file_path"] == "app/auth.py"
    assert result["line_start"] == 45
    assert result["line_end"] == 50
    assert result["producer_spans"] == ["span_1"]  # Set converted to list
    assert result["consumer_spans"] == ["span_2"]  # Set converted to list
    assert result["created_at"] == "2026-01-13T12:30:45+00:00"  # ISO format
    assert result["size_bytes"] == 100

    # Verify types
    assert isinstance(result["artifact_type"], str)
    assert isinstance(result["producer_spans"], list)
    assert isinstance(result["consumer_spans"], list)

def test_artifact_serialization_with_defaults():
    """Artifact should serialize correctly with None/default values"""
    artifact = Artifact(
        artifact_id="art_def",
        artifact_type=ArtifactType.TOOL_OUTPUT,
        content="output",
        summary="Default values test"
    )

    result = artifact.to_dict()

    assert result["file_path"] is None
    assert result["line_start"] is None
    assert result["line_end"] is None
    assert result["producer_spans"] == []  # Empty set -> empty list
    assert result["consumer_spans"] == []
    assert result["created_at"] is None
    assert result["size_bytes"] == 0

def test_turn_plan_creation():
    """TurnPlan should structure investigation preview"""
    hypothesis = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Check SQL injection",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.DATAFLOW_EVIDENCED,
        focus_note="Need to trace user input to query"
    )

    plan = TurnPlan(
        goal="Investigate /login route",
        hypotheses=[hypothesis],
        selected_hypothesis_id="hyp_1",
        selected_span_id="span_hyp_1"
    )

    assert plan.goal == "Investigate /login route"
    assert len(plan.hypotheses) == 1
    assert plan.hypotheses[0].hypothesis_id == "hyp_1"
    assert plan.selected_hypothesis_id == "hyp_1"
    assert plan.selected_span_id == "span_hyp_1"

def test_hypothesis_activity_states():
    """HypothesisActivity should cover all workflow states"""
    # New hypothesis being created
    hyp_new = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Test",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    # Continuing existing hypothesis
    hyp_continuing = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Test",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.CONTINUING,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    # Revisiting after gap
    hyp_revisiting = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Test",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.REVISITING,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    # Queued for future
    hyp_queued = HypothesisInfo(
        hypothesis_id="hyp_2",
        label="Future work",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.QUEUED,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER
    )

    assert hyp_new.activity == HypothesisActivity.NEW
    assert hyp_continuing.activity == HypothesisActivity.CONTINUING
    assert hyp_revisiting.activity == HypothesisActivity.REVISITING
    assert hyp_queued.activity == HypothesisActivity.QUEUED

def test_hypothesis_info_focus_note_validation():
    """HypothesisInfo should enforce focus_note max length of 120 chars"""
    valid_note = "A" * 120  # Exactly 120 chars - should work

    hypothesis = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Test",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.OTHER,
        focus_note=valid_note
    )
    assert hypothesis.focus_note == valid_note

    # Test that >120 chars raises ValueError
    invalid_note = "A" * 121  # 121 chars - should fail
    with pytest.raises(ValueError, match="focus_note must be ≤120 chars"):
        HypothesisInfo(
            hypothesis_id="hyp_1",
            label="Test",
            state=HypothesisState.OPEN,
            activity=HypothesisActivity.NEW,
            created_turn_id=1,
            focus_gap=FocusGap.OTHER,
            focus_note=invalid_note
        )

def test_hypothesis_info_serialization():
    """HypothesisInfo should serialize to dict correctly"""
    hypothesis = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Check SQL injection",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.DATAFLOW_EVIDENCED,
        parent_hypothesis_id="hyp_parent",
        focus_note="Test note",
        span_id="span_1",
        parent_span_id="span_parent"
    )

    result = hypothesis.to_dict()

    assert result["hypothesis_id"] == "hyp_1"
    assert result["label"] == "Check SQL injection"
    assert result["state"] == "open"  # Enum serialized to string
    assert result["activity"] == "new"  # Enum serialized to string
    assert result["created_turn_id"] == 1
    assert result["focus_gap"] == "dataflow_evidenced"  # Enum serialized to string
    assert result["parent_hypothesis_id"] == "hyp_parent"
    assert result["focus_note"] == "Test note"
    assert result["span_id"] == "span_1"
    assert result["parent_span_id"] == "span_parent"

    # Verify enums are strings
    assert isinstance(result["state"], str)
    assert isinstance(result["activity"], str)
    assert isinstance(result["focus_gap"], str)

def test_turn_plan_serialization():
    """TurnPlan should serialize to dict correctly"""
    hypothesis1 = HypothesisInfo(
        hypothesis_id="hyp_1",
        label="Check SQL injection",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.NEW,
        created_turn_id=1,
        focus_gap=FocusGap.DATAFLOW_EVIDENCED
    )

    hypothesis2 = HypothesisInfo(
        hypothesis_id="hyp_2",
        label="Check XSS",
        state=HypothesisState.OPEN,
        activity=HypothesisActivity.QUEUED,
        created_turn_id=1,
        focus_gap=FocusGap.SINK_PRESENT
    )

    plan = TurnPlan(
        goal="Investigate /login route",
        hypotheses=[hypothesis1, hypothesis2],
        selected_hypothesis_id="hyp_1",
        selected_span_id="span_hyp_1"
    )

    result = plan.to_dict()

    assert result["goal"] == "Investigate /login route"
    assert result["selected_hypothesis_id"] == "hyp_1"
    assert result["selected_span_id"] == "span_hyp_1"
    assert len(result["hypotheses"]) == 2

    # Verify hypotheses are serialized correctly
    assert result["hypotheses"][0]["hypothesis_id"] == "hyp_1"
    assert result["hypotheses"][0]["state"] == "open"
    assert result["hypotheses"][0]["activity"] == "new"
    assert result["hypotheses"][1]["hypothesis_id"] == "hyp_2"
    assert result["hypotheses"][1]["state"] == "open"
    assert result["hypotheses"][1]["activity"] == "queued"
