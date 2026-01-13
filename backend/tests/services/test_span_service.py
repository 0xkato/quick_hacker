"""Tests for SpanService"""
import pytest
from services.span_service import SpanService
from models.investigation_trace import Span, SpanType, SpanState

def test_span_service_create_span():
    """SpanService should create and store spans"""
    service = SpanService()

    span = service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test hypothesis",
        state=SpanState.OPEN
    )

    assert span.span_id == "span_123"
    assert span.hypothesis_id == "hyp_1"

    # Should be retrievable
    retrieved = service.get_span("agent_1", "span_123")
    assert retrieved is not None
    assert retrieved.span_id == "span_123"

def test_span_service_get_agent_spans():
    """SpanService should return all spans for an agent"""
    service = SpanService()

    service.create_span(
        agent_id="agent_1",
        span_id="span_1",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Hypothesis 1",
        state=SpanState.OPEN
    )

    service.create_span(
        agent_id="agent_1",
        span_id="span_2",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_2",
        label="Hypothesis 2",
        state=SpanState.OPEN
    )

    spans = service.get_agent_spans("agent_1")
    assert len(spans) == 2
    assert spans["span_1"].hypothesis_id == "hyp_1"
    assert spans["span_2"].hypothesis_id == "hyp_2"

def test_span_service_update_span():
    """SpanService should update existing spans"""
    service = SpanService()

    span = service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN
    )

    # Update state
    updated = service.update_span(
        agent_id="agent_1",
        span_id="span_123",
        state=SpanState.COMPLETED,
        outcome="confirmed"
    )

    assert updated.state == SpanState.COMPLETED
    assert updated.outcome == "confirmed"

def test_span_service_update_nonexistent_span():
    """SpanService should return None when updating nonexistent span"""
    service = SpanService()

    result = service.update_span(
        agent_id="agent_1",
        span_id="nonexistent",
        state=SpanState.COMPLETED
    )

    assert result is None

def test_span_service_attach_event():
    """SpanService should attach events to spans"""
    service = SpanService()

    span = service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN
    )

    # Attach event
    success = service.attach_event("agent_1", "span_123", "event_1")
    assert success is True

    # Verify event is attached
    retrieved = service.get_span("agent_1", "span_123")
    assert "event_1" in retrieved.event_ids

    # Attach duplicate event (should not duplicate)
    service.attach_event("agent_1", "span_123", "event_1")
    assert retrieved.event_ids.count("event_1") == 1

def test_span_service_attach_event_nonexistent_span():
    """SpanService should return False when attaching event to nonexistent span"""
    service = SpanService()

    success = service.attach_event("agent_1", "nonexistent", "event_1")
    assert success is False

def test_span_service_attach_artifact():
    """SpanService should attach artifacts to spans"""
    service = SpanService()

    span = service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN
    )

    # Attach artifact
    success = service.attach_artifact("agent_1", "span_123", "artifact_1")
    assert success is True

    # Verify artifact is attached
    retrieved = service.get_span("agent_1", "span_123")
    assert "artifact_1" in retrieved.artifact_ids

    # Attach duplicate artifact (should not duplicate)
    service.attach_artifact("agent_1", "span_123", "artifact_1")
    assert retrieved.artifact_ids.count("artifact_1") == 1

def test_span_service_attach_artifact_nonexistent_span():
    """SpanService should return False when attaching artifact to nonexistent span"""
    service = SpanService()

    success = service.attach_artifact("agent_1", "nonexistent", "artifact_1")
    assert success is False

def test_span_service_clear_agent_spans():
    """SpanService should clear all spans for an agent"""
    service = SpanService()

    # Create spans for agent_1
    service.create_span(
        agent_id="agent_1",
        span_id="span_1",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test 1",
        state=SpanState.OPEN
    )

    service.create_span(
        agent_id="agent_1",
        span_id="span_2",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_2",
        label="Test 2",
        state=SpanState.OPEN
    )

    # Create span for agent_2
    service.create_span(
        agent_id="agent_2",
        span_id="span_3",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_3",
        label="Test 3",
        state=SpanState.OPEN
    )

    # Clear agent_1 spans
    service.clear_agent_spans("agent_1")

    # Verify agent_1 has no spans
    assert len(service.get_agent_spans("agent_1")) == 0

    # Verify agent_2 still has spans
    assert len(service.get_agent_spans("agent_2")) == 1

def test_span_service_agent_isolation():
    """SpanService should isolate spans between agents"""
    service = SpanService()

    # Create spans for different agents with same span_id
    service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Agent 1",
        state=SpanState.OPEN
    )

    service.create_span(
        agent_id="agent_2",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_2",
        label="Agent 2",
        state=SpanState.OPEN
    )

    # Verify isolation
    span_1 = service.get_span("agent_1", "span_123")
    span_2 = service.get_span("agent_2", "span_123")

    assert span_1.label == "Agent 1"
    assert span_2.label == "Agent 2"
    assert span_1.hypothesis_id == "hyp_1"
    assert span_2.hypothesis_id == "hyp_2"

def test_span_service_focus_note_truncation():
    """SpanService should truncate focus_note to 120 chars"""
    service = SpanService()

    long_note = "x" * 200  # 200 chars

    span = service.create_span(
        agent_id="agent_1",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN,
        focus_note=long_note
    )

    # Should be truncated to 120 chars
    assert len(span.focus_note) == 120
    assert span.focus_note == "x" * 120
