"""Tests for investigation trace data models"""
import pytest
from datetime import datetime
from models.investigation_trace import Span, SpanType, SpanState

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
    """Span should transition through states"""
    span = Span(
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test",
        state=SpanState.OPEN
    )

    # Complete the span
    span.state = SpanState.COMPLETED
    span.outcome = "confirmed"
    span.completed_at = datetime.utcnow()

    assert span.state == SpanState.COMPLETED
    assert span.outcome == "confirmed"
    assert span.completed_at is not None
