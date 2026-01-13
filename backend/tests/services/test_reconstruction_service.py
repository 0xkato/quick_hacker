"""Tests for ReconstructionService"""
import pytest
from datetime import datetime

from services.reconstruction_service import ReconstructionService
from models.investigation_trace import (
    Span,
    SpanType,
    SpanState,
    HypothesisInfo,
    HypothesisState,
    HypothesisActivity,
    FocusGap,
    Artifact,
    ArtifactType,
)


def test_reconstruct_empty_events():
    """ReconstructionService should return only unattributed span for empty events"""
    service = ReconstructionService()
    agent_exec_id = "exec-test-1"

    # Empty events list
    events = []
    artifacts = {}

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=events,
        artifacts=artifacts,
        agent_exec_id=agent_exec_id
    )

    # Should have exactly 1 span (unattributed)
    assert len(spans) == 1

    # Verify unattributed span exists
    unattributed_span_id = f"{agent_exec_id}__unattributed"
    assert unattributed_span_id in spans

    unattributed_span = spans[unattributed_span_id]
    assert unattributed_span.span_type == SpanType.PLACEHOLDER
    assert unattributed_span.label == "Unattributed Events"
    assert unattributed_span.state == SpanState.OPEN
    assert unattributed_span.parent_span_id is None

    # Should have no edges
    assert len(edges) == 0

    # Should have empty event_to_span mapping
    assert len(event_to_span) == 0


def test_reconstruct_turn_plan_creates_span():
    """ReconstructionService should create hypothesis span from turn_plan event"""
    service = ReconstructionService()
    agent_exec_id = "exec-test-2"

    # Create a turn_plan event with one hypothesis
    turn_plan_event = {
        "id": "event-tp-1",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:00:00Z",
        "data": {
            "turn_id": 1,
            "goal": "Investigate SQL injection in login endpoint",
            "stage": "exploration",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp-1",
                    "label": "SQL injection in user input",
                    "state": "active",
                    "activity": "new",
                    "created_turn_id": 1,
                    "focus_gap": "source_controlled_input",
                    "focus_note": "Checking if user input is sanitized",
                    "parent_hypothesis_id": None,
                }
            ],
            "selected_hypothesis_id": "hyp-1",
            "selected_span_id": "exec-test-2__hyp__hyp-1",
        }
    }

    events = [turn_plan_event]
    artifacts = {}

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=events,
        artifacts=artifacts,
        agent_exec_id=agent_exec_id
    )

    # Should have 2 spans: unattributed + hypothesis
    assert len(spans) == 2

    # Verify hypothesis span exists
    hypothesis_span_id = "exec-test-2__hyp__hyp-1"
    assert hypothesis_span_id in spans

    hypothesis_span = spans[hypothesis_span_id]
    assert hypothesis_span.span_type == SpanType.HYPOTHESIS
    assert hypothesis_span.hypothesis_id == "hyp-1"
    assert hypothesis_span.label == "SQL injection in user input"
    assert hypothesis_span.state == SpanState.OPEN
    assert hypothesis_span.focus_gap == FocusGap.SOURCE_CONTROLLED_INPUT
    assert hypothesis_span.focus_note == "Checking if user input is sanitized"
    assert hypothesis_span.stage == "exploration"
    assert hypothesis_span.created_turn_id == 1

    # turn_plan event should be attached to hypothesis span
    assert "event-tp-1" in hypothesis_span.event_ids

    # Verify event_to_span mapping
    assert event_to_span["event-tp-1"] == hypothesis_span_id

    # Should have no edges (no parent)
    assert len(edges) == 0
