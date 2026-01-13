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


def test_event_routing_priority_explicit_span_id():
    """ReconstructionService should prioritize explicit span_id over current_selected_span"""
    service = ReconstructionService()
    agent_exec_id = "exec-test-3"

    # Create a turn_plan with selected span
    turn_plan_event = {
        "id": "event-tp-1",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:00:00Z",
        "data": {
            "turn_id": 1,
            "goal": "Test routing",
            "stage": "exploration",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp-1",
                    "label": "First hypothesis",
                    "state": "active",
                    "activity": "new",
                    "parent_hypothesis_id": None,
                },
                {
                    "hypothesis_id": "hyp-2",
                    "label": "Second hypothesis",
                    "state": "active",
                    "activity": "new",
                    "parent_hypothesis_id": None,
                }
            ],
            "selected_hypothesis_id": "hyp-1",
            "selected_span_id": "exec-test-3__hyp__hyp-1",
        }
    }

    # Create an event with explicit span_id (should override selected span)
    tool_event = {
        "id": "event-tool-1",
        "type": "tool_use",
        "timestamp": "2026-01-13T10:01:00Z",
        "span_id": "exec-test-3__hyp__hyp-2",  # Explicit span_id (hyp-2)
        "data": {"tool": "grep", "result": "found"}
    }

    events = [turn_plan_event, tool_event]
    artifacts = {}

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=events,
        artifacts=artifacts,
        agent_exec_id=agent_exec_id
    )

    # tool_event should be attached to hyp-2 (explicit span_id), NOT hyp-1 (selected)
    hyp2_span_id = "exec-test-3__hyp__hyp-2"
    assert event_to_span["event-tool-1"] == hyp2_span_id
    assert "event-tool-1" in spans[hyp2_span_id].event_ids


def test_event_with_missing_id_skipped():
    """ReconstructionService should skip events with missing event.id gracefully"""
    service = ReconstructionService()
    agent_exec_id = "exec-test-4"

    # Create events, one with missing id
    event_with_id = {
        "id": "event-1",
        "type": "tool_use",
        "timestamp": "2026-01-13T10:00:00Z",
        "data": {"tool": "grep"}
    }

    event_without_id = {
        # Missing "id" field
        "type": "tool_use",
        "timestamp": "2026-01-13T10:01:00Z",
        "data": {"tool": "read"}
    }

    events = [event_with_id, event_without_id]
    artifacts = {}

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=events,
        artifacts=artifacts,
        agent_exec_id=agent_exec_id
    )

    # event_with_id should be in event_to_span
    assert "event-1" in event_to_span

    # event_without_id should NOT be in event_to_span (skipped)
    # There should only be 1 event in the mapping
    assert len(event_to_span) == 1

    # Verify event-1 was attached to unattributed span
    unattributed_span_id = f"{agent_exec_id}__unattributed"
    assert event_to_span["event-1"] == unattributed_span_id
    assert "event-1" in spans[unattributed_span_id].event_ids


def test_duplicate_hypothesis_spans_handled():
    """ReconstructionService should handle duplicate hypothesis spans without overwriting"""
    service = ReconstructionService()
    agent_exec_id = "exec-test-5"

    # Create two turn_plan events with the same hypothesis_id
    turn_plan_1 = {
        "id": "event-tp-1",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:00:00Z",
        "data": {
            "turn_id": 1,
            "goal": "First plan",
            "stage": "exploration",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp-1",
                    "label": "First occurrence",
                    "state": "active",
                    "activity": "new",
                    "parent_hypothesis_id": None,
                }
            ],
            "selected_hypothesis_id": "hyp-1",
            "selected_span_id": "exec-test-5__hyp__hyp-1",
        }
    }

    turn_plan_2 = {
        "id": "event-tp-2",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:01:00Z",
        "data": {
            "turn_id": 2,
            "goal": "Second plan",
            "stage": "exploration",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp-1",  # Same hypothesis_id
                    "label": "Second occurrence (should be skipped)",
                    "state": "active",
                    "activity": "continued",
                    "parent_hypothesis_id": None,
                }
            ],
            "selected_hypothesis_id": "hyp-1",
            "selected_span_id": "exec-test-5__hyp__hyp-1",
        }
    }

    events = [turn_plan_1, turn_plan_2]
    artifacts = {}

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=events,
        artifacts=artifacts,
        agent_exec_id=agent_exec_id
    )

    # Should have 2 spans: unattributed + hyp-1 (not duplicated)
    assert len(spans) == 2

    hyp1_span_id = "exec-test-5__hyp__hyp-1"
    assert hyp1_span_id in spans

    # First label should be preserved (not overwritten)
    assert spans[hyp1_span_id].label == "First occurrence"

    # Both turn_plan events should be attached to hyp-1 span
    assert "event-tp-1" in spans[hyp1_span_id].event_ids
    assert "event-tp-2" in spans[hyp1_span_id].event_ids


def test_edge_building_validates_parent_exists():
    """ReconstructionService should skip edges when parent span doesn't exist"""
    service = ReconstructionService()
    agent_exec_id = "exec-test-6"

    # First, create a parent hypothesis then a child that references it
    turn_plan_1 = {
        "id": "event-tp-1",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:00:00Z",
        "data": {
            "turn_id": 1,
            "goal": "Create parent",
            "stage": "exploration",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp-parent",
                    "label": "Parent hypothesis",
                    "state": "active",
                    "activity": "new",
                    "parent_hypothesis_id": None,
                }
            ],
            "selected_hypothesis_id": "hyp-parent",
            "selected_span_id": "exec-test-6__hyp__hyp-parent",
        }
    }

    # Create child with valid parent reference
    turn_plan_2 = {
        "id": "event-tp-2",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:01:00Z",
        "data": {
            "turn_id": 2,
            "goal": "Create child",
            "stage": "exploration",
            "hypotheses": [
                {
                    "hypothesis_id": "hyp-child",
                    "label": "Child hypothesis",
                    "state": "active",
                    "activity": "new",
                    "parent_hypothesis_id": "hyp-parent",
                }
            ],
            "selected_hypothesis_id": "hyp-child",
            "selected_span_id": "exec-test-6__hyp__hyp-child",
        }
    }

    # Manually create spans with a parent_span_id that points to a nonexistent span
    # to test the edge building validation
    service_instance = ReconstructionService()

    # Mock spans with a child pointing to nonexistent parent
    from models.investigation_trace import Span, SpanType, SpanState
    mock_spans = {
        "unattributed": Span(
            span_id="unattributed",
            span_type=SpanType.PLACEHOLDER,
            hypothesis_id="unattributed",
            label="Unattributed",
            state=SpanState.OPEN,
            parent_span_id=None,
        ),
        "child": Span(
            span_id="child",
            span_type=SpanType.HYPOTHESIS,
            hypothesis_id="hyp-child",
            label="Child",
            state=SpanState.OPEN,
            parent_span_id="nonexistent-parent",  # Parent doesn't exist in spans dict
        ),
    }

    # Call _build_edges directly
    edges = service_instance._build_edges(mock_spans)

    # Should have NO edges (parent doesn't exist in spans dict)
    assert len(edges) == 0


def test_turn_plan_with_invalid_data_structure():
    """ReconstructionService should skip turn_plan events with invalid data structures"""
    service = ReconstructionService()
    agent_exec_id = "exec-test-7"

    # Create turn_plan with invalid data (not a dict)
    invalid_turn_plan_1 = {
        "id": "event-tp-1",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:00:00Z",
        "data": "invalid_string"  # Should be dict
    }

    # Create turn_plan with invalid hypotheses (not a list)
    invalid_turn_plan_2 = {
        "id": "event-tp-2",
        "type": "turn_plan",
        "timestamp": "2026-01-13T10:01:00Z",
        "data": {
            "turn_id": 1,
            "hypotheses": "invalid_string"  # Should be list
        }
    }

    # Create a valid event for comparison
    valid_event = {
        "id": "event-1",
        "type": "tool_use",
        "timestamp": "2026-01-13T10:02:00Z",
        "data": {"tool": "grep"}
    }

    events = [invalid_turn_plan_1, invalid_turn_plan_2, valid_event]
    artifacts = {}

    spans, edges, event_to_span = service.reconstruct_investigation_dag(
        events=events,
        artifacts=artifacts,
        agent_exec_id=agent_exec_id
    )

    # Should only have 1 span (unattributed), no hypothesis spans created
    assert len(spans) == 1

    # Invalid turn_plan events should NOT be in event_to_span
    assert "event-tp-1" not in event_to_span
    assert "event-tp-2" not in event_to_span

    # Valid event should be in event_to_span
    assert "event-1" in event_to_span
