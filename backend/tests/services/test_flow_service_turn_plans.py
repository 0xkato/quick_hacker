"""Tests for FlowService turn plan emission."""
import pytest

from services.flow_service import flow_service
from models.turn_plan import TurnPlan, Hypothesis, HypothesisActivity, FocusGap


@pytest.fixture(autouse=True)
def cleanup_flow_service():
    """Clear flow service state before and after each test."""
    flow_service._flows.clear()
    flow_service._subscribers.clear()
    yield
    flow_service._flows.clear()
    flow_service._subscribers.clear()


def test_emit_turn_plan():
    """Test that turn_plan events are emitted with correct data structure."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    # Create a sample turn plan with hypotheses
    hypotheses = [
        Hypothesis(
            hypothesis_id="hyp-1",
            label="SQL injection in user input",
            state="active",
            activity=HypothesisActivity.NEW,
            created_turn_id="turn-1",
            focus_gap=FocusGap.SOURCE_CONTROLLED_INPUT,
            focus_note="Checking if user input is sanitized",
            span_id="span-1",
            parent_span_id=None,
        ),
        Hypothesis(
            hypothesis_id="hyp-2",
            label="XSS in template rendering",
            state="queued",
            activity=HypothesisActivity.QUEUED,
            created_turn_id="turn-1",
            focus_gap=FocusGap.SINK_PRESENT,
            focus_note="Checking output encoding",
            span_id="span-2",
            parent_span_id=None,
        ),
    ]

    turn_plan = TurnPlan(
        turn_id="turn-1",
        goal="Investigate SQL injection vulnerability in login endpoint",
        hypotheses=hypotheses,
        selected_hypothesis_id="hyp-1",
        selected_span_id="span-1",
        stage="exploration",
    )

    # Emit turn plan
    node = flow_service.emit_turn_plan(agent_id, turn_plan)

    # Verify node structure
    assert node is not None
    assert node.type == "turn_plan"
    assert node.label == "Turn turn-1: Investigate SQL injection vulnerability ..."
    assert node.status == "completed"

    # Verify span tracking fields
    assert node.span_id == "span-1"
    assert node.hypothesis_id == "hyp-1"
    assert node.turn_id == "turn-1"

    # Verify data contains all turn plan information
    assert node.data["turn_id"] == "turn-1"
    assert node.data["stage"] == "exploration"
    assert node.data["goal"] == "Investigate SQL injection vulnerability in login endpoint"
    assert node.data["selected_hypothesis_id"] == "hyp-1"
    assert node.data["selected_span_id"] == "span-1"

    # Verify hypotheses are serialized correctly
    assert len(node.data["hypotheses"]) == 2
    hyp1_data = node.data["hypotheses"][0]
    assert hyp1_data["hypothesis_id"] == "hyp-1"
    assert hyp1_data["label"] == "SQL injection in user input"
    assert hyp1_data["state"] == "active"
    assert hyp1_data["activity"] == "new"  # Enum should be serialized to string
    assert hyp1_data["focus_gap"] == "source_controlled_input"  # Enum should be serialized to string
    assert hyp1_data["focus_note"] == "Checking if user input is sanitized"
    assert hyp1_data["span_id"] == "span-1"


def test_turn_plan_updates_context():
    """Test that flow context is updated with selected_span_id."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    # Create a simple turn plan
    turn_plan = TurnPlan(
        turn_id="turn-2",
        goal="Validate authentication bypass hypothesis",
        hypotheses=[
            Hypothesis(
                hypothesis_id="hyp-3",
                label="Auth bypass via header manipulation",
                state="active",
                activity=HypothesisActivity.CONTINUING,
                created_turn_id="turn-1",
                focus_gap=FocusGap.SECURITY_CONTROL_BYPASSED,
                span_id="span-3",
                parent_span_id="span-0",
            )
        ],
        selected_hypothesis_id="hyp-3",
        selected_span_id="span-3",
        stage="validation",
    )

    # Emit turn plan
    flow_service.emit_turn_plan(agent_id, turn_plan)

    # Verify context is updated
    flow = flow_service.get_flow(agent_id)
    assert flow.context.current_candidate_node_id == "span-3"
