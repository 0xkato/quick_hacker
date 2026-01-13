"""Tests for turn plan models."""

import pytest
from models.turn_plan import (
    Hypothesis,
    TurnPlan,
    HypothesisActivity,
    FocusGap,
)


def test_hypothesis_creation():
    """Test creating a Hypothesis with all fields."""
    hypothesis = Hypothesis(
        hypothesis_id="hyp_001",
        label="Test SQL injection in login endpoint",
        state="active",
        activity=HypothesisActivity.NEW,
        created_turn_id="turn_001",
        focus_gap=FocusGap.SINK_PRESENT,
        parent_hypothesis_id="hyp_000",
        focus_note="Examining user input sanitization logic",
        span_id="span_001",
        parent_span_id="span_000",
    )

    assert hypothesis.hypothesis_id == "hyp_001"
    assert hypothesis.label == "Test SQL injection in login endpoint"
    assert hypothesis.state == "active"
    assert hypothesis.activity == HypothesisActivity.NEW
    assert hypothesis.created_turn_id == "turn_001"
    assert hypothesis.focus_gap == FocusGap.SINK_PRESENT
    assert hypothesis.parent_hypothesis_id == "hyp_000"
    assert hypothesis.focus_note == "Examining user input sanitization logic"
    assert hypothesis.span_id == "span_001"
    assert hypothesis.parent_span_id == "span_000"
    assert len(hypothesis.focus_note) <= 120


def test_turn_plan_creation():
    """Test creating a TurnPlan with hypotheses list."""
    hypothesis1 = Hypothesis(
        hypothesis_id="hyp_001",
        label="Check authentication bypass",
        state="active",
        activity=HypothesisActivity.NEW,
        created_turn_id="turn_001",
        focus_gap=FocusGap.SECURITY_CONTROL_BYPASSED,
    )

    hypothesis2 = Hypothesis(
        hypothesis_id="hyp_002",
        label="Verify input validation",
        state="queued",
        activity=HypothesisActivity.QUEUED,
        created_turn_id="turn_001",
        focus_gap=FocusGap.DATAFLOW_EVIDENCED,
    )

    turn_plan = TurnPlan(
        turn_id="turn_001",
        goal="Investigate authentication vulnerabilities",
        hypotheses=[hypothesis1, hypothesis2],
        selected_hypothesis_id="hyp_001",
        selected_span_id="span_001",
        stage="exploration",
    )

    assert turn_plan.turn_id == "turn_001"
    assert turn_plan.goal == "Investigate authentication vulnerabilities"
    assert len(turn_plan.hypotheses) == 2
    assert turn_plan.selected_hypothesis_id == "hyp_001"
    assert turn_plan.selected_span_id == "span_001"
    assert turn_plan.stage == "exploration"

    # Test to_dict serialization
    plan_dict = turn_plan.to_dict()
    assert plan_dict["turn_id"] == "turn_001"
    assert plan_dict["goal"] == "Investigate authentication vulnerabilities"
    assert len(plan_dict["hypotheses"]) == 2
    assert plan_dict["hypotheses"][0]["hypothesis_id"] == "hyp_001"


def test_focus_note_max_length():
    """Test that focus_note is truncated to 120 characters."""
    long_note = "A" * 200  # Create a 200 character string

    hypothesis = Hypothesis(
        hypothesis_id="hyp_001",
        label="Test hypothesis",
        state="active",
        activity=HypothesisActivity.NEW,
        created_turn_id="turn_001",
        focus_gap=FocusGap.OTHER,
        focus_note=long_note,
    )

    assert len(hypothesis.focus_note) == 120
    assert hypothesis.focus_note == "A" * 120
