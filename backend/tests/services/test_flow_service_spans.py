"""Tests for span-enhanced FlowNode"""
import pytest
from services.flow_service import FlowNode

def test_flow_node_with_span_fields():
    """FlowNode should accept span tracking fields"""
    node = FlowNode(
        id="evt_123",
        type="tool_call",
        label="Read file",
        span_id="span_abc",
        parent_span_id="span_parent",
        hypothesis_id="hyp_1",
        turn_id=5,
        correlation_id="corr_5",
        input_artifact_ids=["art_1"],
        output_artifact_ids=["art_2"],
        tool_invocation_id="tool_inv_1"
    )

    assert node.span_id == "span_abc"
    assert node.parent_span_id == "span_parent"
    assert node.hypothesis_id == "hyp_1"
    assert node.turn_id == 5
    assert node.correlation_id == "corr_5"
    assert node.input_artifact_ids == ["art_1"]
    assert node.output_artifact_ids == ["art_2"]
    assert node.tool_invocation_id == "tool_inv_1"

def test_flow_node_span_fields_optional():
    """Span fields should be optional for backward compatibility"""
    node = FlowNode(
        id="evt_123",
        type="tool_call",
        label="Read file"
    )

    assert node.span_id is None
    assert node.parent_span_id is None
    assert node.hypothesis_id is None
    assert node.turn_id == 0  # default
    assert node.correlation_id is None
    assert node.input_artifact_ids == []
    assert node.output_artifact_ids == []
    assert node.tool_invocation_id is None
