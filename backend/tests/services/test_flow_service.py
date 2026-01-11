"""Tests for flow service context tracking."""
from services.flow_service import FlowService, FlowContext, InvestigationFlow


def test_flow_context_initialization():
    """Test FlowContext initializes with None values."""
    context = FlowContext()
    assert context.current_file is None
    assert context.current_function is None
    assert context.current_candidate_node_id is None
    assert context.investigation_root_id is None


def test_investigation_flow_has_context():
    """Test InvestigationFlow includes FlowContext."""
    flow = InvestigationFlow(session_id="test-session")
    assert hasattr(flow, "context")
    assert isinstance(flow.context, FlowContext)
