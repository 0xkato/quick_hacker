"""Tests for flow service context tracking."""
from services.flow_service import FlowService, FlowContext, InvestigationFlow, flow_service


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


def test_create_file_node():
    """Test creating a file node."""
    flow_service.initialize_flow("test-agent")
    node = flow_service.add_node(
        "test-agent",
        "file",
        "routes.py",
        {"file_path": "/app/routes.py"}
    )
    assert node.type == "file"
    assert node.label == "routes.py"


def test_create_function_node():
    """Test creating a function node."""
    flow_service.initialize_flow("test-agent")
    node = flow_service.add_node(
        "test-agent",
        "function",
        "handle_request()",
        {"function_name": "handle_request"}
    )
    assert node.type == "function"


def test_create_call_node():
    """Test creating a call node."""
    flow_service.initialize_flow("test-agent")
    node = flow_service.add_node(
        "test-agent",
        "call",
        "→ process()",
        {"target_function": "process"}
    )
    assert node.type == "call"
