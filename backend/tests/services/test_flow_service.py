"""Tests for flow service context tracking."""
import pytest

from services.flow_service import FlowService, FlowContext, InvestigationFlow, flow_service


@pytest.fixture(autouse=True)
def cleanup_flow_service():
    """Clear flow service state before and after each test."""
    flow_service._flows.clear()
    flow_service._subscribers.clear()
    yield
    flow_service._flows.clear()
    flow_service._subscribers.clear()


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


def test_update_context_file():
    """Test updating context with current file."""
    flow_service.initialize_flow("test-agent")
    flow_service.update_context("test-agent", current_file="/app/routes.py")

    flow = flow_service.get_flow("test-agent")
    assert flow.context.current_file == "/app/routes.py"


def test_update_context_multiple_fields():
    """Test updating multiple context fields."""
    flow_service.initialize_flow("test-agent")
    flow_service.update_context(
        "test-agent",
        current_file="/app/routes.py",
        current_function="handle_request",
        current_candidate_node_id="abc123"
    )

    flow = flow_service.get_flow("test-agent")
    assert flow.context.current_file == "/app/routes.py"
    assert flow.context.current_function == "handle_request"
    assert flow.context.current_candidate_node_id == "abc123"


def test_update_context_preserves_other_fields():
    """Test updating one field preserves others."""
    flow_service.initialize_flow("test-agent")
    flow_service.update_context("test-agent", current_file="/app/routes.py")
    flow_service.update_context("test-agent", current_function="handle_request")

    flow = flow_service.get_flow("test-agent")
    assert flow.context.current_file == "/app/routes.py"
    assert flow.context.current_function == "handle_request"


def test_get_or_create_file_node_creates_new():
    """Test get_or_create_file_node creates node if not exists."""
    flow_service.initialize_flow("test-agent")
    result = flow_service.get_or_create_file_node("test-agent", "/app/routes.py")
    assert result is None  # Returns None on first call (caller should create)


def test_get_or_create_file_node_returns_existing():
    """Test get_or_create_file_node returns existing node."""
    flow_service.initialize_flow("test-agent")

    # Create file node
    node = flow_service.add_node(
        "test-agent",
        "file",
        "routes.py",
        {"file_path": "/app/routes.py"}
    )

    # Should return the existing node
    result = flow_service.get_or_create_file_node("test-agent", "/app/routes.py")
    assert result is not None
    assert result.id == node.id
    assert result.type == "file"


def test_get_or_create_file_node_different_paths():
    """Test different paths return different nodes."""
    flow_service.initialize_flow("test-agent")

    # Create two file nodes
    node1 = flow_service.add_node(
        "test-agent",
        "file",
        "routes.py",
        {"file_path": "/app/routes.py"}
    )
    node2 = flow_service.add_node(
        "test-agent",
        "file",
        "models.py",
        {"file_path": "/app/models.py"}
    )

    # Should return correct node for each path
    result1 = flow_service.get_or_create_file_node("test-agent", "/app/routes.py")
    result2 = flow_service.get_or_create_file_node("test-agent", "/app/models.py")

    assert result1.id == node1.id
    assert result2.id == node2.id
