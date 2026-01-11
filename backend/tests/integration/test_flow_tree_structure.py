"""Integration tests for flow tree structure."""
import pytest
from services.flow_service import flow_service


@pytest.fixture
def agent_id():
    """Fixture providing unique agent ID."""
    return "test-agent-integration"


@pytest.fixture(autouse=True)
def cleanup(agent_id):
    """Clean up flow after each test."""
    yield
    flow_service.clear_flow(agent_id)


def test_file_investigation_creates_tree(agent_id):
    """Test that file investigation creates proper tree structure."""
    # Initialize flow
    flow_service.initialize_flow(agent_id)

    # Create scan node
    scan_node = flow_service.add_node(
        agent_id,
        "scan",
        "Attack Surface Scan",
        {}
    )

    # Create candidate (entry point)
    candidate_node = flow_service.add_node(
        agent_id,
        "entry_point",
        "POST /api/upload",
        {"file_path": "routes/api.py", "line_number": 45},
        parent_id=scan_node.id,
        set_current=False
    )

    # Set context for this investigation
    flow_service.update_context(
        agent_id,
        current_candidate_node_id=candidate_node.id
    )

    # Create file node with auto-parent
    file_node = flow_service.add_node(
        agent_id,
        "file",
        "api.py",
        {"file_path": "routes/api.py"},
        auto_parent=True,
        set_current=False
    )

    # Update context to current file
    flow_service.update_context(agent_id, current_file="routes/api.py")

    # Create function node with auto-parent
    func_node = flow_service.add_node(
        agent_id,
        "function",
        "handle_upload()",
        {"function_name": "handle_upload", "line_number": 50},
        auto_parent=True,
        set_current=False
    )

    # Create call node
    call_node = flow_service.add_node(
        agent_id,
        "call",
        "→ validate_file()",
        {"target_function": "validate_file", "target_file": "utils/validator.py"},
        parent_id=func_node.id,
        set_current=False
    )

    # Verify tree structure
    flow = flow_service.get_flow(agent_id)

    # Check nodes exist
    assert len(flow.nodes) == 5

    # Check edges (scan → candidate → file → function → call)
    edges_by_target = {e.target: e.source for e in flow.edges}

    assert edges_by_target[candidate_node.id] == scan_node.id
    assert edges_by_target[file_node.id] == candidate_node.id
    assert edges_by_target[func_node.id] == file_node.id
    assert edges_by_target[call_node.id] == func_node.id


def test_multiple_investigation_trees(agent_id):
    """Test multiple parallel investigation trees."""
    flow_service.initialize_flow(agent_id)

    scan_node = flow_service.add_node(agent_id, "scan", "Scan", {})

    # Create two candidates
    candidate1 = flow_service.add_node(
        agent_id, "entry_point", "Entry 1", {},
        parent_id=scan_node.id, set_current=False
    )
    candidate2 = flow_service.add_node(
        agent_id, "dangerous_sink", "Sink 1", {},
        parent_id=scan_node.id, set_current=False
    )

    # Investigate first candidate
    flow_service.update_context(agent_id, current_candidate_node_id=candidate1.id)
    file1 = flow_service.add_node(
        agent_id, "file", "routes.py", {"file_path": "routes.py"},
        auto_parent=True, set_current=False
    )

    # Investigate second candidate
    flow_service.update_context(agent_id, current_candidate_node_id=candidate2.id)
    file2 = flow_service.add_node(
        agent_id, "file", "models.py", {"file_path": "models.py"},
        auto_parent=True, set_current=False
    )

    # Verify both trees are independent
    flow = flow_service.get_flow(agent_id)
    edges_by_target = {e.target: e.source for e in flow.edges}

    # Both candidates children of scan
    assert edges_by_target[candidate1.id] == scan_node.id
    assert edges_by_target[candidate2.id] == scan_node.id

    # Files are children of their respective candidates
    assert edges_by_target[file1.id] == candidate1.id
    assert edges_by_target[file2.id] == candidate2.id
