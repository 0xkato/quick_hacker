"""Tests for flow service context tracking."""
import pytest

from services.flow_service import FlowService, FlowContext, InvestigationFlow, flow_service


@pytest.fixture(autouse=True)
def cleanup_flow_service():
    """Clear flow service state before and after each test."""
    flow_service._flows.clear()
    flow_service._subscribers.clear()
    if hasattr(flow_service, "_structured_index"):
        flow_service._structured_index.clear()
    yield
    flow_service._flows.clear()
    flow_service._subscribers.clear()
    if hasattr(flow_service, "_structured_index"):
        flow_service._structured_index.clear()


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


def test_add_node_auto_parent_file_to_candidate():
    """Test file nodes auto-parent to candidate node."""
    flow_service.initialize_flow("test-agent")

    # Create candidate node and set as context
    candidate = flow_service.add_node(
        "test-agent",
        "entry_point",
        "POST /api/upload",
        {}
    )
    flow_service.update_context("test-agent", current_candidate_node_id=candidate.id)

    # Create file node with auto_parent=True
    file_node = flow_service.add_node(
        "test-agent",
        "file",
        "routes.py",
        {"file_path": "/app/routes.py"},
        auto_parent=True
    )

    # Should have edge from candidate to file
    flow = flow_service.get_flow("test-agent")
    edge = next((e for e in flow.edges if e.target == file_node.id), None)
    assert edge is not None
    assert edge.source == candidate.id


def test_add_node_auto_parent_function_to_file():
    """Test function nodes auto-parent to current file."""
    flow_service.initialize_flow("test-agent")

    # Create file node
    file_node = flow_service.add_node(
        "test-agent",
        "file",
        "routes.py",
        {"file_path": "/app/routes.py"}
    )
    flow_service.update_context("test-agent", current_file="/app/routes.py")

    # Create function node with auto_parent=True
    func_node = flow_service.add_node(
        "test-agent",
        "function",
        "handle_request()",
        {"function_name": "handle_request"},
        auto_parent=True
    )

    # Should have edge from file to function
    flow = flow_service.get_flow("test-agent")
    edge = next((e for e in flow.edges if e.target == func_node.id), None)
    assert edge is not None
    assert edge.source == file_node.id


def test_add_node_explicit_parent_overrides_auto():
    """Test explicit parent_id overrides auto-parent logic."""
    flow_service.initialize_flow("test-agent")

    # Create two nodes
    node1 = flow_service.add_node("test-agent", "scan", "Scan Start", {})
    node2 = flow_service.add_node("test-agent", "analysis", "Analysis", {})

    # Set context but provide explicit parent
    flow_service.update_context("test-agent", current_candidate_node_id=node1.id)

    node3 = flow_service.add_node(
        "test-agent",
        "file",
        "routes.py",
        {},
        parent_id=node2.id,  # Explicit parent
        auto_parent=True
    )

    # Should use explicit parent, not context
    flow = flow_service.get_flow("test-agent")
    edge = next((e for e in flow.edges if e.target == node3.id), None)
    assert edge is not None
    assert edge.source == node2.id


def test_flow_context_has_call_depth_fields():
    """FlowContext should have call_depth and max_call_depth fields."""
    from services.flow_service import FlowContext

    context = FlowContext(
        call_depth=2,
        max_call_depth=5
    )

    assert context.call_depth == 2
    assert context.max_call_depth == 5


def test_flow_context_defaults():
    """FlowContext should default call_depth=0 and max_call_depth=3."""
    from services.flow_service import FlowContext

    context = FlowContext()

    assert context.call_depth == 0
    assert context.max_call_depth == 3


def test_flow_context_rejects_negative_call_depth():
    """FlowContext should reject negative call_depth."""
    from services.flow_service import FlowContext
    import pytest

    with pytest.raises(ValueError, match="call_depth must be non-negative"):
        FlowContext(call_depth=-1)


def test_flow_context_rejects_zero_max_call_depth():
    """FlowContext should reject zero max_call_depth."""
    from services.flow_service import FlowContext
    import pytest

    with pytest.raises(ValueError, match="max_call_depth must be positive"):
        FlowContext(max_call_depth=0)


def test_flow_context_rejects_negative_max_call_depth():
    """FlowContext should reject negative max_call_depth."""
    from services.flow_service import FlowContext
    import pytest

    with pytest.raises(ValueError, match="max_call_depth must be positive"):
        FlowContext(max_call_depth=-1)


def test_update_context_with_call_depth():
    """update_context should update call_depth fields."""
    from services.flow_service import flow_service

    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    # Update call_depth
    flow_service.update_context(agent_id, call_depth=2)
    flow = flow_service.get_flow(agent_id)
    assert flow.context.call_depth == 2

    # Update max_call_depth
    flow_service.update_context(agent_id, max_call_depth=5)
    flow = flow_service.get_flow(agent_id)
    assert flow.context.max_call_depth == 5

    # Both should be preserved
    assert flow.context.call_depth == 2


def test_update_context_rejects_negative_call_depth():
    """update_context should reject negative call_depth."""
    from services.flow_service import flow_service
    import pytest

    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    with pytest.raises(ValueError, match="call_depth must be non-negative"):
        flow_service.update_context(agent_id, call_depth=-1)


def test_update_context_rejects_zero_max_call_depth():
    """update_context should reject zero max_call_depth."""
    from services.flow_service import flow_service
    import pytest

    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    with pytest.raises(ValueError, match="max_call_depth must be positive"):
        flow_service.update_context(agent_id, max_call_depth=0)


def test_update_context_rejects_negative_max_call_depth():
    """update_context should reject negative max_call_depth."""
    from services.flow_service import flow_service
    import pytest

    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    with pytest.raises(ValueError, match="max_call_depth must be positive"):
        flow_service.update_context(agent_id, max_call_depth=-1)


def test_edge_kind_defaults_to_legacy():
    """Edges created by add_node should default to kind='legacy'."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    node1 = flow_service.add_node(agent_id, "scan", "Scan Start", {})
    node2 = flow_service.add_node(agent_id, "analysis", "Analysis", {})

    flow = flow_service.get_flow(agent_id)
    assert flow is not None

    edge = next((e for e in flow.edges if e.source == node1.id and e.target == node2.id), None)
    assert edge is not None
    assert edge.kind == "legacy"


def test_structured_trace_roots_created_and_deduped():
    """ensure_structured_trace should create and dedupe structural roots."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)

    roots1 = flow_service.ensure_structured_trace(agent_id)
    roots2 = flow_service.ensure_structured_trace(agent_id)
    assert roots1 == roots2

    flow = flow_service.get_flow(agent_id)
    assert flow is not None

    assert sum(1 for n in flow.nodes if n.type == "structured_root") == 1
    assert sum(1 for n in flow.nodes if n.type == "global_recon") == 1
    assert sum(1 for n in flow.nodes if n.type == "sinks_group") == 1


def test_get_or_create_structured_steps_parent_builds_hierarchy_and_is_idempotent():
    """get_or_create_structured_steps_parent should build folder→file→function→steps path."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)
    flow_service.ensure_structured_trace(agent_id)

    steps_id_1 = flow_service.get_or_create_structured_steps_parent(
        agent_id,
        trace_root_key="global_recon",
        file_path="backend/services/foo.py",
        function_name="do_thing",
        line_number=123,
    )
    steps_id_2 = flow_service.get_or_create_structured_steps_parent(
        agent_id,
        trace_root_key="global_recon",
        file_path="backend/services/foo.py",
        function_name="do_thing",
        line_number=123,
    )
    assert steps_id_1 == steps_id_2

    flow = flow_service.get_flow(agent_id)
    assert flow is not None

    folder_paths = sorted(
        str(n.data.get("folder_path"))
        for n in flow.nodes
        if n.type == "folder" and isinstance(n.data, dict) and n.data.get("folder_path")
    )
    assert folder_paths == ["backend", "backend/services"]

    file_nodes = [
        n for n in flow.nodes
        if n.type == "file" and n.data.get("file_path") == "backend/services/foo.py" and n.data.get("trace_kind") == "structural"
    ]
    assert len(file_nodes) == 1

    func_nodes = [
        n for n in flow.nodes
        if n.type == "function" and n.data.get("function_name") == "do_thing" and n.data.get("trace_kind") == "structural"
    ]
    assert len(func_nodes) == 1

    steps_nodes = [n for n in flow.nodes if n.type == "steps"]
    assert len(steps_nodes) == 1
    assert steps_nodes[0].id == steps_id_1


def test_populate_structured_from_candidates_creates_entrypoints_and_sinks():
    """populate_structured_from_candidates should create structured entrypoints and sinks (idempotent)."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)
    flow_service.add_node(agent_id, "user_input", "Start", {}, set_current=False)

    candidates = [
        {
            "kind": "entry_point",
            "id": "ep1",
            "label": "GET /hello → hello()",
            "file_path": "app.py",
            "line_number": 10,
            "metadata": {"method": "GET", "route": "/hello"},
            "code_context": "10: def hello():\n11:   ...",
        },
        {
            "kind": "sink",
            "id": "s1",
            "label": "sql sink: cursor.execute(...)",
            "file_path": "db.py",
            "line_number": 22,
            "metadata": {"sink_type": "sql"},
            "code_context": "22: cursor.execute(query)",
        },
    ]

    flow_service.populate_structured_from_candidates(agent_id, candidates)
    flow_service.populate_structured_from_candidates(agent_id, candidates)

    flow = flow_service.get_flow(agent_id)
    assert flow is not None

    entry_nodes = [
        n
        for n in flow.nodes
        if n.type == "entry_point" and n.data.get("trace_kind") == "structural" and n.data.get("attack_surface_candidate_id") == "ep1"
    ]
    assert len(entry_nodes) == 1
    assert entry_nodes[0].data.get("touched") is False

    sink_nodes = [
        n
        for n in flow.nodes
        if n.type == "dangerous_sink" and n.data.get("trace_kind") == "structural" and n.data.get("attack_surface_candidate_id") == "s1"
    ]
    assert len(sink_nodes) == 1

    # Ensure structured edges exist for the structured nodes.
    structured_edges = [e for e in flow.edges if getattr(e, "kind", None) == "structured"]
    assert structured_edges, "expected at least one structured edge"


def test_structured_root_selection_and_entrypoint_touched_flag():
    """set_structured_trace_root + mark_structured_entrypoint_touched should update context and node data."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)
    flow_service.add_node(agent_id, "user_input", "Start", {}, set_current=False)

    candidates = [
        {
            "kind": "entry_point",
            "id": "epX",
            "label": "GET /x → x()",
            "file_path": "app.py",
            "line_number": 1,
            "metadata": {},
            "code_context": "1: def x():\n2:  ...",
        }
    ]
    flow_service.populate_structured_from_candidates(agent_id, candidates)

    flow_service.set_structured_trace_root(agent_id, "entry_point:epX")
    flow_service.mark_structured_entrypoint_touched(agent_id, "epX")

    flow = flow_service.get_flow(agent_id)
    assert flow is not None
    assert flow.context.structured_trace_root_key == "entry_point:epX"

    entry_nodes = [
        n
        for n in flow.nodes
        if n.type == "entry_point" and n.data.get("trace_kind") == "structural" and n.data.get("attack_surface_candidate_id") == "epX"
    ]
    assert len(entry_nodes) == 1
    assert entry_nodes[0].data.get("touched") is True


def test_attach_node_to_structured_trace_adds_structured_edge_from_steps():
    """attach_node_to_structured_trace should connect steps → node via a structured edge."""
    agent_id = "test-agent"
    flow_service.initialize_flow(agent_id)
    flow_service.add_node(agent_id, "user_input", "Start", {}, set_current=False)

    tool_node = flow_service.add_node(
        agent_id,
        "search",
        "search_code: foo",
        {"tool": "search_code", "args": {"path": "backend/services/foo.py"}},
        set_current=False,
    )

    flow_service.attach_node_to_structured_trace(
        agent_id,
        tool_node.id,
        tool_name="search_code",
        args={"path": "backend/services/foo.py"},
    )
    flow_service.attach_node_to_structured_trace(
        agent_id,
        tool_node.id,
        tool_name="search_code",
        args={"path": "backend/services/foo.py"},
    )

    flow = flow_service.get_flow(agent_id)
    assert flow is not None

    structured_edges = [e for e in flow.edges if (e.kind or "legacy") == "structured" and e.target == tool_node.id]
    assert len(structured_edges) == 1

    steps_node = next((n for n in flow.nodes if n.id == structured_edges[0].source), None)
    assert steps_node is not None
    assert steps_node.type == "steps"
