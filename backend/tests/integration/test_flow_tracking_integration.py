"""Integration tests for flow tracking tools."""

import pytest
from services.flow_service import flow_service
from services.tool_core import ToolCore


@pytest.fixture
def tool_core_with_flow(tmp_path):
    """ToolCore with flow initialized."""
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()

    tc = ToolCore(
        repo_path=str(repo_path),
        project_id="test-project",
        agent_id="test-agent"
    )

    # Initialize flow
    flow_service.initialize_flow(tc.agent_id)

    yield tc

    # Cleanup
    flow_service.clear_flow(tc.agent_id)


@pytest.mark.asyncio
async def test_complete_investigation_flow(tool_core_with_flow):
    """Test a complete investigation flow with all tracking tools."""
    tc = tool_core_with_flow

    # 1. Track file analysis
    await tc.track_file_analysis("api/routes.py", purpose="looking for API endpoints")

    # 2. Track function discovered
    await tc.track_function_discovered(
        function_name="handleUpload",
        file_path="api/routes.py",
        line_number=45,
        signature="async def handleUpload(file: UploadFile)",
        reason="handles file uploads"
    )

    # 3. Track entry point
    await tc.track_entry_point(
        entry_type="api_route",
        file_path="api/routes.py",
        line_number=45,
        route="/api/upload",
        method="POST"
    )

    # 4. Track call chain
    await tc.track_call_chain(
        from_function="handleUpload",
        calls=[
            {"target": "validateFile", "file": "validators.py"},
            {"target": "saveToStorage", "file": "storage.py"}
        ]
    )

    # 5. Track sink
    await tc.track_sink_identified(
        sink_type="path_traversal",
        file_path="storage.py",
        line_number=89,
        code_snippet="open(f'uploads/{filename}', 'w')"
    )

    # Verify flow structure
    flow = flow_service.get_flow(tc.agent_id)
    assert flow is not None

    # Check node counts
    file_nodes = [n for n in flow.nodes if n.type == "file"]
    func_nodes = [n for n in flow.nodes if n.type == "function"]
    entry_nodes = [n for n in flow.nodes if n.type == "entry_point"]
    call_nodes = [n for n in flow.nodes if n.type == "call"]
    sink_nodes = [n for n in flow.nodes if n.type == "dangerous_sink"]

    assert len(file_nodes) == 1
    assert len(func_nodes) == 1
    assert len(entry_nodes) == 1
    assert len(call_nodes) == 2
    assert len(sink_nodes) == 1

    # Verify tree structure (function parents to file)
    func_node = func_nodes[0]
    parent_edge = next((e for e in flow.edges if e.target == func_node.id), None)
    assert parent_edge is not None
    parent_node = next(n for n in flow.nodes if n.id == parent_edge.source)
    assert parent_node.type == "file"

    # Verify call nodes parent to function or entry_point
    for call_node in call_nodes:
        parent_edge = next((e for e in flow.edges if e.target == call_node.id), None)
        assert parent_edge is not None
        parent = next(n for n in flow.nodes if n.id == parent_edge.source)
        assert parent.type in ["function", "call", "entry_point"]


@pytest.mark.asyncio
async def test_cross_file_investigation(tool_core_with_flow):
    """Test tracking investigation across multiple files."""
    tc = tool_core_with_flow

    # Track first file
    await tc.track_file_analysis("api/routes.py")
    await tc.track_function_discovered("handler", "api/routes.py", 10)

    # Track second file
    await tc.track_file_analysis("db/queries.py", purpose="tracing data flow")
    await tc.track_function_discovered("executeQuery", "db/queries.py", 50)

    # Verify both files tracked
    flow = flow_service.get_flow(tc.agent_id)
    file_nodes = [n for n in flow.nodes if n.type == "file"]
    assert len(file_nodes) == 2

    # Verify context updated to second file
    assert flow.context.current_file == "db/queries.py"
    assert flow.context.current_function == "executeQuery"
