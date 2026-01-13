# Agent Flow Instrumentation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 5 MCP flow tracking tools that agents use to create semantic investigation trees (file → function → call → sink) instead of generic tool_call nodes.

**Architecture:** Add `@tool` decorated MCP functions to `mcp_tools.py`, wire to `flow_service`, update agent prompts with FLOW TRACKING instructions.

**Tech Stack:** Python (Claude Agent SDK), flow_service, MCP tools, pytest

---

## Task 1: Add track_file_analysis MCP Tool

**Files:**
- Modify: `backend/providers/mcp_tools.py:236-400` (in `_create_sdk_server` function)
- Modify: `backend/providers/mcp_tools.py:35-150` (MCP_TOOLS list for fallback)
- Test: `backend/tests/providers/test_mcp_tools.py`

**Step 1: Add to MCP_TOOLS list for fallback mode**

**File:** `backend/providers/mcp_tools.py`

Find the `MCP_TOOLS` list (around line 35) and add after the last tool definition:

```python
    {
        "name": "track_file_analysis",
        "description": "Record that you're analyzing a file to build investigation tree",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path relative to repository root"},
                "purpose": {"type": "string", "description": "Why analyzing this file (e.g., 'looking for entry points')"}
            },
            "required": ["file_path"]
        }
    },
```

**Step 2: Add SDK tool function**

**File:** `backend/providers/mcp_tools.py`

In `_create_sdk_server()` function, after the last `@tool` definition (around line 400), add:

```python
    @tool("track_file_analysis", "Record that you're analyzing a file", {
        "file_path": str,
        "purpose": str,
    })
    async def track_file_analysis(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_file_analysis(
                file_path=args["file_path"],
                purpose=args.get("purpose", "analyzing")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)
```

**Step 3: Add to tool list at end of _create_sdk_server**

Find where tools are collected (near the end of `_create_sdk_server`), add `track_file_analysis` to the list.

**Step 4: Run linting**

```bash
cd backend
ruff check providers/mcp_tools.py
```

Expected: No errors

**Step 5: Commit**

```bash
git add backend/providers/mcp_tools.py
git commit -m "feat(mcp): add track_file_analysis tool definition

Add MCP tool for tracking file analysis in flow tree.
Agents call this when starting to analyze a file.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Add ToolCore.track_file_analysis Implementation

**Files:**
- Modify: `backend/services/tool_core.py`
- Test: `backend/tests/services/test_tool_core.py`

**Step 1: Write failing test**

**File:** `backend/tests/services/test_tool_core.py`

Add at end of file:

```python
@pytest.mark.asyncio
async def test_track_file_analysis(tool_core, mock_flow_service):
    """Test tracking file analysis creates file node."""
    # Initialize flow
    mock_flow_service.initialize_flow(tool_core.agent_id)

    result = await tool_core.track_file_analysis(
        file_path="api/routes.py",
        purpose="looking for entry points"
    )

    assert "node_id" in result
    assert result["status"] == "tracked"

    # Verify flow service was called correctly
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    file_nodes = [n for n in flow.nodes if n.type == "file"]
    assert len(file_nodes) == 1
    assert file_nodes[0].label == "api/routes.py"
    assert file_nodes[0].data["purpose"] == "looking for entry points"

    # Verify context updated
    assert flow.context.current_file == "api/routes.py"
    assert flow.context.current_function is None
    assert flow.context.call_depth == 0
```

**Step 2: Run test to verify it fails**

```bash
cd backend
pytest tests/services/test_tool_core.py::test_track_file_analysis -v
```

Expected: FAIL with "AttributeError: 'ToolCore' object has no attribute 'track_file_analysis'"

**Step 3: Implement track_file_analysis method**

**File:** `backend/services/tool_core.py`

Add method to ToolCore class (after existing tool methods):

```python
    async def track_file_analysis(
        self,
        file_path: str,
        purpose: str = "analyzing"
    ) -> dict[str, Any]:
        """Track file analysis in flow tree.

        Args:
            file_path: Path relative to repo root
            purpose: Why analyzing this file

        Returns:
            dict with node_id and status
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None, "status": "no_agent"}

        # Update context to track current file
        flow_service.update_context(
            self.agent_id,
            current_file=file_path,
            current_function=None,  # Reset when switching files
            call_depth=0            # Reset depth
        )

        # Create file node
        node = flow_service.add_node(
            self.agent_id,
            node_type="file",
            label=file_path,
            data={
                "file_path": file_path,
                "purpose": purpose
            },
            auto_parent=True  # Parents to investigation root
        )

        return {"node_id": node.id, "status": "tracked"}
```

**Step 4: Add agent_id to ToolCore initialization**

**File:** `backend/services/tool_core.py`

Find `__init__` method and add `agent_id` parameter:

```python
    def __init__(
        self,
        repo_path: str,
        project_id: str,
        agent_id: Optional[str] = None  # ADD THIS
    ):
        self.repo_path = Path(repo_path).resolve()
        self.project_id = project_id
        self.agent_id = agent_id  # ADD THIS
```

**Step 5: Update test fixture to provide agent_id**

**File:** `backend/tests/services/test_tool_core.py`

Find `tool_core` fixture and add `agent_id`:

```python
@pytest.fixture
def tool_core(tmp_path):
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()
    return ToolCore(
        repo_path=str(repo_path),
        project_id="test-project",
        agent_id="test-agent"  # ADD THIS
    )
```

**Step 6: Add mock_flow_service fixture**

```python
@pytest.fixture
def mock_flow_service(monkeypatch):
    """Mock flow service for testing."""
    from services.flow_service import FlowService
    mock_service = FlowService()

    # Patch the global flow_service instance
    import services.tool_core
    monkeypatch.setattr(services.tool_core, "flow_service", mock_service)

    return mock_service
```

**Step 7: Run test to verify it passes**

```bash
cd backend
pytest tests/services/test_tool_core.py::test_track_file_analysis -v
```

Expected: PASS

**Step 8: Commit**

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool): implement track_file_analysis in ToolCore

Tracks file analysis by creating file node in flow tree and
updating context with current file.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Add track_function_discovered MCP Tool

**Files:**
- Modify: `backend/providers/mcp_tools.py`
- Modify: `backend/services/tool_core.py`
- Test: `backend/tests/services/test_tool_core.py`

**Step 1: Add to MCP_TOOLS list**

**File:** `backend/providers/mcp_tools.py`

```python
    {
        "name": "track_function_discovered",
        "description": "Record a function you found interesting during analysis",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name (e.g., 'handleUpload')"},
                "file_path": {"type": "string", "description": "File containing function"},
                "line_number": {"type": "integer", "description": "Line where function defined"},
                "signature": {"type": "string", "description": "Full function signature (optional)"},
                "reason": {"type": "string", "description": "Why it's interesting (optional)"}
            },
            "required": ["function_name", "file_path", "line_number"]
        }
    },
```

**Step 2: Add SDK tool function**

```python
    @tool("track_function_discovered", "Record a function you found interesting", {
        "function_name": str,
        "file_path": str,
        "line_number": int,
        "signature": str,
        "reason": str,
    })
    async def track_function_discovered(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_function_discovered(
                function_name=args["function_name"],
                file_path=args["file_path"],
                line_number=args["line_number"],
                signature=args.get("signature"),
                reason=args.get("reason")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)
```

**Step 3: Write failing test**

**File:** `backend/tests/services/test_tool_core.py`

```python
@pytest.mark.asyncio
async def test_track_function_discovered(tool_core, mock_flow_service):
    """Test tracking function discovery creates function node."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    # First track the file
    await tool_core.track_file_analysis("api/routes.py")

    # Then track function
    result = await tool_core.track_function_discovered(
        function_name="handleUpload",
        file_path="api/routes.py",
        line_number=45,
        signature="async def handleUpload(file: UploadFile)",
        reason="handles file uploads"
    )

    assert "node_id" in result

    # Verify function node created
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    func_nodes = [n for n in flow.nodes if n.type == "function"]
    assert len(func_nodes) == 1
    assert func_nodes[0].label == "handleUpload"
    assert func_nodes[0].data["line_number"] == 45
    assert func_nodes[0].data["signature"] == "async def handleUpload(file: UploadFile)"

    # Verify context updated
    assert flow.context.current_function == "handleUpload"
```

**Step 4: Run test to verify failure**

```bash
pytest tests/services/test_tool_core.py::test_track_function_discovered -v
```

**Step 5: Implement track_function_discovered**

**File:** `backend/services/tool_core.py`

```python
    async def track_function_discovered(
        self,
        function_name: str,
        file_path: str,
        line_number: int,
        signature: Optional[str] = None,
        reason: Optional[str] = None
    ) -> dict[str, Any]:
        """Track function discovery in flow tree.

        Args:
            function_name: Name of the function
            file_path: File containing function
            line_number: Line where defined
            signature: Full function signature
            reason: Why it's interesting

        Returns:
            dict with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Update context
        flow_service.update_context(
            self.agent_id,
            current_function=function_name,
            current_file=file_path
        )

        # Create function node
        node = flow_service.add_node(
            self.agent_id,
            node_type="function",
            label=function_name,
            data={
                "function_name": function_name,
                "file_path": file_path,
                "line_number": line_number,
                "signature": signature,
                "reason": reason
            },
            auto_parent=True  # Parents to current file
        )

        return {"node_id": node.id}
```

**Step 6: Run test to verify pass**

```bash
pytest tests/services/test_tool_core.py::test_track_function_discovered -v
```

**Step 7: Commit**

```bash
git add backend/providers/mcp_tools.py backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool): add track_function_discovered

Records interesting functions in flow tree with metadata
like signature and reason for interest.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 4: Add track_call_chain MCP Tool

**Files:**
- Modify: `backend/providers/mcp_tools.py`
- Modify: `backend/services/tool_core.py`
- Test: `backend/tests/services/test_tool_core.py`

**Step 1: Add to MCP_TOOLS list**

```python
    {
        "name": "track_call_chain",
        "description": "Record a sequence of function calls discovered during tracing",
        "input_schema": {
            "type": "object",
            "properties": {
                "from_function": {"type": "string", "description": "Function making the calls"},
                "calls": {
                    "type": "array",
                    "description": "List of function calls",
                    "items": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Function being called"},
                            "file": {"type": "string", "description": "File containing target (optional)"}
                        },
                        "required": ["target"]
                    }
                }
            },
            "required": ["from_function", "calls"]
        }
    },
```

**Step 2: Add SDK tool function**

```python
    @tool("track_call_chain", "Record a sequence of function calls", {
        "from_function": str,
        "calls": list,
    })
    async def track_call_chain(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_call_chain(
                from_function=args["from_function"],
                calls=args["calls"]
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)
```

**Step 3: Write failing test**

**File:** `backend/tests/services/test_tool_core.py`

```python
@pytest.mark.asyncio
async def test_track_call_chain(tool_core, mock_flow_service):
    """Test tracking call chain creates call nodes."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    # Setup: track file and function
    await tool_core.track_file_analysis("api/routes.py")
    await tool_core.track_function_discovered("handleUpload", "api/routes.py", 45)

    # Track call chain
    result = await tool_core.track_call_chain(
        from_function="handleUpload",
        calls=[
            {"target": "validateFile", "file": "validators.py"},
            {"target": "saveToS3", "file": "storage.py"}
        ]
    )

    assert "call_nodes" in result
    assert len(result["call_nodes"]) == 2

    # Verify call nodes created
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    call_nodes = [n for n in flow.nodes if n.type == "call"]
    assert len(call_nodes) == 2
    assert call_nodes[0].label == "→ validateFile"
    assert call_nodes[0].data["target_file"] == "validators.py"
    assert call_nodes[1].label == "→ saveToS3"


@pytest.mark.asyncio
async def test_track_call_chain_respects_depth(tool_core, mock_flow_service):
    """Test call chain respects max_call_depth limit."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    # Set max depth to 2
    mock_flow_service.update_context(
        tool_core.agent_id,
        max_call_depth=2,
        call_depth=0
    )

    await tool_core.track_file_analysis("test.py")
    await tool_core.track_function_discovered("foo", "test.py", 1)

    # First call (depth 1) - should succeed
    result1 = await tool_core.track_call_chain("foo", [{"target": "bar"}])
    assert len(result1["call_nodes"]) == 1

    # Second call (depth 2) - should succeed
    result2 = await tool_core.track_call_chain("bar", [{"target": "baz"}])
    assert len(result2["call_nodes"]) == 1

    # Third call (depth 3) - should be skipped
    result3 = await tool_core.track_call_chain("baz", [{"target": "qux"}])
    assert len(result3["call_nodes"]) == 0

    # Verify only 2 call nodes created
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    call_nodes = [n for n in flow.nodes if n.type == "call"]
    assert len(call_nodes) == 2
```

**Step 4: Run tests to verify failure**

```bash
pytest tests/services/test_tool_core.py::test_track_call_chain -v
```

**Step 5: Implement track_call_chain**

**File:** `backend/services/tool_core.py`

```python
    async def track_call_chain(
        self,
        from_function: str,
        calls: list[dict[str, str]]
    ) -> dict[str, Any]:
        """Track function call chain in flow tree.

        Args:
            from_function: Function making the calls
            calls: List of calls with 'target' and optional 'file'

        Returns:
            dict with call_nodes list
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"call_nodes": []}

        flow = flow_service.get_flow(self.agent_id)
        if not flow:
            return {"call_nodes": []}

        context = flow.context
        call_node_ids = []

        for call in calls:
            target = call["target"]
            target_file = call.get("file")

            # Increment call depth
            new_depth = context.call_depth + 1

            # Respect max_call_depth
            if new_depth > context.max_call_depth:
                continue

            # Update context with new depth
            flow_service.update_context(self.agent_id, call_depth=new_depth)

            # Create call node
            node = flow_service.add_node(
                self.agent_id,
                node_type="call",
                label=f"→ {target}",
                data={
                    "target_function": target,
                    "target_file": target_file,
                    "from_function": from_function,
                    "call_depth": new_depth
                },
                auto_parent=True
            )

            call_node_ids.append(node.id)

        return {"call_nodes": call_node_ids}
```

**Step 6: Run tests to verify pass**

```bash
pytest tests/services/test_tool_core.py::test_track_call_chain -v
pytest tests/services/test_tool_core.py::test_track_call_chain_respects_depth -v
```

**Step 7: Commit**

```bash
git add backend/providers/mcp_tools.py backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool): add track_call_chain with depth limiting

Tracks function call sequences and respects max_call_depth
to prevent infinite recursion in flow tree.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: Add track_sink_identified MCP Tool

**Files:**
- Modify: `backend/providers/mcp_tools.py`
- Modify: `backend/services/tool_core.py`
- Test: `backend/tests/services/test_tool_core.py`

**Step 1: Add to MCP_TOOLS list**

```python
    {
        "name": "track_sink_identified",
        "description": "Mark a dangerous sink discovered during investigation",
        "input_schema": {
            "type": "object",
            "properties": {
                "sink_type": {"type": "string", "description": "Type: sql, exec, file_write, deserialize, ssrf"},
                "file_path": {"type": "string", "description": "File containing sink"},
                "line_number": {"type": "integer", "description": "Line number of sink"},
                "code_snippet": {"type": "string", "description": "Code showing the sink (optional)"}
            },
            "required": ["sink_type", "file_path", "line_number"]
        }
    },
```

**Step 2: Add SDK tool function**

```python
    @tool("track_sink_identified", "Mark a dangerous sink discovered", {
        "sink_type": str,
        "file_path": str,
        "line_number": int,
        "code_snippet": str,
    })
    async def track_sink_identified(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_sink_identified(
                sink_type=args["sink_type"],
                file_path=args["file_path"],
                line_number=args["line_number"],
                code_snippet=args.get("code_snippet")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)
```

**Step 3: Write failing test**

```python
@pytest.mark.asyncio
async def test_track_sink_identified(tool_core, mock_flow_service):
    """Test tracking sink creates dangerous_sink node."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    result = await tool_core.track_sink_identified(
        sink_type="sql",
        file_path="db/queries.py",
        line_number=89,
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"
    )

    assert "node_id" in result
    assert result["marked_dangerous"] is True

    # Verify sink node
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    sink_nodes = [n for n in flow.nodes if n.type == "dangerous_sink"]
    assert len(sink_nodes) == 1
    assert sink_nodes[0].label == "⚠️ SQL sink"
    assert sink_nodes[0].data["sink_type"] == "sql"
    assert sink_nodes[0].data["line_number"] == 89
```

**Step 4: Run test to verify failure**

**Step 5: Implement track_sink_identified**

```python
    async def track_sink_identified(
        self,
        sink_type: str,
        file_path: str,
        line_number: int,
        code_snippet: Optional[str] = None
    ) -> dict[str, Any]:
        """Track dangerous sink in flow tree.

        Args:
            sink_type: Type of sink (sql, exec, etc.)
            file_path: File containing sink
            line_number: Line number
            code_snippet: Code showing sink

        Returns:
            dict with node_id and marked_dangerous flag
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None, "marked_dangerous": False}

        # Create dangerous_sink node
        node = flow_service.add_node(
            self.agent_id,
            node_type="dangerous_sink",
            label=f"⚠️ {sink_type.upper()} sink",
            data={
                "sink_type": sink_type,
                "file_path": file_path,
                "line_number": line_number,
                "code_snippet": code_snippet,
                "severity": "high"
            },
            auto_parent=True
        )

        return {"node_id": node.id, "marked_dangerous": True}
```

**Step 6: Run test to verify pass**

**Step 7: Commit**

```bash
git add backend/providers/mcp_tools.py backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool): add track_sink_identified

Marks dangerous sinks in flow tree with special styling
and severity metadata.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 6: Add track_entry_point MCP Tool

**Files:**
- Modify: `backend/providers/mcp_tools.py`
- Modify: `backend/services/tool_core.py`
- Test: `backend/tests/services/test_tool_core.py`

**Step 1: Add to MCP_TOOLS list**

```python
    {
        "name": "track_entry_point",
        "description": "Mark an entry point discovered (API route, CLI arg, etc.)",
        "input_schema": {
            "type": "object",
            "properties": {
                "entry_type": {"type": "string", "description": "Type: api_route, cli_arg, form_handler, websocket"},
                "file_path": {"type": "string", "description": "File containing entry point"},
                "line_number": {"type": "integer", "description": "Line number"},
                "route": {"type": "string", "description": "Route path like /api/upload (optional)"},
                "method": {"type": "string", "description": "HTTP method like POST (optional)"}
            },
            "required": ["entry_type", "file_path", "line_number"]
        }
    },
```

**Step 2: Add SDK tool function**

```python
    @tool("track_entry_point", "Mark an entry point discovered", {
        "entry_type": str,
        "file_path": str,
        "line_number": int,
        "route": str,
        "method": str,
    })
    async def track_entry_point(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_entry_point(
                entry_type=args["entry_type"],
                file_path=args["file_path"],
                line_number=args["line_number"],
                route=args.get("route"),
                method=args.get("method")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)
```

**Step 3: Write failing test**

```python
@pytest.mark.asyncio
async def test_track_entry_point(tool_core, mock_flow_service):
    """Test tracking entry point creates entry_point node."""
    mock_flow_service.initialize_flow(tool_core.agent_id)

    result = await tool_core.track_entry_point(
        entry_type="api_route",
        file_path="api/routes.py",
        line_number=45,
        route="/api/upload",
        method="POST"
    )

    assert "node_id" in result

    # Verify entry point node
    flow = mock_flow_service.get_flow(tool_core.agent_id)
    entry_nodes = [n for n in flow.nodes if n.type == "entry_point"]
    assert len(entry_nodes) == 1
    assert entry_nodes[0].label == "POST /api/upload"
    assert entry_nodes[0].data["entry_type"] == "api_route"
```

**Step 4: Run test to verify failure**

**Step 5: Implement track_entry_point**

```python
    async def track_entry_point(
        self,
        entry_type: str,
        file_path: str,
        line_number: int,
        route: Optional[str] = None,
        method: Optional[str] = None
    ) -> dict[str, Any]:
        """Track entry point in flow tree.

        Args:
            entry_type: Type of entry point
            file_path: File location
            line_number: Line number
            route: Route path if applicable
            method: HTTP method if applicable

        Returns:
            dict with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Build label
        label = route if route else f"{entry_type} entry point"
        if method:
            label = f"{method} {label}"

        # Create entry_point node
        node = flow_service.add_node(
            self.agent_id,
            node_type="entry_point",
            label=label,
            data={
                "entry_type": entry_type,
                "file_path": file_path,
                "line_number": line_number,
                "route": route,
                "method": method
            },
            auto_parent=True
        )

        return {"node_id": node.id}
```

**Step 6: Run test to verify pass**

**Step 7: Commit**

```bash
git add backend/providers/mcp_tools.py backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool): add track_entry_point

Marks entry points (API routes, CLI args, etc.) in flow tree
with route and method metadata.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 7: Update MCP Tool Registration

**Files:**
- Modify: `backend/providers/mcp_tools.py:236-500`

**Step 1: Find tool registration in _create_sdk_server**

Look for where all tools are added to the MCP server (near end of function). Should see something like:

```python
    mcp_server = create_sdk_mcp_server(
        "quickhack",
        [read_file, search_code, list_directory, ...]
    )
```

**Step 2: Add all 5 new tools to the list**

Add the 5 new tracking tools:

```python
    mcp_server = create_sdk_mcp_server(
        "quickhack",
        [
            read_file,
            search_code,
            list_directory,
            # ... existing tools ...
            track_file_analysis,
            track_function_discovered,
            track_call_chain,
            track_sink_identified,
            track_entry_point,
        ]
    )
```

**Step 3: Update server_config allowed_tools**

Find `server_config` dict and add the new tools:

```python
    server_config = {
        "allowed_tools": [
            "mcp__quickhack__read_file",
            # ... existing tools ...
            "mcp__quickhack__track_file_analysis",
            "mcp__quickhack__track_function_discovered",
            "mcp__quickhack__track_call_chain",
            "mcp__quickhack__track_sink_identified",
            "mcp__quickhack__track_entry_point",
        ],
    }
```

**Step 4: Update ToolCore initialization in mcp_tools**

Find where ToolCore is instantiated and add agent_id. Look for something like:

```python
tool_core = ToolCore(repo_path=..., project_id=...)
```

Change to:

```python
tool_core = ToolCore(repo_path=..., project_id=..., agent_id=...)
```

Note: You may need to check how agent_id is available in this context.

**Step 5: Run all MCP tool tests**

```bash
cd backend
pytest tests/providers/test_mcp_tools.py -v
```

Expected: All tests pass

**Step 6: Commit**

```bash
git add backend/providers/mcp_tools.py
git commit -m "feat(mcp): register all 5 flow tracking tools

Complete MCP tool registration for flow tracking:
- track_file_analysis
- track_function_discovered
- track_call_chain
- track_sink_identified
- track_entry_point

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 8: Update Scanner Prompt with Flow Tracking

**Files:**
- Modify: `prompting/agents/scanner_system_prompt.md`

**Step 1: Find the CRITICAL RULES section**

Open `prompting/agents/scanner_system_prompt.md` and find the "CRITICAL RULES" section (around line 44).

**Step 2: Add FLOW TRACKING section after CRITICAL RULES**

After the CRITICAL RULES section, add:

```markdown
FLOW TRACKING:
As you investigate, build a visual investigation tree using these tools:

1. When you start analyzing a file:
   track_file_analysis(file_path="api/routes.py", purpose="looking for entry points")

2. When you find an interesting function:
   track_function_discovered(
       function_name="handleUpload",
       file_path="api/routes.py",
       line_number=45,
       signature="async def handleUpload(file: UploadFile)",
       reason="handles file uploads - potential security issue"
   )

3. When you discover function calls:
   track_call_chain(
       from_function="handleUpload",
       calls=[
           {"target": "validateFile", "file": "api/validators.py"},
           {"target": "saveToS3", "file": "storage/s3.py"}
       ]
   )

4. When you find entry points:
   track_entry_point(
       entry_type="api_route",
       route="/api/upload",
       file_path="api/routes.py",
       line_number=45
   )

5. When you find dangerous sinks:
   track_sink_identified(
       sink_type="sql",
       file_path="db/queries.py",
       line_number=89,
       code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"
   )

USE THESE TOOLS FREQUENTLY - they create the investigation visualization that helps you and the user understand the codebase structure.

EXAMPLES:

Exploring a new file:
  read_file("api/routes.py")
  track_file_analysis("api/routes.py", purpose="mapping API endpoints")

Finding a handler:
  track_function_discovered(
      function_name="uploadFile",
      file_path="api/routes.py",
      line_number=23,
      reason="API endpoint that handles file uploads"
  )

Tracing calls in that handler:
  track_call_chain(
      from_function="uploadFile",
      calls=[
          {"target": "validateUpload", "file": "validators.py"},
          {"target": "saveFile", "file": "storage.py"}
      ]
  )

Finding SQL injection:
  track_sink_identified(
      sink_type="sql",
      file_path="db/users.py",
      line_number=45,
      code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"
  )
```

**Step 3: Verify prompt renders correctly**

```bash
cd backend
python -c "from prompting_loader import render_prompt; print(render_prompt('agents/scanner_system_prompt.md', repo_info='test'))" | head -100
```

Expected: Prompt includes FLOW TRACKING section

**Step 4: Commit**

```bash
git add prompting/agents/scanner_system_prompt.md
git commit -m "docs(prompt): add FLOW TRACKING instructions to scanner

Instructs scanner agent to use flow tracking tools when
investigating to build semantic investigation tree.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 9: Update Analyzer Prompt with Flow Tracking

**Files:**
- Modify: `prompting/agents/analyzer_system_prompt.md`

**Step 1: Find appropriate section in analyzer prompt**

Open `prompting/agents/analyzer_system_prompt.md` and find a good place to add flow tracking (likely after initial instructions).

**Step 2: Add FLOW TRACKING section**

Add similar section to analyzer prompt:

```markdown
FLOW TRACKING:
As you perform deep analysis, continue building the investigation tree:

1. When analyzing suspected vulnerabilities, track the call chain:
   track_call_chain(
       from_function="handleRequest",
       calls=[
           {"target": "getUserInput"},
           {"target": "processQuery"},
           {"target": "executeSQL"}  // This is where the vulnerability occurs
       ]
   )

2. When confirming a sink is exploitable:
   track_sink_identified(
       sink_type="sql",
       file_path="db/queries.py",
       line_number=89,
       code_snippet="cursor.execute(query)"  // Confirmed vulnerable
   )

3. When tracing data flow from entry to sink:
   - Track each function in the path with track_function_discovered
   - Use track_call_chain to show the flow
   - Mark the final sink with track_sink_identified

This creates a visual proof-of-concept showing how user input reaches dangerous code.
The investigation tree helps both you and the user understand the vulnerability path.
```

**Step 3: Verify prompt renders**

```bash
python -c "from prompting_loader import render_prompt; print(render_prompt('agents/analyzer_system_prompt.md', repo_info='test'))" | head -100
```

**Step 4: Commit**

```bash
git add prompting/agents/analyzer_system_prompt.md
git commit -m "docs(prompt): add FLOW TRACKING instructions to analyzer

Instructs analyzer to continue flow tracking during deep analysis,
especially when tracing vulnerability paths.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 10: Integration Test for Flow Tracking

**Files:**
- Create: `backend/tests/integration/test_flow_tracking_integration.py`

**Step 1: Create integration test file**

**File:** `backend/tests/integration/test_flow_tracking_integration.py`

```python
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

    # Verify call nodes parent to function
    for call_node in call_nodes:
        parent_edge = next((e for e in flow.edges if e.target == call_node.id), None)
        assert parent_edge is not None
        parent = next(n for n in flow.nodes if n.id == parent_edge.source)
        assert parent.type in ["function", "call"]


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
```

**Step 2: Run integration tests**

```bash
cd backend
pytest tests/integration/test_flow_tracking_integration.py -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add backend/tests/integration/test_flow_tracking_integration.py
git commit -m "test: add flow tracking integration tests

Tests complete investigation flow with all 5 tracking tools
and verifies correct tree structure.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 11: Run Full Test Suite

**Step 1: Run all backend tests**

```bash
cd backend
pytest tests/ -v --tb=short
```

Expected: All tests pass (should be 614+ passing now with new tests)

**Step 2: Run linting**

```bash
cd backend
ruff check .
mypy services/tool_core.py providers/mcp_tools.py
```

Expected: No errors

**Step 3: Build frontend**

```bash
cd frontend
npm run build
```

Expected: Build succeeds

**Step 4: Commit any fixes needed**

If any test failures or lint errors, fix them and commit.

---

## Task 12: Manual Verification

**Step 1: Start the application**

```bash
# Terminal 1: Backend
cd backend
python -m uvicorn main:app --reload

# Terminal 2: Frontend
cd frontend
npm run dev
```

**Step 2: Run a security scan**

1. Open browser to http://localhost:3000
2. Start a new security audit
3. Watch the flow tree visualization
4. Verify you see:
   - File nodes (📁) with actual file paths
   - Function nodes (🔧) under files
   - Call nodes (→) showing relationships
   - Entry point and sink nodes marked appropriately

**Step 3: Test flow tree features**

- [ ] Collapse/expand nodes
- [ ] Search with `type:file` filter
- [ ] Search with `type:function` filter
- [ ] Keyboard shortcut Cmd+F
- [ ] Navigate between matches with Cmd+G

**Step 4: Verify semantic tree vs generic tool calls**

Compare the new semantic tree to what it looked like before (generic "LLM Interactions"). Should see meaningful investigation path.

---

## Task 13: Update Documentation

**Files:**
- Modify: `docs/features/flow-tree-visualization.md`

**Step 1: Add section about flow tracking tools**

**File:** `docs/features/flow-tree-visualization.md`

Find appropriate section and add:

```markdown
## Flow Tracking Tools

Agents use these MCP tools to build the investigation tree:

### track_file_analysis
Record file being analyzed:
```python
track_file_analysis(
    file_path="api/routes.py",
    purpose="looking for entry points"
)
```

Creates file node in tree.

### track_function_discovered
Record interesting function:
```python
track_function_discovered(
    function_name="handleUpload",
    file_path="api/routes.py",
    line_number=45,
    signature="async def handleUpload(...)",
    reason="handles file uploads"
)
```

Creates function node under file.

### track_call_chain
Record function call sequence:
```python
track_call_chain(
    from_function="handleUpload",
    calls=[
        {"target": "validateFile", "file": "validators.py"},
        {"target": "saveToStorage", "file": "storage.py"}
    ]
)
```

Creates call nodes showing flow. Respects `max_call_depth` (default: 3).

### track_sink_identified
Mark dangerous sink:
```python
track_sink_identified(
    sink_type="sql",
    file_path="db/queries.py",
    line_number=89,
    code_snippet="cursor.execute(...)"
)
```

Creates dangerous_sink node with ⚠️ icon.

### track_entry_point
Mark entry point:
```python
track_entry_point(
    entry_type="api_route",
    file_path="api/routes.py",
    line_number=45,
    route="/api/upload",
    method="POST"
)
```

Creates entry_point node.

## Agent Instrumentation

Scanner and analyzer agents are instructed via their system prompts to use these tools during investigation. This creates semantic flow trees instead of generic tool_call nodes.
```

**Step 2: Commit documentation**

```bash
git add docs/features/flow-tree-visualization.md
git commit -m "docs: document flow tracking tools for agents

Add documentation for the 5 MCP flow tracking tools and
how agents use them to build semantic investigation trees.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Success Criteria

**Functional:**
- [ ] All 5 MCP tools implemented and registered
- [ ] ToolCore methods implement correct flow_service calls
- [ ] Scanner prompt includes FLOW TRACKING instructions
- [ ] Analyzer prompt includes FLOW TRACKING instructions
- [ ] All unit tests pass (18+ new tests)
- [ ] Integration tests pass
- [ ] Full test suite passes (614+ tests)

**Manual Verification:**
- [ ] Run security scan creates semantic tree
- [ ] Flow tree shows file → function → call → sink path
- [ ] Collapse/expand works with semantic nodes
- [ ] Search filters work (type:file, type:function)
- [ ] No performance degradation

**Documentation:**
- [ ] Flow tracking tools documented
- [ ] Examples provided for each tool

When all criteria met, feature is complete!
