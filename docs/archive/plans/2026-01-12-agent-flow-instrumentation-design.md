# Agent Flow Instrumentation Design

**Date:** 2026-01-12
**Status:** Design Complete, Ready for Implementation

## Problem Statement

The flow tree visualization infrastructure is complete with all features (collapse/expand, search, call tracing), but agents don't create semantic flow nodes. Instead of seeing meaningful investigation trees like:

```
📁 api/routes.py
  └─ 🔧 handleUpload()
      └─ → validateInput()
          └─ 🔧 checkAuth()
              └─ ⚠️ SQL query (dangerous sink)
```

Users see generic "LLM Interactions" with tool calls. The agents need to explicitly track their investigation steps to populate the flow tree.

## Solution Overview

Add explicit MCP flow tracking tools that agents call during investigation to build the semantic flow tree. Agents will use these tools alongside existing investigation tools (`read_file`, `search_code`) to record what they discover.

**Key Principle:** Agent explicitly calls tracking tools to record discoveries with semantic meaning.

---

## Architecture

### Core Concept

**New MCP Tools (5 tools):**
1. `track_file_analysis` - Record file being analyzed
2. `track_function_discovered` - Record interesting function found
3. `track_call_chain` - Record function call sequences
4. `track_sink_identified` - Mark dangerous sink
5. `track_entry_point` - Mark entry point discovered

**Investigation Flow:**
```
1. Agent: read_file("api/routes.py")
2. Agent: track_file_analysis("api/routes.py", purpose="looking for entry points")
   → Creates file node
3. Agent: track_function_discovered("handleUpload", line=45, parent="api/routes.py")
   → Creates function node under file
4. Agent: track_call_chain(from_function="handleUpload", calls=[...])
   → Creates call nodes showing function call sequence
5. Agent: track_sink_identified(sink_type="sql", file_path="db/queries.py", line=89)
   → Creates dangerous_sink node
```

**Integration Points:**
- MCP tools defined in `backend/providers/mcp_tools.py`
- Tools call `flow_service.add_node()` with proper node types
- Context tracking via `flow_service.update_context()`
- Agent prompts updated with FLOW TRACKING instructions

---

## MCP Tool Specifications

### 1. track_file_analysis

**Purpose:** Record that agent is analyzing a file

**Signature:**
```python
@tool("track_file_analysis", "Record that you're analyzing a file", {
    "file_path": str,  # required
    "purpose": str,    # optional
})
async def track_file_analysis(args: dict[str, Any]) -> dict[str, Any]
```

**Parameters:**
- `file_path` (required): Path relative to repo root (e.g., "api/routes.py")
- `purpose` (optional): Why analyzing (e.g., "looking for entry points", "tracing calls")

**Returns:**
```json
{
  "content": [{"type": "text", "text": "{\"node_id\": \"abc123\", \"status\": \"tracked\"}"}],
  "isError": false
}
```

**Implementation:**
```python
file_path = args["file_path"]
purpose = args.get("purpose", "analyzing")

# Update context to track current file
flow_service.update_context(
    agent_id,
    current_file=file_path,
    current_function=None,  # Reset when switching files
    call_depth=0            # Reset depth
)

# Create file node
node = flow_service.add_node(
    agent_id,
    node_type="file",
    label=file_path,
    data={"file_path": file_path, "purpose": purpose},
    auto_parent=True  # Parents to investigation root
)

return {"node_id": node.id, "status": "tracked"}
```

**Node Metadata:**
- `file_path`: Full path
- `purpose`: Why analyzing
- `timestamp`: When analyzed

---

### 2. track_function_discovered

**Purpose:** Record an interesting function discovered during analysis

**Signature:**
```python
@tool("track_function_discovered", "Record a function you found interesting", {
    "function_name": str,  # required
    "file_path": str,      # required
    "line_number": int,    # required
    "signature": str,      # optional
    "reason": str,         # optional
})
async def track_function_discovered(args: dict[str, Any]) -> dict[str, Any]
```

**Parameters:**
- `function_name` (required): Function name (e.g., "handleUpload")
- `file_path` (required): File containing function
- `line_number` (required): Line where function defined
- `signature` (optional): Full function signature
- `reason` (optional): Why it's interesting (e.g., "handles file uploads - potential security issue")

**Returns:**
```json
{
  "content": [{"type": "text", "text": "{\"node_id\": \"def456\", \"parent_id\": \"abc123\"}"}],
  "isError": false
}
```

**Implementation:**
```python
function_name = args["function_name"]
file_path = args["file_path"]
line_number = args["line_number"]
signature = args.get("signature")
reason = args.get("reason")

# Update context to track current function
flow_service.update_context(
    agent_id,
    current_function=function_name,
    current_file=file_path  # Ensure file context set
)

# Create function node
node = flow_service.add_node(
    agent_id,
    node_type="function",
    label=function_name,
    data={
        "function_name": function_name,
        "file_path": file_path,
        "line_number": line_number,
        "signature": signature,
        "reason": reason
    },
    auto_parent=True  # Parents to current file node
)

return {"node_id": node.id, "parent_id": node.data.get("parent_id")}
```

**Node Metadata:**
- `function_name`: Name
- `file_path`: Location
- `line_number`: Definition line
- `signature`: Full signature (if provided)
- `reason`: Why interesting

---

### 3. track_call_chain

**Purpose:** Record a sequence of function calls discovered during tracing

**Signature:**
```python
@tool("track_call_chain", "Record a sequence of function calls", {
    "from_function": str,  # required
    "calls": list,         # required - list of {"target": str, "file": str}
})
async def track_call_chain(args: dict[str, Any]) -> dict[str, Any]
```

**Parameters:**
- `from_function` (required): Function making the calls
- `calls` (required): List of calls, each with:
  - `target` (str): Function being called
  - `file` (str, optional): File containing target function

**Example:**
```json
{
  "from_function": "handleUpload",
  "calls": [
    {"target": "validateFile", "file": "api/validators.py"},
    {"target": "saveToS3", "file": "storage/s3.py"}
  ]
}
```

**Returns:**
```json
{
  "content": [{"type": "text", "text": "{\"call_nodes\": [\"xyz789\", \"xyz790\"]}"}],
  "isError": false
}
```

**Implementation:**
```python
from_function = args["from_function"]
calls = args["calls"]

flow = flow_service.get_flow(agent_id)
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
    flow_service.update_context(agent_id, call_depth=new_depth)

    # Create call node
    node = flow_service.add_node(
        agent_id,
        node_type="call",
        label=f"→ {target}",
        data={
            "target_function": target,
            "target_file": target_file,
            "from_function": from_function,
            "call_depth": new_depth
        },
        auto_parent=True  # Parents to current function
    )

    call_node_ids.append(node.id)

return {"call_nodes": call_node_ids}
```

**Node Metadata:**
- `target_function`: Called function name
- `target_file`: File containing target (if known)
- `from_function`: Caller
- `call_depth`: Current depth in call chain

---

### 4. track_sink_identified

**Purpose:** Mark a dangerous sink discovered during investigation

**Signature:**
```python
@tool("track_sink_identified", "Mark a dangerous sink discovered", {
    "sink_type": str,      # required
    "file_path": str,      # required
    "line_number": int,    # required
    "code_snippet": str,   # optional
})
async def track_sink_identified(args: dict[str, Any]) -> dict[str, Any]
```

**Parameters:**
- `sink_type` (required): Type of sink - "sql", "exec", "file_write", "deserialize", "ssrf", etc.
- `file_path` (required): File containing sink
- `line_number` (required): Line number of sink
- `code_snippet` (optional): Code showing the sink

**Returns:**
```json
{
  "content": [{"type": "text", "text": "{\"node_id\": \"sink123\", \"marked_dangerous\": true}"}],
  "isError": false
}
```

**Implementation:**
```python
sink_type = args["sink_type"]
file_path = args["file_path"]
line_number = args["line_number"]
code_snippet = args.get("code_snippet")

# Create dangerous_sink node
node = flow_service.add_node(
    agent_id,
    node_type="dangerous_sink",
    label=f"⚠️ {sink_type.upper()} sink",
    data={
        "sink_type": sink_type,
        "file_path": file_path,
        "line_number": line_number,
        "code_snippet": code_snippet,
        "severity": "high"  # Default severity
    },
    auto_parent=True  # Parents to current context
)

return {"node_id": node.id, "marked_dangerous": True}
```

**Node Metadata:**
- `sink_type`: SQL, exec, file_write, etc.
- `file_path`: Location
- `line_number`: Exact line
- `code_snippet`: Vulnerable code
- `severity`: Risk level

---

### 5. track_entry_point

**Purpose:** Mark an entry point discovered (API route, CLI arg, etc.)

**Signature:**
```python
@tool("track_entry_point", "Mark an entry point discovered", {
    "entry_type": str,     # required
    "file_path": str,      # required
    "line_number": int,    # required
    "route": str,          # optional
    "method": str,         # optional
})
async def track_entry_point(args: dict[str, Any]) -> dict[str, Any]
```

**Parameters:**
- `entry_type` (required): "api_route", "cli_arg", "form_handler", "websocket", "graphql_resolver"
- `file_path` (required): File containing entry point
- `line_number` (required): Line number
- `route` (optional): Route path (e.g., "/api/upload")
- `method` (optional): HTTP method (e.g., "POST")

**Returns:**
```json
{
  "content": [{"type": "text", "text": "{\"node_id\": \"entry123\"}"}],
  "isError": false
}
```

**Implementation:**
```python
entry_type = args["entry_type"]
file_path = args["file_path"]
line_number = args["line_number"]
route = args.get("route")
method = args.get("method")

# Create entry_point node
label = route if route else f"{entry_type} entry point"
if method:
    label = f"{method} {label}"

node = flow_service.add_node(
    agent_id,
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

**Node Metadata:**
- `entry_type`: Type of entry point
- `file_path`: Location
- `line_number`: Definition line
- `route`: Route/path (if applicable)
- `method`: HTTP method (if applicable)

---

## Flow Service Integration

### Context Management

Flow tracking tools automatically manage `FlowContext` to maintain proper tree structure:

**File Analysis Updates:**
```python
flow_service.update_context(
    agent_id,
    current_file=file_path,
    current_function=None,  # Reset when switching files
    call_depth=0            # Reset depth
)
```

**Function Discovery Updates:**
```python
flow_service.update_context(
    agent_id,
    current_function=function_name
)
```

**Call Chain Updates:**
```python
flow_service.update_context(
    agent_id,
    call_depth=context.call_depth + 1
)
```

### Auto-Parenting Logic

All tracking tools use `auto_parent=True` to automatically determine parent nodes:

- **file** nodes → parent to `investigation_root_id` (candidate node)
- **function** nodes → parent to current `file` node
- **call** nodes → parent to current `function` node
- **sink/entry_point** nodes → parent to current context (file or function)

This is handled by existing `add_node()` logic in `flow_service.py`.

### Depth Limiting

`track_call_chain` respects `max_call_depth` from context:

```python
if new_depth > context.max_call_depth:
    continue  # Skip this call, don't create node
```

Default `max_call_depth` is 3 (configurable per agent).

---

## Prompt Instrumentation

### Scanner Prompt Updates

Add to `prompting/agents/scanner_system_prompt.md` after "CRITICAL RULES" section:

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

### Analyzer Prompt Updates

Add similar FLOW TRACKING section to `prompting/agents/analyzer_system_prompt.md` with examples focused on deep analysis:

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
   - Track each function in the path
   - Use track_call_chain to show the flow
   - Mark the final sink with track_sink_identified

This creates a visual proof-of-concept showing how user input reaches dangerous code.
```

### Behavioral Changes

With these prompt updates:

- **Before:** Agent calls `read_file`, `search_code` → creates generic `tool_call` nodes
- **After:** Agent calls investigation tools + tracking tools → creates semantic `file`/`function`/`call`/`sink` nodes

**Example investigation flow:**
```
1. read_file("api/upload.py")
2. track_file_analysis("api/upload.py", "looking for upload handlers")
3. [reads code, finds handleUpload function]
4. track_function_discovered("handleUpload", line=23, reason="processes file uploads")
5. [analyzes function, sees it calls validateFile and saveToStorage]
6. track_call_chain(from_function="handleUpload", calls=[...])
7. [finds SQL query in saveToStorage]
8. track_sink_identified(sink_type="sql", file_path="storage.py", line=89)
```

**Result:** Rich semantic tree showing investigation path.

---

## Implementation Plan

### Phase 1: Add MCP Tools (Backend)

**File:** `backend/providers/mcp_tools.py`

**Steps:**
1. Add 5 new `@tool` decorated functions following existing pattern
2. Each tool:
   - Validates parameters
   - Calls appropriate `flow_service` methods
   - Returns success response with node IDs
3. Add to `_create_sdk_server()` function
4. Update `MCP_TOOLS` list for fallback mode

**Time estimate:** 2-3 hours

**Dependencies:** Existing flow_service API

### Phase 2: Add ToolCore Wrappers

**File:** `backend/services/tool_core.py`

**Steps:**
1. Add 5 new async methods wrapping flow_service calls
2. Extract `agent_id` from context (stored when ToolCore initialized)
3. Handle errors gracefully
4. Format responses for MCP

**Time estimate:** 1-2 hours

**Dependencies:** Phase 1 complete

### Phase 3: Update Agent Prompts

**Files:**
- `prompting/agents/scanner_system_prompt.md`
- `prompting/agents/analyzer_system_prompt.md`

**Steps:**
1. Add FLOW TRACKING section with instructions
2. Add concrete examples for each tool
3. Add behavioral guidance ("USE THESE TOOLS FREQUENTLY")
4. Test prompt rendering

**Time estimate:** 1 hour

**Dependencies:** None (can be done in parallel with Phase 1-2)

### Phase 4: Testing

**Files:**
- `backend/tests/providers/test_mcp_tools.py` (add tests)
- `backend/tests/integration/test_flow_tracking.py` (new file)

**Steps:**

**Unit Tests:**
```python
@pytest.mark.asyncio
async def test_track_file_analysis():
    tool_core = ToolCore(repo_path="/test", project_id="test-1")
    result = await tool_core.track_file_analysis(
        file_path="api/routes.py",
        purpose="looking for entry points"
    )

    flow = flow_service.get_flow("test-agent")
    file_nodes = [n for n in flow.nodes if n.type == "file"]
    assert len(file_nodes) == 1
    assert file_nodes[0].label == "api/routes.py"
    assert file_nodes[0].data["purpose"] == "looking for entry points"

@pytest.mark.asyncio
async def test_track_call_chain_respects_depth():
    tool_core = ToolCore(repo_path="/test", project_id="test-1")

    # Set max depth to 2
    flow_service.update_context("test-agent", max_call_depth=2, call_depth=0)

    # Track function
    await tool_core.track_function_discovered(
        function_name="foo",
        file_path="test.py",
        line_number=1
    )

    # Call at depth 1
    await tool_core.track_call_chain(
        from_function="foo",
        calls=[{"target": "bar"}]
    )

    # Call at depth 2
    await tool_core.track_call_chain(
        from_function="bar",
        calls=[{"target": "baz"}]
    )

    # Call at depth 3 (should be skipped)
    await tool_core.track_call_chain(
        from_function="baz",
        calls=[{"target": "qux"}]
    )

    flow = flow_service.get_flow("test-agent")
    call_nodes = [n for n in flow.nodes if n.type == "call"]
    assert len(call_nodes) == 2  # Only bar and baz, not qux
```

**Integration Tests:**
```python
@pytest.mark.asyncio
async def test_scanner_creates_semantic_flow(mock_agent):
    """Test that scanner with updated prompts creates semantic nodes."""

    # Run scanner on test repo
    agent = ReActSecurityAgent(...)
    await agent.run()

    # Verify flow tree structure
    flow = flow_service.get_flow(agent.id)

    # Should have file nodes (not just tool_call nodes)
    file_nodes = [n for n in flow.nodes if n.type == "file"]
    assert len(file_nodes) > 0

    # Should have function nodes
    function_nodes = [n for n in flow.nodes if n.type == "function"]
    assert len(function_nodes) > 0

    # Should have call nodes showing relationships
    call_nodes = [n for n in flow.nodes if n.type == "call"]
    assert len(call_nodes) > 0

    # Verify tree structure (functions parent to files)
    for func in function_nodes:
        parent_edge = next(e for e in flow.edges if e.target == func.id)
        parent_node = next(n for n in flow.nodes if n.id == parent_edge.source)
        assert parent_node.type == "file"
```

**Time estimate:** 3-4 hours

**Dependencies:** Phases 1-3 complete

### Phase 5: Visual Verification

**Steps:**
1. Run scanner on real repository
2. Open flow tree visualization in UI
3. Verify semantic tree shows:
   - File nodes with actual file paths
   - Function nodes under files
   - Call nodes showing function relationships
   - Sink/entry point nodes marked appropriately
4. Test collapse/expand, search with semantic nodes

**Time estimate:** 1 hour

**Dependencies:** All phases complete

---

## Testing Strategy

### Unit Tests

**Coverage targets:**
- Each MCP tool function (5 tests)
- Context updates (3 tests)
- Auto-parenting logic (3 tests)
- Depth limiting (2 tests)
- Error handling (5 tests)

**Total:** ~18 unit tests

### Integration Tests

**Scenarios:**
1. Scanner creates file → function → call tree
2. Analyzer adds sink nodes to existing tree
3. Call chain respects max depth limit
4. Multiple files tracked correctly
5. Entry points and sinks marked with proper metadata

**Total:** ~5 integration tests

### Manual Testing

**Checklist:**
- [ ] Run scanner on Python repo with API routes
- [ ] Verify file nodes created for examined files
- [ ] Verify function nodes show discovered handlers
- [ ] Verify call nodes show function relationships
- [ ] Verify sink nodes marked with ⚠️ icon
- [ ] Test flow tree collapse/expand with semantic nodes
- [ ] Test flow tree search filters (type:file, type:function)
- [ ] Verify keyboard shortcuts work
- [ ] Test with 50+ node tree (performance)

---

## Success Criteria

### Functional Requirements

✅ **Flow tracking tools implemented**
- All 5 MCP tools available to agents
- Tools properly integrated with flow_service
- Context tracking works correctly

✅ **Agent prompts updated**
- Scanner prompt includes FLOW TRACKING section with examples
- Analyzer prompt includes FLOW TRACKING section
- Agents naturally use tracking tools during investigation

✅ **Semantic flow tree created**
- Agents create file/function/call/sink nodes (not just tool_call)
- Tree structure reflects investigation path
- Parent-child relationships correct

✅ **UI displays meaningful tree**
- Flow visualization shows: 📁 file → 🔧 function → → call → ⚠️ sink
- Collapse/expand works with semantic nodes
- Search filters work (type:file, type:function, etc.)
- Keyboard shortcuts functional

### Non-Functional Requirements

✅ **Performance**
- No significant slowdown from tracking calls
- Flow tree renders smoothly with 100+ nodes

✅ **Reliability**
- Tracking tool failures don't break agent investigation
- Graceful degradation if flow_service unavailable

✅ **Maintainability**
- Code follows existing patterns
- Tests provide good coverage
- Documentation clear

---

## Risks & Mitigations

### Risk 1: Agent Forgets to Track

**Risk:** Agent uses investigation tools but forgets to call tracking tools.

**Likelihood:** Medium

**Mitigation:**
- Prompt explicitly says "USE THESE TOOLS FREQUENTLY"
- Include tracking tools in every example
- Consider adding reminder in analyzer handoff prompt
- Monitor real audits and adjust prompts based on behavior

### Risk 2: Too Many Tracking Calls

**Risk:** Agent calls tracking tools excessively, slowing down investigation.

**Likelihood:** Low

**Mitigation:**
- Tracking tools are fast (just add nodes to in-memory structure)
- Flow service already optimized for many nodes
- Monitor performance in testing

### Risk 3: Incorrect Tree Structure

**Risk:** Auto-parenting logic creates wrong relationships.

**Likelihood:** Low

**Mitigation:**
- Context tracking already works in existing flow service
- Comprehensive unit tests for parenting logic
- Integration tests verify tree structure

### Risk 4: SDK Tool Changes

**Risk:** Claude Agent SDK `@tool` decorator API changes.

**Likelihood:** Low

**Mitigation:**
- Already have fallback mode for testing without SDK
- Pin SDK version in requirements
- Tools follow existing patterns (low risk of breaking changes)

---

## Future Enhancements

**Not included in this design, potential future work:**

1. **Automatic inference from existing tools**
   - Middleware that auto-creates file nodes when `read_file` called
   - Would supplement (not replace) explicit tracking

2. **Cross-file visualization**
   - Show links between files based on imports/calls
   - "Jump to definition" from call nodes

3. **Time-based replay**
   - Show investigation tree building over time
   - Slider to replay agent's thought process

4. **Confidence scoring**
   - Agent indicates confidence in each node
   - Visual indicator in tree (opacity, color)

5. **LLM reasoning capture**
   - Agent adds reasoning for each tracked item
   - Hover tooltip shows why agent found it interesting

6. **Collaborative investigation**
   - Multiple agents working on same tree
   - See other agents' discoveries in real-time

---

## Appendix: Example Agent Behavior

### Before (Generic Tool Calls)

**Agent actions:**
```
1. read_file("api/routes.py")
2. search_code("@app.post")
3. read_file("db/queries.py")
4. search_code("cursor.execute")
```

**Flow tree shows:**
```
Start Investigation
  └─ tool_call: read_file
  └─ tool_call: search_code
  └─ tool_call: read_file
  └─ tool_call: search_code
```

**Problem:** No semantic meaning, just tool names.

---

### After (Semantic Tracking)

**Agent actions:**
```
1. read_file("api/routes.py")
2. track_file_analysis("api/routes.py", purpose="looking for API endpoints")
3. track_function_discovered("handleUpload", line=23, reason="file upload handler")
4. track_call_chain(from_function="handleUpload", calls=[{"target": "saveFile"}])
5. read_file("storage/s3.py")
6. track_file_analysis("storage/s3.py", purpose="tracing file save")
7. track_function_discovered("saveFile", line=45)
8. track_sink_identified(sink_type="path_traversal", file_path="storage/s3.py", line=89)
```

**Flow tree shows:**
```
Start Investigation
  └─ 📁 api/routes.py (looking for API endpoints)
      └─ 🔧 handleUpload (line 23) - file upload handler
          └─ → saveFile (storage/s3.py)
              └─ 📁 storage/s3.py (tracing file save)
                  └─ 🔧 saveFile (line 45)
                      └─ ⚠️ PATH_TRAVERSAL sink (line 89)
```

**Result:** Clear investigation path showing how agent found the vulnerability.

---

## References

- Flow Service API: `backend/services/flow_service.py`
- Existing MCP Tools: `backend/providers/mcp_tools.py`
- Flow Visualization: `docs/features/flow-tree-visualization.md`
- Scanner Prompt: `prompting/agents/scanner_system_prompt.md`
- Analyzer Prompt: `prompting/agents/analyzer_system_prompt.md`
