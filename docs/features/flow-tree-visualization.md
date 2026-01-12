# Flow Tree Visualization

Real-time visualization of investigation flow as an interactive tree.

## Features

### 1. Call Tracing with Configurable Depth

The flow service automatically tracks function calls during investigation:

- **Max depth**: Configurable via `FlowContext.max_call_depth` (default: 3)
- **Call nodes**: Created when LLM analysis mentions function calls
- **Cross-file tracing**: Automatically creates file nodes when calls span files

**Usage:**
```python
flow_service.update_context(
    agent_id="agent-1",
    call_depth=0,          # Current depth
    max_call_depth=5       # Increase limit for deeper tracing
)
```

### 2. Multi-Language Function Extraction

Supports Python, JavaScript, TypeScript, Go, and Rust:

**TypeScript Support:**
- Arrow functions: `const handleRequest = () => {}`
- Class methods: `class Foo { handleRequest() {} }`
- Decorated methods: `@route('/api') async handleUpload() {}`
- Interface methods: `interface Handler { process(): void }`

**Go Support:**
- Functions: `func handleRequest() {}`
- Methods: `func (h *Handler) Process() {}`

**Rust Support:**
- Functions: `fn handle_request() {}`
- Methods: `impl Handler { fn process(&self) {} }`

### 3. Collapsible Subtrees

Click the chevron button on any node with children to collapse/expand:

- **Expand indicator**: ▶ with count badge (+5)
- **Collapse indicator**: ▼
- **Default state**: All expanded
- **Hidden descendants**: Dimmed in minimap

### 4. Unified Search & Filter

Search box supports type prefixes and wildcards:

**Syntax:**
| Query | Effect |
|-------|--------|
| `type:file` | Show only file nodes |
| `type:function` | Show only function nodes |
| `type:call` | Show only call nodes |
| `function:handle*` | Function names matching pattern |
| `api.py` | Fuzzy match in labels |
| `type:file routes` | Multiple filters (AND logic) |

**Examples:**
- Find all files: `type:file`
- Find functions starting with "handle": `function:handle*`
- Find file containing "routes": `type:file routes`

### 5. Search Highlighting

- **Matches**: Yellow border (2px)
- **Non-matches**: 30% opacity (dimmed)
- **Ancestors**: Always visible (maintains path from root)

## Flow Tracking Tools

Agents use these MCP tools to build the investigation tree during security audits. These tools create semantic nodes instead of generic tool_call nodes.

### track_file_analysis

Record a file being analyzed during investigation:

```python
track_file_analysis(
    file_path="api/routes.py",
    purpose="looking for entry points"
)
```

**Creates:** File node (📁) in the tree under the current investigation root.

**Use case:** Called when an agent begins analyzing a file to understand its structure or find vulnerabilities.

### track_function_discovered

Record an interesting function found during analysis:

```python
track_function_discovered(
    function_name="handleUpload",
    file_path="api/routes.py",
    line_number=45,
    signature="async def handleUpload(request, file)",
    reason="handles file uploads without validation"
)
```

**Creates:** Function node (🔧) under the file node.

**Use case:** Called when an agent identifies a function that's relevant to the investigation (e.g., processes user input, calls dangerous sinks, or is part of an attack path).

### track_call_chain

Record a function call sequence to trace execution flow:

```python
track_call_chain(
    from_function="handleUpload",
    calls=[
        {"target": "validateFile", "file": "validators.py", "line": 23},
        {"target": "saveToStorage", "file": "storage.py", "line": 89}
    ]
)
```

**Creates:** Call nodes (→) showing the execution flow from one function to others.

**Respects:** `max_call_depth` setting (default: 3) to prevent infinite expansion.

**Use case:** Called when an agent traces how data flows through multiple functions, especially when tracking user input to dangerous sinks.

### track_sink_identified

Mark a dangerous sink that could be exploited:

```python
track_sink_identified(
    sink_type="sql",
    file_path="db/queries.py",
    line_number=89,
    code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
    severity="high"
)
```

**Creates:** Dangerous sink node (⚠️) marked with severity level.

**Sink types:** `sql`, `command`, `path_traversal`, `code_eval`, `deserialization`, `xxe`, `ldap`, `nosql`

**Use case:** Called when an agent identifies a dangerous operation that could be exploited if attacker-controlled data reaches it.

### track_entry_point

Mark an entry point where external data enters the system:

```python
track_entry_point(
    entry_type="api_route",
    file_path="api/routes.py",
    line_number=45,
    route="/api/upload",
    method="POST",
    params=["file", "metadata"]
)
```

**Creates:** Entry point node (🚪) showing where attackers can inject data.

**Entry types:** `api_route`, `webhook`, `cli_arg`, `env_var`, `file_upload`, `websocket`

**Use case:** Called when an agent identifies how external/untrusted data enters the application.

## Agent Instrumentation

Scanner and analyzer agents are instructed via their system prompts to use these tools during investigation. This creates semantic flow trees that show:

- **Investigation structure**: Files → Functions → Calls
- **Security findings**: Entry points → Data flow → Dangerous sinks
- **Attack paths**: Complete chains from entry point to exploitable sink

The flow tree replaces generic "LLM Interaction" nodes with meaningful investigation semantics, making it easier to understand what the agent discovered and how.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Cmd/Ctrl + F | Focus search box |
| Cmd/Ctrl + G | Next match |
| Cmd/Ctrl + Shift + G | Previous match |
| Escape | Clear search |

## Performance Optimizations

- **Debounced search**: 300ms delay prevents excessive re-renders
- **Edge caching**: O(1) lookups for descendants/ancestors
- **Memoization**: Expensive calculations cached with `useMemo`

Tested with 500+ node trees without performance degradation.

## API Reference

### FlowContext

```python
@dataclass
class FlowContext:
    current_file: Optional[str]
    current_function: Optional[str]
    current_candidate_node_id: Optional[str]
    investigation_root_id: Optional[str]
    call_depth: int = 0              # Current depth in call chain
    max_call_depth: int = 3          # Configurable limit
```

### Node Types

- `file` - File being investigated
- `function` - Function definition
- `call` - Function call edge
- `external` - External dependency
- `auth_boundary` - Authentication check
- `dangerous_sink` - Security sink (SQL, file I/O, etc.)
- (existing types: `user_input`, `tool_call`, `analysis`, etc.)

## Usage Example

```python
from backend.services.flow_service import flow_service

# Initialize flow
flow = flow_service.initialize_flow("agent-1")

# Update context for call tracing
flow_service.update_context(
    "agent-1",
    current_file="api/routes.py",
    current_function="handleRequest",
    max_call_depth=5
)

# Add function node
node = flow_service.add_node(
    "agent-1",
    node_type="function",
    label="handleRequest",
    data={"function_name": "handleRequest", "signature": "def handleRequest(data):"},
    auto_parent=True  # Automatically parent to current file
)

# Subscribe to updates (for real-time UI)
def on_flow_update(flow_dict):
    print(f"Flow updated: {len(flow_dict['nodes'])} nodes")

unsubscribe = flow_service.subscribe("agent-1", on_flow_update)
```
