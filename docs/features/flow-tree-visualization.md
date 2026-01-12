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
