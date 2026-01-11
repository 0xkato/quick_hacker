# Flow Service - Tree Structure

## Overview

The Flow Service tracks investigation progress as a hierarchical tree showing:
- File structure of audited codebase
- Functions within files
- Call paths across files
- Parallel investigation threads

## Architecture

### Tree Structure

```
Scan Root
├─ Candidate 1 (Entry Point/Sink)
│  ├─ File A
│  │  ├─ Function foo()
│  │  │  └─ Call → bar()
│  │  └─ Function baz()
│  └─ File B
│     └─ Function bar()
└─ Candidate 2 (Entry Point/Sink)
   └─ File C
      └─ Function qux()
```

### Node Types

**Architectural Nodes:**
- `file`: File being investigated
- `function`: Function/method definition
- `call`: Function call (branches to target)
- `external`: External library call
- `auth_boundary`: Auth check

**Investigation Nodes:**
- `entry_point`: Entry point found by triage
- `dangerous_sink`: Dangerous sink found
- `investigation`: Investigation action
- `finding`: Validated security finding

### Context Tracking

`FlowContext` maintains investigation state:
- `current_file`: File currently being read
- `current_function`: Function being analyzed
- `current_candidate_node_id`: Root of current investigation tree
- `investigation_root_id`: For multi-threaded investigations

## Usage

### Creating Investigation Trees

```python
from services.flow_service import flow_service

# Initialize
flow_service.initialize_flow(agent_id)

# Create scan root
scan = flow_service.add_node(agent_id, "scan", "Attack Surface Scan", {})

# Create candidate (starts new tree)
candidate = flow_service.add_node(
    agent_id,
    "entry_point",
    "POST /api/upload",
    {"file_path": "routes/api.py"},
    parent_id=scan.id,
    set_current=False
)

# Set context for this investigation
flow_service.update_context(
    agent_id,
    current_candidate_node_id=candidate.id
)

# Create file node (auto-parents to candidate)
file_node = flow_service.add_node(
    agent_id,
    "file",
    "api.py",
    {"file_path": "routes/api.py"},
    auto_parent=True,
    set_current=False
)

# Update context
flow_service.update_context(agent_id, current_file="routes/api.py")

# Create function node (auto-parents to file)
func_node = flow_service.add_node(
    agent_id,
    "function",
    "handle_upload()",
    {"function_name": "handle_upload"},
    auto_parent=True,
    set_current=False
)
```

### Auto-Parent Logic

When `auto_parent=True`:
- `file` nodes → parent to `current_candidate_node_id`
- `function` nodes → parent to current file node
- `call` nodes → parent to `current_node_id`

Explicit `parent_id` always overrides auto-parent.

### File Node Deduplication

Use `get_or_create_file_node()` to avoid duplicate file nodes:

```python
file_node = flow_service.get_or_create_file_node(agent_id, file_path)
if not file_node:
    # Create new file node
    file_node = flow_service.add_node(...)
```

## Frontend Integration

The FlowVisualization component:
1. Calculates subtree widths
2. Positions multiple trees horizontally
3. Centers parent nodes over children
4. Uses colored icons for node types

See `frontend/components/FlowVisualization/FlowVisualization.tsx`

## Testing

Run tests:
```bash
cd backend
pytest tests/services/test_flow_service.py -v
pytest tests/integration/test_flow_tree_structure.py -v
```
