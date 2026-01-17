# Data Flow Visualization Design

**Date:** 2026-01-17
**Status:** Design Complete
**Author:** Claude (via brainstorming session)

## Overview

This design introduces a new visualization component that displays **data flow paths** in audited code, showing how user-controlled input flows from entry points through the application to dangerous sinks. This is distinct from the existing investigation trace visualization, which shows the agent's actions.

**Key Distinction:**
- **Existing TreeLayout/FlowVisualization**: "What is the agent doing?" (agent investigation trace)
- **New DataFlowDiagram**: "Where does user input flow in the target code?" (vulnerability paths)

## User Requirements

Based on user input, the system should:

1. **Visualize data flow paths** in the audited codebase (not agent investigation steps)
2. **Use graph structure** with entry point trees showing all paths
3. **Progressive reveal**: Current investigation path prominent, historical paths dimmed
4. **Color-code paths** by validation status (investigating, valid finding, false positive, mitigated)
5. **Rich interactivity**:
   - Click nodes to view code context
   - Expand/collapse branches
   - Hover to highlight complete paths
   - Filter by vulnerability type and status

## Architecture

### High-Level System Design

```
┌─────────────────────────────────────────────────────────────────┐
│                    Frontend (React + ReactFlow)                 │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           DataFlowDiagram Component                      │  │
│  │  - Entry point tree roots                                │  │
│  │  - Path rendering with color-coding                      │  │
│  │  - Progressive reveal + history                          │  │
│  │  - Interactive: hover, click, expand, filter             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓ WebSocket / REST                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Backend (FastAPI + Python)                   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │      DataFlowReconstructionService                       │  │
│  │  - Consume agent events (tool calls, findings)           │  │
│  │  - Build data flow graph incrementally                   │  │
│  │  - Track: entry points → transforms → sinks             │  │
│  │  - Validate paths (sanitization checks, auth gates)      │  │
│  │  - Emit graph updates via WebSocket                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           ↓                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         Existing Services Integration                    │  │
│  │  - code_graph_service: Entry points + call graph        │  │
│  │  - security_detectors: Sink pattern matching            │  │
│  │  - attack_surface_service: Entry point discovery        │  │
│  │  - reconstruction_service: Event routing                │  │
│  │  - strict_classifier: Path validation (triage)          │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model

### Core Data Structures (Backend)

```python
@dataclass
class DataFlowNode:
    """A node in the data flow graph."""
    node_id: str                    # Unique identifier
    node_type: str                  # "entry_point" | "function" | "transform" | "sanitizer" | "validator" | "sink"
    label: str                      # Display name
    file_path: str                  # Source file location
    line_number: Optional[int]      # Line in source file
    code_snippet: Optional[str]     # 10 lines before/after for popover
    vulnerability_type: Optional[str]  # "sql_injection" | "command_injection" | etc.
    is_dangerous: bool              # True if dangerous sink
    is_sanitizer: bool              # True if validates/sanitizes
    confidence: float               # 0.0-1.0 confidence
    discovered_at: str              # Timestamp
    metadata: Dict[str, Any]        # Additional context

@dataclass
class DataFlowEdge:
    """An edge representing data flowing between nodes."""
    edge_id: str
    source_node_id: str
    target_node_id: str
    variable_name: Optional[str]    # Variable carrying data
    transform_type: Optional[str]   # "passthrough" | "concat" | "format" | etc.
    label: Optional[str]
    style: str = "default"          # "solid" | "dashed" | "sanitized"

@dataclass
class DataFlowPath:
    """A complete path from entry point to sink."""
    path_id: str
    entry_point_id: str             # Starting node
    sink_node_id: str               # Ending node
    node_ids: List[str]             # Ordered list of nodes
    edge_ids: List[str]             # Edges connecting path
    status: PathStatus              # INVESTIGATING | VALID_FINDING | FALSE_POSITIVE | MITIGATED
    validation_reason: Optional[str]
    vulnerability_type: str
    severity: str                   # "critical" | "high" | "medium" | "low"
    discovered_at: str
    last_updated: str
    has_sanitization: bool
    has_validation: bool
    bypasses_auth: bool

class PathStatus(Enum):
    INVESTIGATING = "investigating"
    VALID_FINDING = "valid_finding"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"
    PENDING = "pending"

@dataclass
class DataFlowGraph:
    """Complete data flow graph for an audit session."""
    agent_id: str
    nodes: Dict[str, DataFlowNode]
    edges: Dict[str, DataFlowEdge]
    paths: Dict[str, DataFlowPath]
    entry_points: List[str]
    active_path_id: Optional[str]
    created_at: str
    last_updated: str
```

### Frontend Types (TypeScript)

```typescript
interface DataFlowNode {
  nodeId: string;
  nodeType: 'entry_point' | 'function' | 'transform' | 'sanitizer' | 'validator' | 'sink';
  label: string;
  filePath: string;
  lineNumber?: number;
  codeSnippet?: string;
  vulnerabilityType?: string;
  isDangerous: boolean;
  isSanitizer: boolean;
  confidence: number;
  discoveredAt: string;
  metadata: Record<string, any>;
}

interface DataFlowEdge {
  edgeId: string;
  sourceNodeId: string;
  targetNodeId: string;
  variableName?: string;
  transformType?: string;
  label?: string;
  style: 'solid' | 'dashed' | 'sanitized';
}

type PathStatus = 'investigating' | 'valid_finding' | 'false_positive' | 'mitigated' | 'pending';

interface DataFlowPath {
  pathId: string;
  entryPointId: string;
  sinkNodeId: string;
  nodeIds: string[];
  edgeIds: string[];
  status: PathStatus;
  validationReason?: string;
  vulnerabilityType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  discoveredAt: string;
  lastUpdated: string;
  hasSanitization: boolean;
  hasValidation: boolean;
  bypassesAuth: boolean;
}

interface DataFlowGraph {
  agentId: string;
  nodes: Record<string, DataFlowNode>;
  edges: Record<string, DataFlowEdge>;
  paths: Record<string, DataFlowPath>;
  entryPoints: string[];
  activePathId?: string;
  createdAt: string;
  lastUpdated: string;
}
```

### Event Integration

The backend builds the graph incrementally by consuming agent events:

```python
# Agent discovers entry point
{
  "type": "entry_point_discovered",
  "data": {
    "node_id": "ep_1",
    "route": "POST /api/users",
    "file": "routers/users.py",
    "line": 45
  }
}

# Agent discovers sink
{
  "type": "sink_discovered",
  "data": {
    "node_id": "sink_1",
    "sink_type": "sql_injection",
    "function": "cursor.execute()",
    "file": "services/db.py",
    "line": 128
  }
}

# Agent traces data flow
{
  "type": "dataflow_edge_found",
  "data": {
    "source_node_id": "ep_1",
    "target_node_id": "func_1",
    "variable": "user_input"
  }
}

# Agent completes path validation
{
  "type": "path_validated",
  "data": {
    "path_id": "path_1",
    "status": "valid_finding",
    "reason": "No sanitization between entry and sink"
  }
}
```

## Layout Algorithm

### Hierarchical Tree with Path-Based Grouping

The layout creates a tree rooted at entry points, with branches showing different data flow paths:

**Key Principles:**
1. Entry points at the left, arranged vertically
2. Horizontal flow left-to-right: Entry → Function → Sink
3. Vertical separation for branches when flow diverges
4. Node sharing where flows converge
5. Progressive reveal: Active path prominent, historical dimmed

**Algorithm Steps:**

```python
def compute_layout(graph, active_path_id):
    # Constants
    HORIZONTAL_SPACING = 350  # Space between depth levels
    VERTICAL_SPACING = 120    # Space between nodes at same depth
    ENTRY_POINT_SPACING = 200 # Extra space between entry point trees

    # Step 1: Assign depth (layer) to each node via BFS from entry points
    node_depths = assign_depths_via_bfs(graph)

    # Step 2: Layout each entry point tree separately
    positions = {}
    current_y = 0

    for entry_point_id in graph.entry_points:
        # Position entry point
        positions[entry_point_id] = Position(x=0, y=current_y)

        # Get paths from this entry point
        entry_paths = get_paths_from_entry(graph, entry_point_id)

        # Separate active from historical
        active_path = find_active_path(entry_paths, active_path_id)
        historical_paths = get_historical_paths(entry_paths, active_path_id)

        # Layout nodes depth by depth
        max_depth = get_max_depth(node_depths)
        subtree_max_y = current_y

        for depth in range(1, max_depth + 1):
            nodes_at_depth = get_nodes_at_depth(depth, node_depths, entry_point_id)

            # Sort: active path first, then historical
            nodes_at_depth.sort(by_path_priority)

            # Position vertically
            x = depth * HORIZONTAL_SPACING
            for i, node_id in enumerate(nodes_at_depth):
                y = current_y + i * VERTICAL_SPACING
                positions[node_id] = Position(x=x, y=y)
                subtree_max_y = max(subtree_max_y, y)

        # Move to next entry point
        current_y = subtree_max_y + ENTRY_POINT_SPACING

    return positions
```

### Progressive Reveal Visual Strategy

**Active Path (Currently Investigating):**
- Opacity: 100%
- Node size: Normal
- Edge width: 3px
- Glow effect: Subtle animated glow
- Color: Yellow border (investigating state)

**Historical Paths (Previously Explored):**
- Opacity: 40%
- Edge width: 2px
- No animation
- Color: Based on final status (green/red/blue/gray)

**Shared Nodes:**
- Use color from highest-priority path
- Show badge indicating node appears in multiple paths

## Visual Design

### Color Coding Scheme

**Path Status Colors:**

```typescript
const PATH_STATUS_COLORS = {
  investigating: {
    node: { border: '#facc15', background: '#fef3c7', glow: '0 0 10px rgba(250, 204, 21, 0.5)' },
    edge: { stroke: '#facc15', strokeWidth: 3, animated: true }
  },
  valid_finding: {
    node: { border: '#ef4444', background: '#fee2e2', glow: 'none' },
    edge: { stroke: '#ef4444', strokeWidth: 2.5, animated: false }
  },
  false_positive: {
    node: { border: '#6b7280', background: '#f3f4f6', glow: 'none' },
    edge: { stroke: '#9ca3af', strokeWidth: 1.5, animated: false }
  },
  mitigated: {
    node: { border: '#3b82f6', background: '#dbeafe', glow: 'none' },
    edge: { stroke: '#3b82f6', strokeWidth: 2, animated: false }
  },
  pending: {
    node: { border: '#9ca3af', background: '#f9fafb', glow: 'none' },
    edge: { stroke: '#d1d5db', strokeWidth: 1.5, animated: false, style: 'dashed' }
  }
};
```

**Node Type Indicators:**

- **Entry Point**: 🚪 Green (ArrowRight icon)
- **Function**: ⚙️ Purple (Code icon)
- **Transform**: 🔄 Blue (RefreshCw icon)
- **Sanitizer**: 🛡️ Green hexagon (Shield icon) + checkmark badge
- **Validator**: ✅ Green hexagon (CheckCircle icon) + checkmark badge
- **Sink**: ⚠️ Red diamond (AlertTriangle icon) + pulsate animation

**Edge Styles:**

- **Default**: Solid line, smoothstep curve
- **Sanitized**: Green solid line with 🛡️ label
- **Tentative**: Dashed line with ? label

## Interactive Features

### 1. Node Click - Code Context Popover

Clicking a node opens a popover displaying:
- Node label and type
- File location with line number
- Code snippet (10 lines context)
- Vulnerability type (if applicable)
- Dangerous sink / Sanitizer indicators
- Confidence score
- List of paths containing this node
- Actions: "Open in Editor", "View Call Graph"

### 2. Hover - Path Highlighting

Hovering over any node:
- Finds all paths containing the node
- Highlights the highest-priority path
- Dims non-highlighted nodes to 30% opacity
- Scales highlighted nodes to 1.05x
- Smooth 0.2s transition

### 3. Expand/Collapse Branches

- Chevron button on path nodes
- Collapsed paths show only entry point and sink
- Preserves path state across re-renders
- Visual indicator shows descendant count

### 4. Filter by Vulnerability Type & Status

Filter toolbar provides:
- **Vulnerability Type filters**: SQL injection, XSS, Command injection, etc.
- **Path Status filters**: Investigating, Valid finding, Mitigated, False positive
- **Multi-select**: Enable/disable multiple filters
- **Quick actions**: Show All, Clear
- **Active filter badge**: Shows count of active filters

## Backend Implementation

### DataFlowReconstructionService

```python
class DataFlowReconstructionService:
    """Reconstructs data flow graphs from agent events."""

    async def initialize_graph(self, agent_id: str, repo_path: str) -> DataFlowGraph:
        """Initialize empty graph."""

    async def process_event(self, agent_id: str, event: Dict) -> Optional[DataFlowGraph]:
        """Process agent event and update graph."""
        # Route to handlers:
        # - entry_point_discovered
        # - sink_discovered
        # - function_analyzed
        # - dataflow_edge_found
        # - path_validated
        # - sanitizer_detected
        # - tool_result (auto-extraction)

    def _handle_entry_point_discovered(self, graph, data):
        """Add entry point node."""

    def _handle_sink_discovered(self, graph, data):
        """Add dangerous sink node."""

    def _handle_dataflow_edge(self, graph, data):
        """Add edge and update paths."""

    def _update_paths(self, graph, new_edge):
        """Trace backward from sinks to construct complete paths."""

    async def _detect_sinks_in_content(self, graph, file_path, content):
        """Auto-detect sinks using pattern matching."""

    async def _detect_entry_points_in_content(self, graph, file_path, content):
        """Auto-detect entry points (routes, CLI args)."""
```

### Real-Time Updates via WebSocket

```python
# WebSocket subscription
{
  "type": "subscribe_dataflow",
  "agent_id": "agent_123"
}

# Server broadcasts updates
{
  "type": "dataflow_graph_update",
  "data": {
    "agent_id": "agent_123",
    "graph": { /* serialized DataFlowGraph */ },
    "timestamp": "2026-01-17T12:00:00Z"
  }
}
```

**Update Batching:** Rapid updates are batched (200ms interval) to reduce WebSocket traffic.

### REST API Endpoints

```python
# Get current graph
GET /api/dataflow/{agent_id}

# Get paths with filtering
GET /api/dataflow/{agent_id}/paths?status=valid_finding&vulnerability_type=sql_injection

# Get node details
GET /api/dataflow/{agent_id}/nodes/{node_id}
```

### Performance Considerations

1. **Incremental Updates**: Graph built incrementally, no full reconstruction
2. **Efficient Path Finding**: Backward BFS from sinks with cycle detection
3. **WebSocket Throttling**: 200ms batching interval
4. **Graph Size Limits**:
   - Max 1000 nodes per graph
   - Max 5000 edges per graph
   - Prune least relevant nodes if exceeded

## Frontend Implementation

### Component Structure

```
DataFlowDiagram (main component)
├── FilterToolbar (vulnerability type & status filters)
├── ReactFlow canvas
│   └── DataFlowNodeComponent (custom node renderer)
├── NodePopover (code context on click)
├── PathLegend (visual legend)
└── StatsPanel (graph statistics)
```

### Main Component Features

- **State management**: Nodes, edges, filters, hover/selection state
- **WebSocket integration**: Subscribe to real-time updates
- **Layout computation**: useDataFlowLayout hook
- **Filter logic**: Apply vulnerability type and status filters
- **Visibility calculation**: Show/hide nodes based on collapsed state and filters
- **Event handlers**: Click, hover, pane click

### Custom Node Component

Renders nodes with:
- Icon based on node type
- Color based on path status
- Path count badge (if node in multiple paths)
- Vulnerability type display
- Confidence score
- Pulsate animation for dangerous sinks
- Active path indicator dot

## Integration

### Project Workspace Page Integration

Add tab switcher to project workspace:

```typescript
<div className="flex gap-2">
  <button onClick={() => setTab('investigation')}>
    Investigation Trace
  </button>
  <button onClick={() => setTab('dataflow')}>
    Data Flow Analysis
  </button>
</div>

{selectedTab === 'investigation' ? (
  <TreeLayout /* existing */ />
) : (
  <DataFlowDiagram agentId={agentId} projectId={projectId} />
)}
```

### Agent Orchestrator Integration

Emit data flow events during agent execution:

```python
# After tool result processing
await dataflow_reconstruction_service.process_event(
    agent_id=agent_id,
    event={"type": "tool_result", "data": tool_result}
)

# Broadcast updated graph
graph = dataflow_reconstruction_service.get_graph(agent_id)
if graph:
    await broadcast_dataflow_update(agent_id, graph)
```

## Database Schema (Optional Persistence)

```sql
CREATE TABLE dataflow_graphs (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL UNIQUE,
    graph_data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_dataflow_graphs_agent_id ON dataflow_graphs(agent_id);
CREATE INDEX idx_dataflow_graphs_updated_at ON dataflow_graphs(updated_at);
```

## Testing Strategy

### Unit Tests

**Backend:**
- Test graph initialization
- Test event processing (entry points, sinks, edges, paths)
- Test path construction from entry to sink
- Test auto-detection of sinks and entry points
- Test path validation status updates

**Frontend:**
- Test empty states (no agent, no data)
- Test graph rendering with mock data
- Test node click popover
- Test hover highlighting
- Test filter functionality
- Test collapse/expand

### Integration Tests

- Test REST API endpoints
- Test WebSocket subscription and updates
- Test end-to-end flow: agent event → graph update → frontend display

### Performance Tests

- Test with large graphs (1000 nodes, 5000 edges)
- Test layout algorithm performance
- Test WebSocket update latency

## File Structure

```
frontend/components/DataFlowDiagram/
├── DataFlowDiagram.tsx              # Main component
├── DataFlowNodeComponent.tsx        # Custom node renderer
├── NodePopover.tsx                  # Node detail popover
├── FilterToolbar.tsx                # Filter UI
├── PathLegend.tsx                   # Visual legend
├── StatsPanel.tsx                   # Statistics display
├── useDataFlowLayout.ts             # Layout algorithm hook
├── types.ts                         # TypeScript types
├── index.ts                         # Exports
└── README.md                        # Component documentation

backend/services/
├── dataflow_reconstruction_service.py  # New service

backend/routers/
├── dataflow.py                         # New API router

backend/tests/services/
├── test_dataflow_reconstruction.py     # Service tests

backend/tests/integration/
├── test_dataflow_visualization.py      # Integration tests

frontend/components/DataFlowDiagram/__tests__/
├── DataFlowDiagram.test.tsx           # Component tests
```

## Implementation Timeline

### Phase 1: Backend Foundation (Week 1)
- Create DataFlowReconstructionService
- Add data flow models
- Implement event processing
- Add API endpoints
- Write unit tests

### Phase 2: Frontend Components (Week 2)
- Create TypeScript types
- Implement DataFlowDiagram main component
- Build DataFlowNodeComponent
- Add NodePopover, FilterToolbar, PathLegend, StatsPanel
- Implement layout algorithm hook

### Phase 3: Integration (Week 3)
- Integrate with project workspace page
- Connect WebSocket updates
- Add event emission to agent orchestrator
- Test end-to-end flow

### Phase 4: Polish & Testing (Week 4)
- Add database persistence
- Write integration tests
- Performance optimization
- Documentation
- User acceptance testing

## Success Criteria

1. **Functional**: All data flow paths from entry points to sinks are visualized correctly
2. **Real-time**: Updates appear within 500ms of agent discovery
3. **Interactive**: All interactions (click, hover, filter, collapse) work smoothly
4. **Performance**: Handles graphs with 500+ nodes without lag
5. **Visual Clarity**: Active vs. historical paths are clearly distinguished
6. **Accurate**: Auto-detected sinks and entry points have >80% precision

## Future Enhancements

1. **Path Comparison**: Side-by-side comparison of multiple paths
2. **Path Export**: Export paths to report format (PDF, JSON)
3. **Path Replay**: Step-by-step animation of data flow
4. **Code Editing**: Edit code directly from popover to fix vulnerabilities
5. **AI-Powered Suggestions**: Suggest sanitization points
6. **Integration with Call Graph**: Show call graph overlay on data flow
7. **Multi-Agent Comparison**: Compare data flows across different agents

## Conclusion

This design provides a comprehensive data flow visualization system that tracks actual vulnerability paths in audited code. By visualizing how user input flows from entry points through transformations to dangerous sinks, security auditors gain clear insight into potential vulnerabilities. The progressive reveal approach keeps focus on current investigation while preserving historical context, and the rich interactivity enables deep exploration of discovered paths.
