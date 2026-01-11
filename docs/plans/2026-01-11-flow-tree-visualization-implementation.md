# Flow Tree Visualization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform linear flow visualization into multi-tree architectural view showing file structure, code paths, and parallel investigation threads.

**Architecture:** Add context tracking to FlowService backend to maintain parent-child relationships based on investigation scope (file → function → call). Modify agent tool execution to create architectural nodes. Update frontend layout algorithm to calculate subtree widths and position multiple investigation trees horizontally without overlap.

**Tech Stack:** Python 3.10 (FastAPI, Pydantic), React/TypeScript (ReactFlow), pytest, Playwright

---

## Task 1: Backend - Add FlowContext Data Structure

**Files:**
- Modify: `backend/services/flow_service.py:1-50`
- Test: `backend/tests/services/test_flow_service.py` (create)

**Step 1: Write the failing test**

Create test file:

```python
"""Tests for flow service context tracking."""
from services.flow_service import FlowService, FlowContext, InvestigationFlow


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
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py::test_flow_context_initialization -v`

Expected: FAIL with "cannot import name 'FlowContext'"

**Step 3: Add FlowContext to flow_service.py**

Add after imports (around line 12):

```python
@dataclass
class FlowContext:
    """Tracks investigation context for proper tree branching."""
    current_file: Optional[str] = None
    current_function: Optional[str] = None
    current_candidate_node_id: Optional[str] = None
    investigation_root_id: Optional[str] = None
```

Modify InvestigationFlow class (around line 62):

```python
@dataclass
class InvestigationFlow:
    session_id: str
    nodes: list[FlowNode] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)
    current_node_id: Optional[str] = None
    context: FlowContext = field(default_factory=FlowContext)  # ADD THIS LINE
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py::test_flow_context_initialization tests/services/test_flow_service.py::test_investigation_flow_has_context -v`

Expected: PASS (2 tests)

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/flow-tree-visualization
git add backend/services/flow_service.py backend/tests/services/test_flow_service.py
git commit -m "feat(flow): add FlowContext for investigation tracking

Add FlowContext dataclass to track current file, function, and candidate
node during investigation. Include context in InvestigationFlow.

This enables proper parent-child relationships in the tree structure."
```

---

## Task 2: Backend - Add New Architectural Node Types

**Files:**
- Modify: `backend/services/flow_service.py:15-27`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Write the failing test**

Add to test file:

```python
from services.flow_service import flow_service


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
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py::test_create_file_node -v`

Expected: FAIL with type error or validation error

**Step 3: Add new node types**

Modify NodeType definition (around line 15):

```python
NodeType = Literal[
    # Existing
    "user_input",
    "tool_call",
    "tool_result",
    "analysis",
    "finding",
    "code_read",
    "search",
    "scan",
    "entry_point",
    "dangerous_sink",
    "investigation",
    # NEW architectural nodes
    "file",
    "function",
    "call",
    "external",
    "auth_boundary",
]
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py::test_create_file_node tests/services/test_flow_service.py::test_create_function_node tests/services/test_flow_service.py::test_create_call_node -v`

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/services/flow_service.py backend/tests/services/test_flow_service.py
git commit -m "feat(flow): add architectural node types

Add file, function, call, external, auth_boundary node types to support
architectural tree structure. Enables visualization of codebase structure
and execution paths."
```

---

## Task 3: Backend - Add update_context Method

**Files:**
- Modify: `backend/services/flow_service.py:77-120`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Write the failing test**

Add to test file:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py::test_update_context_file -v`

Expected: FAIL with "FlowService has no attribute 'update_context'"

**Step 3: Add update_context method**

Add to FlowService class (after get_flow method, around line 90):

```python
def update_context(
    self,
    agent_id: str,
    *,
    current_file: Optional[str] = None,
    current_function: Optional[str] = None,
    current_candidate_node_id: Optional[str] = None,
    investigation_root_id: Optional[str] = None,
) -> None:
    """Update investigation context for proper tree branching."""
    flow = self._flows.get(agent_id)
    if not flow:
        return

    if current_file is not None:
        flow.context.current_file = current_file
    if current_function is not None:
        flow.context.current_function = current_function
    if current_candidate_node_id is not None:
        flow.context.current_candidate_node_id = current_candidate_node_id
    if investigation_root_id is not None:
        flow.context.investigation_root_id = investigation_root_id
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py -k "update_context" -v`

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/services/flow_service.py backend/tests/services/test_flow_service.py
git commit -m "feat(flow): add context update method

Add update_context() to FlowService for tracking investigation state.
Preserves existing context fields when updating individual fields."
```

---

## Task 4: Backend - Add get_or_create_file_node Method

**Files:**
- Modify: `backend/services/flow_service.py:120-150`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Write the failing test**

Add to test file:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py::test_get_or_create_file_node_creates_new -v`

Expected: FAIL with "FlowService has no attribute 'get_or_create_file_node'"

**Step 3: Add get_or_create_file_node method**

Add to FlowService class (after update_context, around line 110):

```python
def get_or_create_file_node(
    self,
    agent_id: str,
    file_path: str,
) -> Optional[FlowNode]:
    """Get existing file node or return None (let caller create it).

    Returns:
        FlowNode if file already has a node, None otherwise
    """
    flow = self._flows.get(agent_id)
    if not flow:
        return None

    # Check if we already have a node for this file
    for node in flow.nodes:
        if node.type == "file" and node.data.get("file_path") == file_path:
            return node

    return None
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py -k "get_or_create_file_node" -v`

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/services/flow_service.py backend/tests/services/test_flow_service.py
git commit -m "feat(flow): add file node lookup method

Add get_or_create_file_node() to prevent duplicate file nodes.
Returns existing node if file already in tree, None otherwise."
```

---

## Task 5: Backend - Add Auto-Parent Logic to add_node

**Files:**
- Modify: `backend/services/flow_service.py:94-145`
- Test: `backend/tests/services/test_flow_service.py`

**Step 1: Write the failing test**

Add to test file:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py::test_add_node_auto_parent_file_to_candidate -v`

Expected: FAIL - test expects auto-parent behavior but current code doesn't support it

**Step 3: Modify add_node method**

Update add_node signature and logic (around line 94):

```python
def add_node(
    self,
    agent_id: str,
    node_type: NodeType,
    label: str,
    data: Optional[dict] = None,
    *,
    parent_id: Optional[str] = None,
    edge_label: Optional[str] = None,
    llm_reasoning: Optional[str] = None,
    code_context: Optional[str] = None,
    tool_result_summary: Optional[str] = None,
    confidence_score: Optional[float] = None,
    set_current: bool = True,
    auto_parent: bool = False,  # NEW PARAMETER
) -> FlowNode:
    """Add a node to the flow."""
    flow = self._flows.get(agent_id)
    if not flow:
        flow = self.initialize_flow(agent_id)

    # Determine parent based on context if not explicitly provided
    if parent_id is None and auto_parent:
        if node_type == "file":
            # Files are children of investigation root (candidate)
            parent_id = flow.context.current_candidate_node_id
        elif node_type == "function":
            # Functions are children of current file
            if flow.context.current_file:
                file_node = self.get_or_create_file_node(agent_id, flow.context.current_file)
                parent_id = file_node.id if file_node else flow.context.current_candidate_node_id
        elif node_type == "call":
            # Calls are children of current function/node
            parent_id = flow.current_node_id
        # else: keep parent_id as None, will use flow.current_node_id below

    previous_node_id = parent_id or flow.current_node_id

    # Rest of existing implementation continues unchanged...
```

**Step 4: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/services/test_flow_service.py -k "auto_parent" -v`

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/services/flow_service.py backend/tests/services/test_flow_service.py
git commit -m "feat(flow): add auto-parent logic to add_node

Add auto_parent parameter to add_node() that uses context to determine
parent node:
- file nodes → candidate node
- function nodes → current file node
- call nodes → current function/node

Explicit parent_id still takes precedence over auto-parent."
```

---

## Task 6: Frontend - Add Multi-Tree Layout Algorithm

**Files:**
- Modify: `frontend/components/FlowVisualization/FlowVisualization.tsx:530-595`
- Test: Manual verification (add Playwright test in Task 7)

**Step 1: Create backup of current function**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/flow-tree-visualization/frontend/components/FlowVisualization
cp FlowVisualization.tsx FlowVisualization.tsx.backup
```

**Step 2: Replace calculateLayout function**

Replace the entire calculateLayout function (lines 531-595) with:

```typescript
/**
 * Calculate positions for multiple investigation trees with no overlap.
 */
function calculateLayout(
  nodes: FlowNode[],
  edges: FlowEdge[]
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();

  if (nodes.length === 0) return positions;

  // Build adjacency lists
  const children = new Map<string, string[]>();
  const parents = new Map<string, string[]>();

  for (const edge of edges) {
    if (!children.has(edge.source)) children.set(edge.source, []);
    children.get(edge.source)!.push(edge.target);

    if (!parents.has(edge.target)) parents.set(edge.target, []);
    parents.get(edge.target)!.push(edge.source);
  }

  // Find root nodes (each starts an investigation tree)
  const roots = nodes.filter(n =>
    !parents.has(n.id) || parents.get(n.id)!.length === 0
  );

  // Layout constants
  const TREE_HORIZONTAL_SPACING = 400;
  const NODE_WIDTH = 220;
  const NODE_HEIGHT = 100;

  let currentXOffset = 0;

  // Layout each tree separately
  for (const root of roots) {
    const subtreeWidth = calculateSubtreeWidth(root.id, children, NODE_WIDTH);

    layoutSubtree(
      root.id,
      children,
      positions,
      currentXOffset,
      0,
      NODE_WIDTH,
      NODE_HEIGHT
    );

    currentXOffset += subtreeWidth + TREE_HORIZONTAL_SPACING;
  }

  return positions;
}

/**
 * Calculate width needed for a subtree.
 */
function calculateSubtreeWidth(
  nodeId: string,
  children: Map<string, string[]>,
  nodeWidth: number
): number {
  const childIds = children.get(nodeId) || [];

  if (childIds.length === 0) {
    return nodeWidth;
  }

  // Subtree width is sum of all children's subtree widths
  const childrenWidth = childIds.reduce((sum, childId) => {
    return sum + calculateSubtreeWidth(childId, children, nodeWidth);
  }, 0);

  return Math.max(nodeWidth, childrenWidth);
}

/**
 * Recursively layout a subtree.
 */
function layoutSubtree(
  nodeId: string,
  children: Map<string, string[]>,
  positions: Map<string, { x: number; y: number }>,
  x: number,
  depth: number,
  nodeWidth: number,
  nodeHeight: number
): number {
  const childIds = children.get(nodeId) || [];

  if (childIds.length === 0) {
    // Leaf node
    positions.set(nodeId, { x, y: depth * nodeHeight });
    return nodeWidth;
  }

  // Layout children left-to-right
  let currentChildX = x;
  const childCenters: number[] = [];

  for (const childId of childIds) {
    const childWidth = layoutSubtree(
      childId,
      children,
      positions,
      currentChildX,
      depth + 1,
      nodeWidth,
      nodeHeight
    );

    // Store center position of this child
    childCenters.push(currentChildX + childWidth / 2);
    currentChildX += childWidth;
  }

  // Position parent centered over children
  const leftmost = childCenters[0];
  const rightmost = childCenters[childCenters.length - 1];
  const centerX = (leftmost + rightmost) / 2;

  positions.set(nodeId, { x: centerX, y: depth * nodeHeight });

  // Return total width used by this subtree
  return currentChildX - x;
}
```

**Step 3: Test in browser**

Run: `cd frontend && npm run dev`

Open browser to the flow visualization page and verify:
- Multiple investigation trees appear side-by-side
- No overlapping nodes
- Trees with more branches get more horizontal space

**Step 4: Commit**

```bash
git add frontend/components/FlowVisualization/FlowVisualization.tsx
git commit -m "feat(ui): add multi-tree layout algorithm

Replace simple BFS layout with hierarchical tree layout:
- Calculate subtree widths to prevent overlap
- Position multiple investigation trees horizontally
- Center parent nodes over children
- Each tree gets appropriate horizontal space"
```

---

## Task 7: Frontend - Add Icons for New Node Types

**Files:**
- Modify: `frontend/components/FlowVisualization/FlowVisualization.tsx:90-105`
- Modify: `frontend/components/FlowVisualization/FlowVisualization.tsx:393-445`

**Step 1: Add new imports**

Add to import section (around line 18):

```typescript
import {
  Search,
  FileText,
  AlertTriangle,
  Code,
  MessageSquare,
  Loader2,
  CheckCircle,
  XCircle,
  Brain,
  Scan,
  Network,
  ArrowRight,    // NEW
  ExternalLink,  // NEW
  Shield,        // NEW
} from 'lucide-react';
```

**Step 2: Add icons to typeIcons object**

Update typeIcons (around line 90):

```typescript
const typeIcons: Record<string, React.ReactNode> = {
  user_input: <MessageSquare className="w-4 h-4" />,
  tool_call: <Code className="w-4 h-4" />,
  tool_result: <FileText className="w-4 h-4" />,
  analysis: <Brain className="w-4 h-4" />,
  finding: <AlertTriangle className="w-4 h-4 text-sev-high" />,
  code_read: <FileText className="w-4 h-4" />,
  search: <Search className="w-4 h-4" />,
  scan: <Scan className="w-4 h-4" />,
  entry_point: <Network className="w-4 h-4" />,
  dangerous_sink: <AlertTriangle className="w-4 h-4 text-sev-medium" />,
  investigation: <Brain className="w-4 h-4" />,
  // NEW architectural nodes
  file: <FileText className="w-4 h-4 text-blue-400" />,
  function: <Code className="w-4 h-4 text-purple-400" />,
  call: <ArrowRight className="w-4 h-4 text-green-400" />,
  external: <ExternalLink className="w-4 h-4 text-gray-400" />,
  auth_boundary: <Shield className="w-4 h-4 text-yellow-400" />,
  cycle: <AlertTriangle className="w-4 h-4 text-sev-medium" />,
};
```

**Step 3: Update legend**

Update legend section (around line 415):

```typescript
<div className="space-y-1.5 text-vsc-text">
  <div className="flex items-center gap-2">
    <Network className="w-3 h-3 text-vsc-text-muted" />
    <span>Entry Point / Sink</span>
  </div>
  <div className="flex items-center gap-2">
    <FileText className="w-3 h-3 text-blue-400" />
    <span>File Explored</span>
  </div>
  <div className="flex items-center gap-2">
    <Code className="w-3 h-3 text-purple-400" />
    <span>Function Analyzed</span>
  </div>
  <div className="flex items-center gap-2">
    <ArrowRight className="w-3 h-3 text-green-400" />
    <span>Function Call</span>
  </div>
  <div className="flex items-center gap-2">
    <AlertTriangle className="w-3 h-3 text-sev-high" />
    <span>Finding</span>
  </div>
</div>
```

**Step 4: Test in browser**

Run: `cd frontend && npm run dev`

Verify:
- New node types show correct colored icons
- Legend displays new node types

**Step 5: Commit**

```bash
git add frontend/components/FlowVisualization/FlowVisualization.tsx
git commit -m "feat(ui): add icons for architectural node types

Add distinct colored icons for:
- File nodes (blue)
- Function nodes (purple)
- Call nodes (green)
- External calls (gray)
- Auth boundaries (yellow)

Update legend to show new node types."
```

---

## Task 8: Integration Test - File Node Creation

**Files:**
- Create: `backend/tests/integration/test_flow_tree_structure.py`

**Step 1: Write integration test**

Create test file:

```python
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
```

**Step 2: Run test to verify it passes**

Run: `cd backend && python -m pytest tests/integration/test_flow_tree_structure.py -v`

Expected: PASS (2 tests)

**Step 3: Commit**

```bash
git add backend/tests/integration/test_flow_tree_structure.py
git commit -m "test(flow): add integration tests for tree structure

Test file investigation creates proper tree hierarchy and multiple
parallel investigation trees remain independent."
```

---

## Task 9: Agent Integration - Helper Functions

**Files:**
- Modify: `backend/agents/react_agent.py:1600-1700` (add at end of class)
- Test: Manual verification (covered by integration tests)

**Step 1: Add function extraction helper**

Add to ReactAgent class (after existing helper methods):

```python
def _extract_functions_from_code(self, code: str) -> list[dict]:
    """Extract function definitions from code.

    Returns list of dicts with: name, signature, line_number
    """
    functions = []
    import re

    # Python functions
    pattern = r'^\s*def\s+(\w+)\s*\((.*?)\):'
    for match in re.finditer(pattern, code, re.MULTILINE):
        line_num = code[:match.start()].count('\n') + 1
        functions.append({
            "name": match.group(1),
            "signature": match.group(0).strip(),
            "line_number": line_num
        })

    # JavaScript/TypeScript functions
    js_pattern = r'^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\('
    for match in re.finditer(js_pattern, code, re.MULTILINE):
        line_num = code[:match.start()].count('\n') + 1
        functions.append({
            "name": match.group(1),
            "signature": f"function {match.group(1)}()",
            "line_number": line_num
        })

    return functions


def _extract_calls_from_analysis(self, analysis: str) -> list[dict]:
    """Extract function calls from LLM analysis.

    Returns list of dicts with: target_function, call_type
    """
    calls = []
    import re

    # Look for patterns like "calls functionName()" or "invokes X.Y()"
    pattern = r'(?:calls?|invokes?|executes?)\s+([a-zA-Z_][\w\.]*)\s*\('
    for match in re.finditer(pattern, analysis, re.IGNORECASE):
        calls.append({
            "target_function": match.group(1),
            "call_type": "internal"
        })

    return calls
```

**Step 2: Test manually**

```bash
cd backend
python3 -c "
from agents.react_agent import ReactAgent
agent = ReactAgent.__new__(ReactAgent)

# Test function extraction
code = '''
def handle_request(data):
    return process(data)

def process(data):
    return data
'''
funcs = agent._extract_functions_from_code(code)
print('Extracted functions:', funcs)
assert len(funcs) == 2

# Test call extraction
analysis = 'The function calls process() and then invokes validate()'
calls = agent._extract_calls_from_analysis(analysis)
print('Extracted calls:', calls)
assert len(calls) == 2

print('✓ Helper functions work correctly')
"
```

Expected: Output showing extracted functions and calls

**Step 3: Commit**

```bash
git add backend/agents/react_agent.py
git commit -m "feat(agent): add function/call extraction helpers

Add _extract_functions_from_code() to parse function definitions from
code (Python and JavaScript).

Add _extract_calls_from_analysis() to extract function calls from LLM
analysis output."
```

---

## Task 10: Agent Integration - Tool Call Wrapper (Read File)

**Files:**
- Modify: `backend/agents/react_agent.py:1512-1520`
- Test: Manual verification with running agent

**Step 1: Backup current _execute_tool_call method**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/flow-tree-visualization/backend/agents
cp react_agent.py react_agent.py.backup
```

**Step 2: Add file reading logic to _execute_tool_call**

Find the `_execute_tool_call` method (around line 1500) and add this at the beginning, before the existing tool execution code:

```python
async def _execute_tool_call(self, tool_name: str, arguments: dict) -> str:
    """Execute a tool call with architectural tree tracking."""

    # FILE READ: Create file and function nodes
    if tool_name == "read_file":
        file_path = arguments.get("path", "")

        # Get or create file node
        from services.flow_service import flow_service
        file_node = flow_service.get_or_create_file_node(self.id, file_path)

        if not file_node:
            # Create new file node
            import os
            file_node = flow_service.add_node(
                self.id,
                "file",
                f"📄 {os.path.basename(file_path)}",
                {
                    "file_path": file_path,
                    "full_path": file_path,
                    "tool": "read_file"
                },
                auto_parent=True
            )

        # Update context
        flow_service.update_context(self.id, current_file=file_path)
        flow_service.update_node_status(self.id, file_node.id, "running")

        # Execute tool
        result = await self._tools[tool_name].execute(**arguments)

        flow_service.update_node_status(self.id, file_node.id, "completed")

        # Parse result to extract functions
        try:
            functions = self._extract_functions_from_code(result)
            for func in functions[:10]:  # Limit to first 10 functions
                func_node = flow_service.add_node(
                    self.id,
                    "function",
                    f"⚡ {func['name']}()",
                    {
                        "function_name": func["name"],
                        "line_number": func.get("line_number"),
                        "signature": func.get("signature"),
                    },
                    parent_id=file_node.id,
                    auto_parent=False,
                    set_current=False
                )
        except Exception:
            pass  # If parsing fails, just skip function nodes

        self._broadcast_flow_update()
        return result

    # EXISTING TOOL EXECUTION CODE CONTINUES HERE...
    # (Keep all the existing tool execution logic)
```

**Step 3: Test with manual agent run**

Start backend and create a test agent that reads a file. Verify:
- File node appears in flow
- Function nodes appear as children of file
- Icons show correctly

**Step 4: Commit**

```bash
git add backend/agents/react_agent.py
git commit -m "feat(agent): add file reading with tree structure

When agent reads file:
- Create/get file node parented to current candidate
- Extract functions and create child nodes
- Update context to track current file

Limits to 10 functions to avoid overwhelming the tree."
```

---

## Task 11: Documentation - Update README

**Files:**
- Create: `backend/services/README_FLOW_SERVICE.md`

**Step 1: Create documentation**

```markdown
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
```

**Step 2: Commit**

```bash
git add backend/services/README_FLOW_SERVICE.md
git commit -m "docs(flow): add flow service documentation

Document tree structure, node types, context tracking, and usage
examples for the flow tree visualization feature."
```

---

## Task 12: Final Integration Test

**Files:**
- Create: `backend/tests/integration/test_agent_flow_integration.py`

**Step 1: Write end-to-end test**

```python
"""End-to-end test for agent flow tree integration."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from agents.react_agent import ReactAgent
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig
from services.flow_service import flow_service


@pytest.fixture
def mock_agent():
    """Create a mock agent for testing."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.REACT,
        provider_config=ProviderConfig(
            provider="mock",
            model="test-model",
            api_key="test-key"
        )
    )
    agent = ReactAgent(request, "/tmp/test-repo")
    agent._tools = {
        "read_file": MagicMock(
            execute=AsyncMock(return_value="""
def handle_request(data):
    result = process(data)
    return result

def process(data):
    return validate(data)
""")
        )
    }
    return agent


@pytest.mark.asyncio
async def test_agent_creates_tree_on_file_read(mock_agent):
    """Test agent creates proper tree when reading file."""
    flow_service.initialize_flow(mock_agent.id)

    # Create scan and candidate
    scan_node = flow_service.add_node(
        mock_agent.id,
        "scan",
        "Scan",
        {}
    )
    candidate_node = flow_service.add_node(
        mock_agent.id,
        "entry_point",
        "POST /api/upload",
        {},
        parent_id=scan_node.id,
        set_current=False
    )
    flow_service.update_context(
        mock_agent.id,
        current_candidate_node_id=candidate_node.id
    )

    # Execute read_file tool
    result = await mock_agent._execute_tool_call(
        "read_file",
        {"path": "routes/api.py"}
    )

    # Verify tree structure
    flow = flow_service.get_flow(mock_agent.id)

    # Should have: scan, candidate, file, 2 functions
    assert len(flow.nodes) >= 4

    # Find file node
    file_nodes = [n for n in flow.nodes if n.type == "file"]
    assert len(file_nodes) == 1
    file_node = file_nodes[0]
    assert "api.py" in file_node.label

    # Find function nodes
    func_nodes = [n for n in flow.nodes if n.type == "function"]
    assert len(func_nodes) >= 2
    func_names = [n.label for n in func_nodes]
    assert any("handle_request" in name for name in func_names)
    assert any("process" in name for name in func_names)

    # Verify edges
    edges_by_target = {e.target: e.source for e in flow.edges}

    # File should be child of candidate
    assert edges_by_target[file_node.id] == candidate_node.id

    # Functions should be children of file
    for func in func_nodes:
        assert edges_by_target[func.id] == file_node.id

    # Cleanup
    flow_service.clear_flow(mock_agent.id)
```

**Step 2: Run test**

Run: `cd backend && python -m pytest tests/integration/test_agent_flow_integration.py -v`

Expected: PASS

**Step 3: Commit**

```bash
git add backend/tests/integration/test_agent_flow_integration.py
git commit -m "test(integration): add agent flow tree end-to-end test

Test that agent creates proper tree structure when reading files:
- File node created
- Functions extracted and added as children
- Proper parent-child relationships maintained"
```

---

## Task 13: Manual Verification & Documentation

**Files:**
- Create: `docs/plans/2026-01-11-flow-tree-verification.md`

**Step 1: Create verification checklist**

```markdown
# Flow Tree Visualization - Verification Checklist

## Backend Verification

### FlowService
- [ ] FlowContext added to InvestigationFlow
- [ ] New node types (file, function, call, external, auth_boundary) work
- [ ] update_context() preserves existing fields
- [ ] get_or_create_file_node() returns existing or None
- [ ] auto_parent=True uses context correctly
- [ ] Explicit parent_id overrides auto_parent

### Agent Integration
- [ ] read_file creates file node
- [ ] read_file extracts functions
- [ ] Function nodes are children of file
- [ ] Context updates on file read
- [ ] Multiple file reads create separate nodes

## Frontend Verification

### Layout
- [ ] Multiple investigation trees display side-by-side
- [ ] No overlapping nodes
- [ ] Trees with more branches get more width
- [ ] Parent nodes centered over children
- [ ] Deep trees don't overflow viewport

### Visual
- [ ] File nodes show blue FileText icon
- [ ] Function nodes show purple Code icon
- [ ] Call nodes show green ArrowRight icon
- [ ] Legend displays new node types
- [ ] Tooltips show node details

## Integration Testing

### End-to-End Flow
- [ ] Start scan creates root node
- [ ] Triage creates candidate nodes
- [ ] Reading file creates tree structure
- [ ] Multiple candidates create parallel trees
- [ ] Clicking node shows details in popover

### Performance
- [ ] Layout calculates quickly for 100+ nodes
- [ ] No UI lag when adding nodes
- [ ] ReactFlow viewport smooth with multiple trees

## Manual Testing Steps

### Test 1: Basic Tree Creation
1. Start backend: `./run-local.sh`
2. Create agent in UI
3. Select file to audit
4. Verify flow visualization shows:
   - Scan root
   - Entry points/sinks as children
   - Files as children of candidates
   - Functions as children of files

### Test 2: Multiple Investigation Trees
1. Run scan that finds 3+ candidates
2. Verify each candidate starts its own tree
3. Verify trees don't overlap
4. Verify trees are visually distinct

### Test 3: Deep Investigation
1. Investigate one candidate deeply (read multiple files)
2. Verify tree grows vertically
3. Verify function nodes appear
4. Verify no performance issues

## Known Limitations

- Function extraction limited to 10 per file
- Only Python and JavaScript function patterns supported
- Call extraction depends on LLM output format
- No collapsible subtrees yet

## Future Enhancements

- [ ] Add call node creation when tracing calls
- [ ] Support more languages for function extraction
- [ ] Add subtree collapse/expand
- [ ] Add filtering by node type
- [ ] Add search/highlight in tree
```

**Step 2: Run manual verification**

Follow the manual testing steps in the checklist and mark completed items.

**Step 3: Commit**

```bash
git add docs/plans/2026-01-11-flow-tree-verification.md
git commit -m "docs: add flow tree verification checklist

Document verification steps for backend, frontend, and integration
testing. Include manual testing procedures and known limitations."
```

---

## Summary

This implementation plan converts the linear flow visualization into a hierarchical tree structure showing:

**Backend (Tasks 1-5):**
- FlowContext for tracking investigation state
- New architectural node types (file, function, call)
- Auto-parent logic based on context
- File node deduplication

**Frontend (Tasks 6-7):**
- Multi-tree layout algorithm with subtree width calculation
- Colored icons for architectural nodes
- Updated legend

**Integration (Tasks 8-12):**
- Helper functions for extracting functions/calls from code
- Agent integration for file reading with tree creation
- Comprehensive tests (unit, integration, end-to-end)

**Documentation (Tasks 11-13):**
- Flow service README
- Verification checklist
- Manual testing procedures

Each task follows TDD: write test → verify failure → implement → verify pass → commit.

All code is complete and ready for copy-paste execution.
