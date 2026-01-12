# Frontend Integration Test Specification

This document specifies the frontend integration tests that should be implemented once the frontend code is added to this worktree.

## Test File Location

`frontend/components/FlowVisualization/__tests__/integration.test.tsx`

## Required Test Infrastructure

```json
// package.json devDependencies
{
  "@testing-library/react": "^14.0.0",
  "@testing-library/user-event": "^14.5.0",
  "@testing-library/jest-dom": "^6.1.0",
  "jest": "^29.7.0",
  "@types/jest": "^29.5.0"
}
```

## Test Suites

### 1. Basic Rendering Integration

**Purpose**: Verify all nodes and edges render correctly

```typescript
describe('FlowVisualization Integration', () => {
  it('should render all nodes and edges', () => {
    // Given: A flow with file, function, and call nodes
    // When: Component renders
    // Then: All nodes appear in the DOM with correct labels
    // Then: Edges connect the nodes properly
  });
});
```

### 2. Search with Type Filters Integration

**Purpose**: Verify search functionality with type-based filtering

```typescript
describe('Search Integration', () => {
  it('should support search with type filters', async () => {
    // Given: A flow with mixed node types
    // When: User types "type:file" in search
    // Then: Only file nodes are highlighted
    // Then: Other nodes are dimmed
  });

  it('should support multiple type filters', async () => {
    // Given: A flow with mixed node types
    // When: User types "type:file,function"
    // Then: File and function nodes are highlighted
    // Then: Call and other nodes are dimmed
  });

  it('should support text search within types', async () => {
    // Given: Multiple file nodes with different names
    // When: User types "type:file api"
    // Then: Only file nodes containing "api" are highlighted
  });
});
```

### 3. Collapse/Expand Integration

**Purpose**: Verify tree collapse/expand functionality

```typescript
describe('Collapse/Expand Integration', () => {
  it('should collapse and expand subtrees', async () => {
    // Given: A tree with file → function → call hierarchy
    // When: User clicks collapse button on file node
    // Then: All descendant nodes are hidden
    // When: User clicks expand button
    // Then: Descendant nodes reappear
  });

  it('should work with search active', async () => {
    // Given: A tree with search results highlighted
    // When: User collapses a node containing matches
    // Then: Collapsed node shows badge indicating hidden matches
    // Then: Parent path to collapsed matches remains visible
  });

  it('should persist collapse state during operations', async () => {
    // Given: User collapses several subtrees
    // When: New nodes are added via WebSocket
    // Then: Previously collapsed trees remain collapsed
  });
});
```

### 4. Keyboard Shortcuts Integration

**Purpose**: Verify keyboard navigation and shortcuts

```typescript
describe('Keyboard Shortcuts Integration', () => {
  it('should focus search on Cmd+F', async () => {
    // Given: Flow visualization is visible
    // When: User presses Cmd+F (Mac) or Ctrl+F (Windows)
    // Then: Search input receives focus
  });

  it('should clear search on Escape', async () => {
    // Given: Search has query text
    // When: User presses Escape
    // Then: Search input is cleared
    // Then: All nodes return to normal state
  });

  it('should navigate results with arrow keys', async () => {
    // Given: Search has multiple results
    // When: User presses arrow down
    // Then: Next result is highlighted
    // When: User presses arrow up
    // Then: Previous result is highlighted
  });

  it('should expand collapsed node on Enter', async () => {
    // Given: Collapsed node is selected
    // When: User presses Enter
    // Then: Node expands to show children
  });
});
```

### 5. Performance Integration

**Purpose**: Verify performance with large datasets

```typescript
describe('Performance Integration', () => {
  it('should handle 500+ nodes without lag', async () => {
    // Given: Flow with 500 nodes in multiple trees
    // When: Component renders
    // Then: Initial render completes within 1 second
  });

  it('should search large flows quickly', async () => {
    // Given: Flow with 500+ nodes
    // When: User types in search
    // Then: Results appear within 200ms (debounced)
  });

  it('should collapse large subtrees smoothly', async () => {
    // Given: Node with 100+ descendants
    // When: User collapses the node
    // Then: Collapse animation completes within 300ms
  });

  it('should handle rapid node additions', async () => {
    // Given: Initial flow with some nodes
    // When: 50 nodes are added rapidly via WebSocket
    // Then: UI remains responsive
    // Then: All nodes eventually appear
  });
});
```

### 6. Search + Collapse Integration

**Purpose**: Verify search and collapse work together

```typescript
describe('Search and Collapse Integration', () => {
  it('should show match count in collapsed nodes', async () => {
    // Given: Subtree with 5 matching nodes
    // When: Parent is collapsed during search
    // Then: Parent node shows badge "5 matches"
  });

  it('should auto-expand path to search result', async () => {
    // Given: Search result in deeply nested collapsed tree
    // When: User navigates to result
    // Then: All ancestor nodes auto-expand
    // Then: Result node is highlighted
  });

  it('should clear search before collapse', async () => {
    // Given: Active search with results
    // When: User presses Escape
    // Then: Search clears
    // When: User collapses node
    // Then: Normal collapse occurs without search badges
  });
});
```

### 7. End-to-End Flow Integration

**Purpose**: Verify complete user workflows

```typescript
describe('End-to-End Flow Integration', () => {
  it('should complete full investigation workflow', async () => {
    // 1. Flow starts with scan node
    // 2. Entry points are added
    // 3. User searches for "upload"
    // 4. User collapses unrelated branches
    // 5. User navigates with keyboard
    // 6. New finding node appears via WebSocket
    // 7. User expands finding details
    // Verify: All state remains consistent
  });

  it('should persist state across operations', async () => {
    // Given: User has collapsed some nodes and has active search
    // When: WebSocket delivers new nodes
    // Then: Collapsed state persists
    // Then: Search results update to include new nodes if matching
    // Then: Layout adjusts without breaking existing tree structure
  });
});
```

## Mock Data Examples

### Basic Flow Mock

```typescript
const mockBasicFlow: InvestigationFlow = {
  session_id: 'test-session',
  nodes: [
    {
      id: '1',
      type: 'scan',
      label: 'Security Scan',
      status: 'completed',
      data: {},
      timestamp: new Date().toISOString()
    },
    {
      id: '2',
      type: 'entry_point',
      label: 'POST /api/upload',
      status: 'completed',
      data: {},
      timestamp: new Date().toISOString()
    },
    {
      id: '3',
      type: 'file',
      label: 'routes.py',
      status: 'completed',
      data: { file_path: 'api/routes.py' },
      timestamp: new Date().toISOString()
    },
    {
      id: '4',
      type: 'function',
      label: 'upload_handler()',
      status: 'completed',
      data: { function_name: 'upload_handler' },
      timestamp: new Date().toISOString()
    },
    {
      id: '5',
      type: 'call',
      label: '→ save_file',
      status: 'completed',
      data: { target_function: 'save_file' },
      timestamp: new Date().toISOString()
    }
  ],
  edges: [
    { id: 'e1', source: '1', target: '2', label: 'investigates' },
    { id: 'e2', source: '2', target: '3', label: 'reads' },
    { id: 'e3', source: '3', target: '4', label: 'contains' },
    { id: 'e4', source: '4', target: '5', label: 'calls' }
  ],
  current_node_id: '5',
  context: {
    current_file: 'api/routes.py',
    current_function: 'upload_handler',
    current_candidate_node_id: '2',
    investigation_root_id: '2',
    call_depth: 1,
    max_call_depth: 3
  }
};
```

### Large Flow Generator

```typescript
function generateLargeFlow(nodeCount: number): InvestigationFlow {
  const nodes: FlowNode[] = [];
  const edges: FlowEdge[] = [];

  // Create scan root
  nodes.push({
    id: '0',
    type: 'scan',
    label: 'Large Scan',
    status: 'completed',
    data: {},
    timestamp: new Date().toISOString()
  });

  // Create multiple trees
  const treesCount = Math.floor(nodeCount / 100);
  let nodeId = 1;

  for (let t = 0; t < treesCount; t++) {
    // Entry point
    const entryId = String(nodeId++);
    nodes.push({
      id: entryId,
      type: 'entry_point',
      label: `Entry ${t}`,
      status: 'completed',
      data: {},
      timestamp: new Date().toISOString()
    });
    edges.push({
      id: `e-0-${entryId}`,
      source: '0',
      target: entryId,
      label: null
    });

    // Create branching structure under each entry
    createBranchingStructure(nodes, edges, entryId, nodeId, 4, 5);
    nodeId += 100 / treesCount;
  }

  return {
    session_id: 'large-flow',
    nodes,
    edges,
    current_node_id: nodes[nodes.length - 1].id,
    context: {
      current_file: null,
      current_function: null,
      current_candidate_node_id: nodes[1].id,
      investigation_root_id: nodes[1].id,
      call_depth: 0,
      max_call_depth: 5
    }
  };
}
```

## Test Utilities

### Custom Matchers

```typescript
// Check if node is visible
expect(node).toBeVisible();

// Check if node is highlighted (search result)
expect(node).toHaveClass('highlighted');

// Check if node is dimmed (not matching search)
expect(node).toHaveClass('dimmed');

// Check if node is collapsed
expect(node).toHaveAttribute('data-collapsed', 'true');
```

### Helper Functions

```typescript
// Wait for debounced search
async function waitForSearch(ms = 300) {
  await waitFor(() => {}, { timeout: ms });
}

// Get all visible nodes
function getVisibleNodes(container: HTMLElement) {
  return Array.from(container.querySelectorAll('[data-node-visible="true"]'));
}

// Simulate keyboard shortcut
function pressShortcut(key: string, meta = false, ctrl = false) {
  fireEvent.keyDown(window, { key, metaKey: meta, ctrlKey: ctrl });
}
```

## Running the Tests

```bash
# Run all integration tests
npm test -- integration.test.tsx

# Run with coverage
npm test -- --coverage integration.test.tsx

# Run in watch mode
npm test -- --watch integration.test.tsx

# Run specific test suite
npm test -- --testNamePattern="Search Integration"
```

## Performance Benchmarks

All tests should pass these performance requirements:

- Initial render (100 nodes): < 200ms
- Initial render (500 nodes): < 1000ms
- Search debounce: 300ms
- Search execution (500 nodes): < 100ms
- Collapse animation: < 300ms
- Node addition (WebSocket): < 50ms per node

## Test Coverage Goals

- Line coverage: > 80%
- Branch coverage: > 75%
- Function coverage: > 80%
- Critical paths: 100%
