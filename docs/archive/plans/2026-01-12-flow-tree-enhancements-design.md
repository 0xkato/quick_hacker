# Flow Tree Visualization - Enhancements Design

**Date:** 2026-01-12
**Status:** Design Complete, Ready for Implementation

## Overview

This design adds 5 enhancements to the existing flow tree visualization:

1. **Call Tracing with Configurable Depth** - Automatically create call nodes when LLM analyzes function calls
2. **Complete TypeScript Support** - Arrow functions, class methods, decorators, interfaces
3. **Collapsible Subtrees** - Expand/collapse functionality with count badges
4. **Unified Search/Filter** - Single search box with type prefixes (`type:file`, `function:handleRequest`)
5. **Search Highlighting** - Visual emphasis on matches with ancestor path visibility

## Architecture

### Integration Strategy

Build on existing flow tree visualization with modular enhancements:
- Backend: Extend function extraction and add call tracing
- Frontend: Add toolbar with search/filter controls
- State: Node collapse state and search state in component
- Storage: Configurable depth limits and preferences

**Key Principle:** Each enhancement can be enabled/disabled independently.

---

## Enhancement 1: Call Tracing with Configurable Depth

### Backend Changes

**FlowContext Extension:**
```python
@dataclass
class FlowContext:
    current_file: Optional[str] = None
    current_function: Optional[str] = None
    current_candidate_node_id: Optional[str] = None
    investigation_root_id: Optional[str] = None
    call_depth: int = 0              # NEW: Current depth in call chain
    max_call_depth: int = 3          # NEW: Configurable limit
```

**Call Node Creation Logic:**

When LLM provides analysis mentioning function calls:
1. Parse analysis with existing `_extract_calls_from_analysis()`
2. Check if `call_depth < max_call_depth`
3. For each call found:
   - Create call node parented to current function
   - If call references another file, create/get file node
   - If target function exists, link to it
   - Increment call_depth in context
4. Update context with new function scope

**Settings Storage:**

Add to agent settings:
```python
class AgentSettings:
    max_call_depth: int = 3  # Default limit
```

Store per-agent to allow different investigation tiers to use different depths.

### Call Tracing Flow

```
1. Agent analyzes function foo()
2. LLM returns: "calls bar() which validates input"
3. Extract call: {target_function: "bar", call_type: "internal"}
4. Check call_depth (0) < max_call_depth (3) ✓
5. Create call node: "→ bar()" parented to foo()
6. If bar() in same file, link to existing function node
7. If bar() in different file, create file node + function node
8. Increment call_depth to 1
9. Continue investigation into bar() if needed
```

---

## Enhancement 2: Complete TypeScript Support

### Extended Function Extraction Patterns

**Current Support:**
- `function name()`
- `export function name()`
- `async function name()`
- `function* name()` (generators)

**New Patterns to Add:**

1. **Arrow Functions:**
```typescript
const handleRequest = () => {}
const handleRequest = async () => {}
export const handleRequest = () => {}
const handleRequest = (data) => {}
```

Pattern: `r'^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>'`

2. **Class Methods:**
```typescript
class RequestHandler {
    handleRequest() {}
    async processData() {}
    private validateInput() {}
}
```

Pattern: `r'^\s*(?:public|private|protected|static)?\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*[:{]'`

3. **Decorated Methods:**
```typescript
@route('/api/upload')
async handleUpload() {}
```

Pattern: `r'^\s*@\w+(?:\([^)]*\))?\s*\n\s*(?:async\s+)?(\w+)\s*\('`

4. **Interface Methods (for reference):**
```typescript
interface Handler {
    handleRequest(data: any): Promise<void>
}
```

Pattern: `r'^\s*(\w+)\s*\([^)]*\)\s*:\s*\w+'` (mark as interface method)

### Implementation Strategy

Update `_extract_functions_from_code()`:
```python
def _extract_functions_from_code(self, code: str) -> list[dict]:
    """Extract function definitions from code.

    Supports: Python, JavaScript, TypeScript (arrow functions, methods, decorators)
    """
    if not code or not isinstance(code, str):
        return []

    functions = []
    lines = code.split('\n')

    # Python patterns (existing)
    python_pattern = r'^\s*(?:async\s+)?def\s+(\w+)\s*\('

    # JavaScript/TypeScript patterns (extended)
    js_function_pattern = r'^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\('
    arrow_pattern = r'^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>'
    method_pattern = r'^\s*(?:public|private|protected|static)?\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*[:{]'
    decorator_pattern = r'^\s*@\w+(?:\([^)]*\))?$'  # Match decorator line

    i = 0
    while i < len(lines):
        line = lines[i]
        line_num = i + 1

        # Check for decorated method (TypeScript)
        if re.match(decorator_pattern, line) and i + 1 < len(lines):
            next_line = lines[i + 1]
            method_match = re.match(method_pattern, next_line)
            if method_match:
                functions.append({
                    "name": method_match.group(1),
                    "signature": f"{line.strip()} {method_match.group(0).strip()}",
                    "line_number": line_num,
                    "language": "typescript"
                })
                i += 2
                continue

        # Try each pattern
        for pattern, lang in [
            (python_pattern, "python"),
            (js_function_pattern, "javascript"),
            (arrow_pattern, "typescript"),
            (method_pattern, "typescript")
        ]:
            match = re.match(pattern, line)
            if match:
                functions.append({
                    "name": match.group(1),
                    "signature": match.group(0).strip(),
                    "line_number": line_num,
                    "language": lang
                })
                break

        i += 1

    return functions
```

---

## Enhancement 3: Collapsible Subtrees

### State Management

**Add to FlowVisualization component:**
```typescript
interface CollapsedState {
  [nodeId: string]: boolean;  // true = collapsed
}

const [collapsedNodes, setCollapsedNodes] = useState<CollapsedState>({});
```

### Node Visibility Logic

When rendering nodes:
1. Calculate descendants for each node
2. If node is collapsed, mark all descendants as `hidden: true`
3. Update ReactFlow nodes array with hidden property
4. Show collapse button (▼) on nodes with children
5. Show expand button (▶) on collapsed nodes
6. Add count badge: "📁 (+5 hidden)"

### UI Implementation

**Collapse Button Component:**
```typescript
function CollapseButton({
  nodeId,
  isCollapsed,
  descendantCount,
  onToggle
}: CollapseButtonProps) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        onToggle(nodeId);
      }}
      className="absolute top-1 right-1 p-1 hover:bg-vsc-hover rounded"
    >
      {isCollapsed ? (
        <>
          <ChevronRight className="w-3 h-3" />
          <span className="text-xs ml-1">+{descendantCount}</span>
        </>
      ) : (
        <ChevronDown className="w-3 h-3" />
      )}
    </button>
  );
}
```

**Collapse Logic:**
```typescript
const toggleCollapse = (nodeId: string) => {
  setCollapsedNodes(prev => ({
    ...prev,
    [nodeId]: !prev[nodeId]
  }));
};

// Calculate which nodes to hide
const visibleNodes = useMemo(() => {
  const hidden = new Set<string>();

  Object.entries(collapsedNodes).forEach(([nodeId, isCollapsed]) => {
    if (isCollapsed) {
      // Find all descendants and mark hidden
      const descendants = getDescendants(nodeId, edges);
      descendants.forEach(id => hidden.add(id));
    }
  });

  return nodes.map(node => ({
    ...node,
    hidden: hidden.has(node.id)
  }));
}, [nodes, edges, collapsedNodes]);
```

**Default State:** Everything expanded (per requirement B).

---

## Enhancement 4 & 5: Unified Search with Type Prefixes

### Search Syntax

**Supported Formats:**

| Query | Behavior |
|-------|----------|
| `type:file` | Show only file nodes |
| `type:function` | Show only function nodes |
| `type:call` | Show only call nodes |
| `function:handle*` | Search function names with wildcard |
| `api.py` | Fuzzy match node labels |
| `type:file routes` | Combine filters (AND logic) |
| `type:function OR type:call` | Multiple types (OR logic) |

### Query Parser

```typescript
interface SearchQuery {
  types: string[];           // Node types to show
  labelPattern?: string;     // Text to match in labels
  functionPattern?: string;  // Function name pattern
  caseSensitive: boolean;
}

function parseSearchQuery(query: string): SearchQuery {
  const parts = query.trim().split(/\s+/);
  const types: string[] = [];
  let labelPattern = '';
  let functionPattern = '';

  parts.forEach(part => {
    if (part.startsWith('type:')) {
      types.push(part.substring(5));
    } else if (part.startsWith('function:')) {
      functionPattern = part.substring(9).replace('*', '.*');
    } else if (part !== 'OR' && part !== 'AND') {
      labelPattern = part;
    }
  });

  return {
    types,
    labelPattern,
    functionPattern,
    caseSensitive: false
  };
}
```

### Filtering Logic

```typescript
const filterNodes = (nodes: FlowNode[], query: SearchQuery): Set<string> => {
  const matches = new Set<string>();

  nodes.forEach(node => {
    let isMatch = true;

    // Type filter
    if (query.types.length > 0) {
      isMatch = isMatch && query.types.includes(node.type);
    }

    // Label pattern
    if (query.labelPattern) {
      const labelLower = node.label.toLowerCase();
      const patternLower = query.labelPattern.toLowerCase();
      isMatch = isMatch && labelLower.includes(patternLower);
    }

    // Function name pattern
    if (query.functionPattern && node.type === 'function') {
      const regex = new RegExp(query.functionPattern, 'i');
      isMatch = isMatch && regex.test(node.data?.function_name || node.label);
    }

    if (isMatch) {
      matches.add(node.id);
      // Also include ancestors (keep path visible)
      getAncestors(node.id, edges).forEach(id => matches.add(id));
    }
  });

  return matches;
};
```

### UI Component

```typescript
function SearchToolbar({ onSearch, resultCount, currentIndex }: SearchToolbarProps) {
  const [query, setQuery] = useState('');

  return (
    <div className="flex items-center gap-2 p-2 border-b border-vsc-border">
      <Search className="w-4 h-4 text-vsc-text-muted" />
      <input
        type="text"
        value={query}
        onChange={e => {
          setQuery(e.target.value);
          onSearch(e.target.value);
        }}
        placeholder="Search: type:file, function:handle*, api.py"
        className="flex-1 bg-vsc-input border border-vsc-border rounded px-2 py-1"
      />
      {query && (
        <>
          <button
            onClick={() => setQuery('')}
            className="p-1 hover:bg-vsc-hover rounded"
          >
            <X className="w-4 h-4" />
          </button>
          <div className="text-sm text-vsc-text-muted">
            {currentIndex + 1}/{resultCount} matches
          </div>
          <div className="flex gap-1">
            <button className="p-1 hover:bg-vsc-hover rounded">
              <ChevronUp className="w-4 h-4" />
            </button>
            <button className="p-1 hover:bg-vsc-hover rounded">
              <ChevronDown className="w-4 h-4" />
            </button>
          </div>
        </>
      )}
    </div>
  );
}
```

### Highlighting

Matching nodes get yellow border:
```typescript
const getNodeStyle = (node: FlowNode, isMatch: boolean, isVisible: boolean) => ({
  ...baseStyle,
  opacity: isVisible ? 1 : 0.3,  // Dim non-matching nodes
  borderColor: isMatch ? '#facc15' : borderColor,  // Yellow for matches
  borderWidth: isMatch ? '2px' : '1px',
});
```

---

## Implementation Phases

### Phase 1: Backend (Call Tracing + TypeScript)
1. Add call_depth and max_call_depth to FlowContext
2. Extend _extract_functions_from_code with TypeScript patterns
3. Add settings storage for max_call_depth
4. Create call nodes when analyzing functions
5. Add tests for TypeScript extraction
6. Add tests for call tracing with depth limits

### Phase 2: Frontend (Collapse/Expand)
1. Add collapsedNodes state to FlowVisualization
2. Implement getDescendants helper
3. Add CollapseButton component to nodes
4. Update node visibility based on collapse state
5. Test with deep trees (10+ levels)

### Phase 3: Frontend (Search/Filter)
1. Add SearchToolbar component
2. Implement query parser with type prefix support
3. Add filtering logic with ancestor inclusion
4. Implement highlighting with opacity changes
5. Add keyboard shortcuts (Cmd+F, Cmd+G)
6. Test with complex queries

### Phase 4: Integration & Polish
1. Integrate all features together
2. Add loading states for search
3. Optimize performance for large trees (1000+ nodes)
4. Update documentation
5. Create integration tests

---

## Testing Strategy

### Backend Tests
- TypeScript arrow function extraction
- TypeScript class method extraction
- Decorated method extraction
- Call tracing with depth limits
- Call tracing across files
- Settings persistence

### Frontend Tests
- Collapse/expand single node
- Collapse/expand cascading nodes
- Search with type filters
- Search with wildcards
- Combined filters (type + pattern)
- Keyboard navigation

### Integration Tests
- End-to-end: Create call chain, verify depth limit
- End-to-end: Search filtered results
- End-to-end: Collapse + search interaction
- Performance: 1000+ node tree with search

---

## Performance Considerations

### Backend
- Function extraction: O(n) where n = lines of code
- Call tracing: Limited by max_call_depth (default 3)
- Memory: Store only function signatures, not full code

### Frontend
- Search/filter: O(n) where n = node count
- Collapse: O(d) where d = descendants of collapsed node
- Rendering: ReactFlow handles virtualization (tested to 10k nodes)

### Optimizations
- Debounce search input (300ms)
- Memoize filtered nodes
- Cache ancestor/descendant calculations
- Use Set for O(1) lookup in visibility checks

---

## Known Limitations

### Call Tracing
- Depends on LLM accurately identifying calls in analysis
- Dynamic/runtime calls (callbacks, eval) not traceable
- Recursive calls respect depth limit (may not show full recursion)

### TypeScript Support
- Multiline arrow functions detected from first line only
- Generic type parameters may confuse regex
- Overloaded methods extracted as separate functions

### Search
- No regex in search box (only wildcards)
- Case-insensitive by default (no toggle)
- No full-text search in code context (only labels)

### Collapse
- State cleared on page refresh (no persistence)
- No "collapse all" / "expand all" buttons yet
- No automatic collapse of deep subtrees

---

## Future Enhancements (Beyond These 5)

1. **Persistence** - Save collapse/search state to localStorage
2. **Advanced Search** - Full regex support, code context search
3. **Auto-collapse** - Configurable rules (depth > 5, type = function)
4. **Export View** - Export filtered/collapsed tree as image
5. **Keyboard Shortcuts** - Full keyboard navigation
6. **Call Graph View** - Alternative visualization showing call relationships
7. **Go/Rust Support** - Extend to other languages
8. **Performance Profiling** - Show time spent in each function
9. **Diff View** - Compare trees across investigation iterations
10. **Annotations** - Add notes to nodes

---

## Success Criteria

- ✅ Call tracing creates nodes up to configurable depth limit
- ✅ TypeScript arrow functions and class methods extracted correctly
- ✅ Users can collapse/expand subtrees with count badges
- ✅ Search supports type prefixes and wildcard patterns
- ✅ Matching nodes highlighted, non-matching dimmed
- ✅ All tests pass (backend + frontend + integration)
- ✅ Performance acceptable for 500+ node trees
- ✅ Documentation updated with examples
