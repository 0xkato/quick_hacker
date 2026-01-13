# Code Graph Visualization Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:writing-plans to create an implementation plan from this design.

**Goal:** Replace the linear investigation flow with a code call graph that shows actual codebase structure, with relevance scoring and agent activity overlay.

**Architecture:** Entry-point driven tree visualization. Start from routes/main/APIs, expand outward on demand. Nodes scored by position + content patterns. Agent actions shown as highlights on the graph, not a separate timeline.

**Tech Stack:** ReactFlow (dagre layout), Python AST parsing, FastAPI endpoints

---

## Core Concept

A code call graph visualization that replaces the current linear investigation flow. The graph shows the actual structure of the codebase - which functions call which, starting from entry points.

**Key behaviors:**

- **Entry-point anchored**: Tree roots are discovered entry points (FastAPI routes, `main()`, CLI handlers)
- **Progressive expansion**: Nodes start collapsed. Click to expand children
- **Relevance badges**: Each node shows High/Medium/Low/Skip based on position + content patterns
- **Agent activity overlay**: When the agent reads a file, that node gets highlighted

**What this replaces:**

The current `FlowVisualization` that shows a linear chain of agent actions. Instead of "agent did X, then Y, then Z", you see "here's the code structure, and here's where the agent has looked".

---

## Relevance Scoring System

Each node scored on two dimensions:

### Content Patterns (0-100 points)

| Points | Patterns |
|--------|----------|
| +40 | auth, authentication, login, session, token, jwt, oauth |
| +40 | crypto, encrypt, decrypt, hash, password, secret |
| +40 | sql, query, execute, cursor, database |
| +40 | exec, eval, subprocess, shell, command, system |
| +40 | input, request, body, params, user_input, form |
| +30 | file, read, write, open, path, upload |
| +20 | http, api, endpoint, route, handler |
| +10 | config, settings, env |
| -20 | test, spec, mock, fixture |
| -10 | log, print, debug, trace |

### Graph Position (0-60 points)

| Points | Position |
|--------|----------|
| +60 | Entry point (route handler, main, CLI) |
| +40 | Depth 1 (directly called by entry point) |
| +25 | Depth 2 |
| +15 | Depth 3 |
| +5 | Depth 4+ |

### Combined Score → Relevance Level

| Score | Level | Display |
|-------|-------|---------|
| 80+ | High | Red badge - Prioritize investigating |
| 50-79 | Medium | Yellow badge - Worth exploring |
| 20-49 | Low | Gray badge - Context if needed |
| <20 | Skip | Hidden/dimmed - Test files, logging utils |

---

## Tree Structure & Node Display

### Node Types

| Type | Description |
|------|-------------|
| `entry_point` | Route handlers, main(), CLI commands (tree roots) |
| `function` | In-repo function definitions |
| `external` | Calls to libraries/stdlib (collapsed by default) |
| `cycle` | Back-reference to already-shown node |

### Node Visual Structure

```
┌─────────────────────────────────────┐
│ [Icon] function_name      [HIGH] ▶ │
│ src/auth/handler.py:45             │
│ ● Agent viewed  ⏱ 2.3s ago         │
└─────────────────────────────────────┘
     │
     ├──▶ [child node collapsed] [MED] ▶
     ├──▶ [child node collapsed] [LOW] ▶
     └──▶ [child node expanded]  [HIGH]
              │
              └──▶ ...
```

### Visual Indicators

- **Relevance badge**: `[HIGH]` red, `[MED]` yellow, `[LOW]` gray
- **Expand arrow**: `▶` collapsed, `▼` expanded
- **Agent activity dot**: `●` = agent has read this file
- **Child count**: "(3 calls)" on collapsed nodes
- **Timestamp**: When agent last touched this node

### Interactions

- Click node → Expand/collapse children
- Click relevance badge → Show scoring breakdown
- Hover → Preview function signature and file path
- Double-click → Open full file detail panel

---

## Backend Architecture

### New `CodeGraphService` (replaces `flow_service.py`)

```python
class CodeGraphService:
    async def initialize_graph(agent_id: str, repo_path: str) -> Graph
        """Build graph from discovered entry points."""

    async def expand_node(agent_id: str, node_id: str) -> List[Node]
        """Expand a node's children on demand."""

    def mark_visited(agent_id: str, node_id: str, timestamp: datetime, duration_ms: int)
        """Mark node as visited by agent."""

    def get_graph(agent_id: str) -> Graph
        """Get current graph state."""
```

### Enhanced `call_tree.py`

- Add relevance scoring during AST parsing
- Store content pattern matches per node
- Track graph depth during expansion
- Return relevance score + breakdown with each node

### Updated `react_agent.py`

- On `read_file` → Find matching node → `mark_visited()`
- On investigation start → `initialize_graph()` with entry points
- Remove old `flow_service` calls

### New Endpoints

```
GET  /agents/{id}/graph                    → Full graph state
GET  /agents/{id}/graph/expand/{node_id}   → Expand node children
POST /agents/{id}/graph/entry-points       → Discover entry points
```

---

## Frontend Architecture

### Component Structure

```
CodeGraphVisualization/
├── CodeGraphVisualization.tsx   → Main container, ReactFlow setup
├── CodeGraphNode.tsx            → Single node render
├── CodeGraphNodeDetail.tsx      → Expanded detail panel
├── RelevanceBreakdown.tsx       → Scoring explanation tooltip
└── GraphControls.tsx            → Filter toggles, actions
```

### Layout

- ReactFlow with dagre layout (hierarchical tree)
- Entry points at top/left, children flow down/right
- Collapsed nodes show as single boxes with child count

### Top Bar Controls

- Filter toggles: `[Show High] [Show Medium] [Show Low] [Show Skip]`
- Stats: "Entry points: 5 | Visited: 12/47 | High relevance unvisited: 8"
- Actions: `[Expand All High] [Collapse All] [Reset]`

### State Management

- Track expanded node IDs locally
- Poll `/agents/{id}/graph` for agent visit updates
- Expand requests merge into local state

---

## Entry Point Discovery

Auto-detected patterns by language:

| Language | Patterns |
|----------|----------|
| Python/FastAPI | `@app.get`, `@router.post`, decorators |
| Python | `if __name__ == "__main__"` |
| Python/CLI | `@click.command`, argparse |
| Go | `func main()`, HTTP handlers |
| JS/TS | Express routes, default exports |

---

## Files Changed

| File | Action |
|------|--------|
| `backend/cass/tools/call_tree.py` | Enhance with relevance scoring |
| `backend/services/flow_service.py` | Replace with `code_graph_service.py` |
| `backend/agents/react_agent.py` | Update to mark nodes visited |
| `backend/routers/flow.py` | Replace with `routers/graph.py` |
| `frontend/components/FlowVisualization/` | Replace with `CodeGraphVisualization/` |
| `frontend/types/index.ts` | Update types for graph nodes |

---

## What Gets Removed

- Linear investigation flow concept
- Auto-linking nodes to "previous" node
- Timeline-style visualization
- `FlowNode` type with sequential linking
- `flow_service.py` and its in-memory flow storage
