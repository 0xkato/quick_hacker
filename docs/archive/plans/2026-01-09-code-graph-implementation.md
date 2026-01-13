# Code Graph Visualization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace linear investigation flow with entry-point driven code call graph showing actual codebase structure with relevance scoring.

**Architecture:** Backend builds call graph from entry points with AST parsing, scores nodes by position + content patterns. Frontend renders as collapsible tree with ReactFlow dagre layout. Agent actions highlight visited nodes.

**Tech Stack:** Python AST, FastAPI, ReactFlow with dagre, TypeScript

---

## Task 1: Create Relevance Scoring Module

**Files:**
- Create: `backend/services/relevance_scorer.py`
- Test: `backend/tests/test_relevance_scorer.py`

**Step 1: Create the relevance scorer**

Create `backend/services/relevance_scorer.py`:
```python
"""Relevance scoring for code graph nodes."""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class RelevanceScore:
    """Breakdown of how a node's relevance was calculated."""
    total: int
    level: str  # "high", "medium", "low", "skip"
    content_score: int
    position_score: int
    matched_patterns: list[str]


# Content patterns and their scores
CONTENT_PATTERNS = [
    # Security-critical (+40)
    (40, ["auth", "authentication", "login", "session", "token", "jwt", "oauth"]),
    (40, ["crypto", "encrypt", "decrypt", "hash", "password", "secret"]),
    (40, ["sql", "query", "execute", "cursor", "database"]),
    (40, ["exec", "eval", "subprocess", "shell", "command", "system"]),
    (40, ["input", "request", "body", "params", "user_input", "form"]),
    # Important (+30)
    (30, ["file", "read", "write", "open", "path", "upload"]),
    # Moderate (+20)
    (20, ["http", "api", "endpoint", "route", "handler"]),
    # Low (+10)
    (10, ["config", "settings", "env"]),
    # Negative (tests, logging)
    (-20, ["test", "spec", "mock", "fixture"]),
    (-10, ["log", "print", "debug", "trace"]),
]

# Position scores by depth
POSITION_SCORES = {
    0: 60,  # Entry point
    1: 40,  # Depth 1
    2: 25,  # Depth 2
    3: 15,  # Depth 3
}
DEFAULT_POSITION_SCORE = 5  # Depth 4+


def score_content(text: str) -> tuple[int, list[str]]:
    """Score content based on pattern matching.

    Args:
        text: Combined text of function name, file path, and code content

    Returns:
        Tuple of (score, list of matched pattern groups)
    """
    text_lower = text.lower()
    score = 0
    matched = []

    for points, patterns in CONTENT_PATTERNS:
        for pattern in patterns:
            if pattern in text_lower:
                score += points
                matched.append(pattern)
                break  # Only count each pattern group once

    return score, matched


def score_position(depth: int) -> int:
    """Score based on position in call graph.

    Args:
        depth: Distance from entry point (0 = entry point itself)

    Returns:
        Position score
    """
    return POSITION_SCORES.get(depth, DEFAULT_POSITION_SCORE)


def calculate_relevance(
    function_name: str,
    file_path: str,
    depth: int,
    code_content: Optional[str] = None,
) -> RelevanceScore:
    """Calculate relevance score for a code graph node.

    Args:
        function_name: Name of the function
        file_path: Path to the file containing the function
        depth: Distance from entry point in the call graph
        code_content: Optional function body text for deeper analysis

    Returns:
        RelevanceScore with breakdown
    """
    # Combine text for pattern matching
    text_parts = [function_name, file_path]
    if code_content:
        text_parts.append(code_content)
    combined_text = " ".join(text_parts)

    content_score, matched_patterns = score_content(combined_text)
    position_score = score_position(depth)

    total = max(0, content_score + position_score)  # Floor at 0

    # Determine level
    if total >= 80:
        level = "high"
    elif total >= 50:
        level = "medium"
    elif total >= 20:
        level = "low"
    else:
        level = "skip"

    return RelevanceScore(
        total=total,
        level=level,
        content_score=content_score,
        position_score=position_score,
        matched_patterns=matched_patterns,
    )
```

**Step 2: Write tests**

Create `backend/tests/test_relevance_scorer.py`:
```python
"""Tests for relevance scoring."""

import pytest
from services.relevance_scorer import (
    calculate_relevance,
    score_content,
    score_position,
)


class TestScoreContent:
    def test_auth_patterns_score_high(self):
        score, matched = score_content("authenticate_user login")
        assert score >= 40
        assert "auth" in matched or "login" in matched

    def test_sql_patterns_score_high(self):
        score, matched = score_content("execute_query database")
        assert score >= 40
        assert "execute" in matched or "database" in matched

    def test_test_files_score_negative(self):
        score, matched = score_content("test_something mock_data")
        assert score < 0
        assert "test" in matched or "mock" in matched

    def test_neutral_code_scores_zero(self):
        score, matched = score_content("calculate_total helper_util")
        assert score == 0
        assert matched == []


class TestScorePosition:
    def test_entry_point_scores_highest(self):
        assert score_position(0) == 60

    def test_depth_1_scores_high(self):
        assert score_position(1) == 40

    def test_deep_nodes_score_low(self):
        assert score_position(5) == 5
        assert score_position(10) == 5


class TestCalculateRelevance:
    def test_auth_at_depth_1_is_high(self):
        result = calculate_relevance("authenticate", "auth/handler.py", 1)
        assert result.level == "high"
        assert result.total >= 80

    def test_test_file_is_skip(self):
        result = calculate_relevance("test_auth", "tests/test_auth.py", 3)
        assert result.level == "skip"
        assert result.total < 20

    def test_utility_at_depth_3_is_low(self):
        result = calculate_relevance("format_string", "utils/helpers.py", 3)
        assert result.level == "low"

    def test_entry_point_with_route_is_high(self):
        result = calculate_relevance("get_users", "api/routes.py", 0)
        assert result.level == "high"
        assert result.position_score == 60
```

**Step 3: Run tests**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && pytest tests/test_relevance_scorer.py -v`
Expected: All tests pass

**Step 4: Commit**

```bash
git add backend/services/relevance_scorer.py backend/tests/test_relevance_scorer.py
git commit -m "feat: add relevance scoring module for code graph nodes"
```

---

## Task 2: Create Code Graph Data Models

**Files:**
- Create: `backend/models/code_graph.py`

**Step 1: Create data models**

Create `backend/models/code_graph.py`:
```python
"""Data models for code graph visualization."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Literal


NodeType = Literal["entry_point", "function", "external", "cycle"]
RelevanceLevel = Literal["high", "medium", "low", "skip"]


@dataclass
class GraphNode:
    """A node in the code call graph."""
    id: str
    type: NodeType
    label: str  # Function name or route path
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    module: Optional[str] = None

    # Relevance scoring
    relevance_level: RelevanceLevel = "low"
    relevance_score: int = 0
    relevance_breakdown: dict = field(default_factory=dict)

    # Expansion state
    is_expanded: bool = False
    child_count: int = 0
    children_loaded: bool = False

    # Agent activity
    visited: bool = False
    visited_at: Optional[str] = None
    visit_duration_ms: Optional[int] = None

    # Additional data
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GraphEdge:
    """An edge connecting two nodes in the call graph."""
    id: str
    source: str
    target: str
    label: Optional[str] = "calls"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CodeGraph:
    """The complete code call graph for an agent session."""
    agent_id: str
    repo_path: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    entry_point_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "repo_path": self.repo_path,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "entry_point_ids": self.entry_point_ids,
            "created_at": self.created_at,
        }

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Find a node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_stats(self) -> dict:
        """Get summary statistics."""
        visited_count = sum(1 for n in self.nodes if n.visited)
        high_unvisited = sum(
            1 for n in self.nodes
            if n.relevance_level == "high" and not n.visited
        )

        level_counts = {"high": 0, "medium": 0, "low": 0, "skip": 0}
        for node in self.nodes:
            level_counts[node.relevance_level] += 1

        return {
            "total_nodes": len(self.nodes),
            "entry_points": len(self.entry_point_ids),
            "visited": visited_count,
            "high_relevance_unvisited": high_unvisited,
            "by_relevance": level_counts,
        }
```

**Step 2: Commit**

```bash
git add backend/models/code_graph.py
git commit -m "feat: add code graph data models"
```

---

## Task 3: Create Code Graph Service

**Files:**
- Create: `backend/services/code_graph_service.py`

**Step 1: Create the service**

Create `backend/services/code_graph_service.py`:
```python
"""Code Graph Service - Manages code call graphs for agents."""

import uuid
from datetime import datetime
from typing import Optional, Callable
from collections import defaultdict
from pathlib import Path

from models.code_graph import CodeGraph, GraphNode, GraphEdge
from services.relevance_scorer import calculate_relevance
from cass.tools.call_tree import CallTreeBuilder


class CodeGraphService:
    """Manages code call graphs for agent sessions."""

    def __init__(self):
        self._graphs: dict[str, CodeGraph] = {}
        self._subscribers: dict[str, set[Callable]] = defaultdict(set)
        self._builders: dict[str, CallTreeBuilder] = {}

    async def initialize_graph(self, agent_id: str, repo_path: str) -> CodeGraph:
        """Initialize a code graph for an agent by discovering entry points.

        Args:
            agent_id: The agent session ID
            repo_path: Path to the repository

        Returns:
            The initialized CodeGraph with entry points as root nodes
        """
        # Create call tree builder for this repo
        builder = CallTreeBuilder(repo_path)
        self._builders[agent_id] = builder

        # Discover FastAPI routes as entry points
        routes = builder.list_fastapi_routes()

        graph = CodeGraph(agent_id=agent_id, repo_path=repo_path)

        # Create entry point nodes
        for route in routes:
            node_id = f"ep_{route['id']}"

            # Calculate relevance (entry points are depth 0)
            relevance = calculate_relevance(
                function_name=route.get("handler", ""),
                file_path=route.get("file", ""),
                depth=0,
            )

            node = GraphNode(
                id=node_id,
                type="entry_point",
                label=f"{route['method']} {route['path']}",
                file_path=route.get("file"),
                line_number=route.get("line"),
                relevance_level=relevance.level,
                relevance_score=relevance.total,
                relevance_breakdown={
                    "content_score": relevance.content_score,
                    "position_score": relevance.position_score,
                    "matched_patterns": relevance.matched_patterns,
                },
                data={
                    "route_id": route["id"],
                    "method": route.get("method"),
                    "path": route.get("path"),
                    "handler": route.get("handler"),
                },
            )

            graph.nodes.append(node)
            graph.entry_point_ids.append(node_id)

        self._graphs[agent_id] = graph
        self._notify_subscribers(agent_id)
        return graph

    async def expand_node(self, agent_id: str, node_id: str) -> list[GraphNode]:
        """Expand a node to show its children (functions it calls).

        Args:
            agent_id: The agent session ID
            node_id: The node to expand

        Returns:
            List of newly added child nodes
        """
        graph = self._graphs.get(agent_id)
        if not graph:
            return []

        node = graph.get_node(node_id)
        if not node or node.children_loaded:
            return []

        builder = self._builders.get(agent_id)
        if not builder:
            return []

        new_nodes = []

        # For entry points, build the call tree from the route
        if node.type == "entry_point" and node.data.get("route_id"):
            route = {
                "id": node.data["route_id"],
                "method": node.data.get("method"),
                "path": node.data.get("path"),
                "handler": node.data.get("handler"),
                "file": node.file_path,
                "line": node.line_number,
            }

            tree = builder.build_call_tree(route, max_depth=2, max_nodes=50)

            # Skip first two nodes (route + handler) as we already have the entry point
            tree_nodes = tree.get("nodes", [])[2:]
            tree_edges = tree.get("edges", [])[1:]

            # Map old node IDs to new ones
            id_map = {node.data["route_id"]: node_id}

            # Find handler node ID from original tree
            original_edges = tree.get("edges", [])
            if original_edges:
                handler_id = original_edges[0].get("target")
                if handler_id:
                    id_map[handler_id] = node_id

            # Calculate depth based on position
            depth = 1  # Children of entry point

            for tree_node in tree_nodes:
                old_id = tree_node["id"]
                new_id = f"{node_id}_{old_id}"
                id_map[old_id] = new_id

                # Calculate relevance
                relevance = calculate_relevance(
                    function_name=tree_node.get("label", ""),
                    file_path=tree_node.get("data", {}).get("file", ""),
                    depth=depth,
                )

                child_node = GraphNode(
                    id=new_id,
                    type=tree_node.get("type", "function"),
                    label=tree_node.get("label", ""),
                    file_path=tree_node.get("data", {}).get("file"),
                    line_number=tree_node.get("data", {}).get("line"),
                    module=tree_node.get("data", {}).get("module"),
                    relevance_level=relevance.level,
                    relevance_score=relevance.total,
                    relevance_breakdown={
                        "content_score": relevance.content_score,
                        "position_score": relevance.position_score,
                        "matched_patterns": relevance.matched_patterns,
                    },
                    data=tree_node.get("data", {}),
                )

                graph.nodes.append(child_node)
                new_nodes.append(child_node)

            # Add edges with mapped IDs
            for tree_edge in tree_edges:
                source = id_map.get(tree_edge["source"], tree_edge["source"])
                target = id_map.get(tree_edge["target"], tree_edge["target"])

                edge = GraphEdge(
                    id=f"e_{uuid.uuid4().hex[:8]}",
                    source=source,
                    target=target,
                    label=tree_edge.get("label"),
                )
                graph.edges.append(edge)

        node.is_expanded = True
        node.children_loaded = True
        node.child_count = len(new_nodes)

        self._notify_subscribers(agent_id)
        return new_nodes

    def mark_visited(
        self,
        agent_id: str,
        file_path: str,
        duration_ms: Optional[int] = None,
    ) -> Optional[GraphNode]:
        """Mark nodes matching a file path as visited by the agent.

        Args:
            agent_id: The agent session ID
            file_path: Path to the file the agent visited
            duration_ms: How long the agent spent on this file

        Returns:
            The first matching node that was marked, or None
        """
        graph = self._graphs.get(agent_id)
        if not graph:
            return None

        # Normalize path for comparison
        file_path_normalized = str(Path(file_path))
        marked_node = None

        for node in graph.nodes:
            if node.file_path and file_path_normalized in str(node.file_path):
                if not node.visited:
                    node.visited = True
                    node.visited_at = datetime.utcnow().isoformat()
                    node.visit_duration_ms = duration_ms
                    if marked_node is None:
                        marked_node = node

        if marked_node:
            self._notify_subscribers(agent_id)

        return marked_node

    def get_graph(self, agent_id: str) -> Optional[CodeGraph]:
        """Get the code graph for an agent."""
        return self._graphs.get(agent_id)

    def clear_graph(self, agent_id: str) -> None:
        """Clear the graph for an agent."""
        if agent_id in self._graphs:
            del self._graphs[agent_id]
        if agent_id in self._builders:
            del self._builders[agent_id]
        if agent_id in self._subscribers:
            del self._subscribers[agent_id]

    def subscribe(self, agent_id: str, callback: Callable) -> Callable:
        """Subscribe to graph updates. Returns unsubscribe function."""
        self._subscribers[agent_id].add(callback)

        # Send current state immediately
        graph = self._graphs.get(agent_id)
        if graph:
            callback(graph.to_dict())

        def unsubscribe():
            self._subscribers[agent_id].discard(callback)

        return unsubscribe

    def _notify_subscribers(self, agent_id: str) -> None:
        """Notify subscribers of a graph update."""
        graph = self._graphs.get(agent_id)
        if not graph:
            return

        for callback in self._subscribers.get(agent_id, []):
            try:
                callback(graph.to_dict())
            except Exception:
                pass


# Global instance
code_graph_service = CodeGraphService()
```

**Step 2: Commit**

```bash
git add backend/services/code_graph_service.py
git commit -m "feat: add code graph service with entry point discovery and expansion"
```

---

## Task 4: Create Graph Router

**Files:**
- Create: `backend/routers/graph.py`
- Modify: `backend/main.py`

**Step 1: Create the graph router**

Create `backend/routers/graph.py`:
```python
"""Graph router - API endpoints for code graph visualization."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from services.code_graph_service import code_graph_service


router = APIRouter()


class InitializeGraphRequest(BaseModel):
    repo_path: str


@router.post("/agents/{agent_id}/graph/initialize")
async def initialize_graph(agent_id: str, request: InitializeGraphRequest):
    """Initialize a code graph for an agent by discovering entry points."""
    graph = await code_graph_service.initialize_graph(agent_id, request.repo_path)
    return graph.to_dict()


@router.get("/agents/{agent_id}/graph")
async def get_graph(agent_id: str):
    """Get the code graph for an agent."""
    graph = code_graph_service.get_graph(agent_id)
    if not graph:
        return {
            "agent_id": agent_id,
            "repo_path": "",
            "nodes": [],
            "edges": [],
            "entry_point_ids": [],
        }
    return graph.to_dict()


@router.get("/agents/{agent_id}/graph/stats")
async def get_graph_stats(agent_id: str):
    """Get graph statistics for an agent."""
    graph = code_graph_service.get_graph(agent_id)
    if not graph:
        return {
            "total_nodes": 0,
            "entry_points": 0,
            "visited": 0,
            "high_relevance_unvisited": 0,
            "by_relevance": {"high": 0, "medium": 0, "low": 0, "skip": 0},
        }
    return graph.get_stats()


@router.post("/agents/{agent_id}/graph/expand/{node_id}")
async def expand_node(agent_id: str, node_id: str):
    """Expand a node to show its children."""
    new_nodes = await code_graph_service.expand_node(agent_id, node_id)
    return {
        "expanded_node_id": node_id,
        "new_nodes": [n.to_dict() for n in new_nodes],
    }


class MarkVisitedRequest(BaseModel):
    file_path: str
    duration_ms: Optional[int] = None


@router.post("/agents/{agent_id}/graph/mark-visited")
async def mark_visited(agent_id: str, request: MarkVisitedRequest):
    """Mark a file as visited by the agent."""
    node = code_graph_service.mark_visited(
        agent_id,
        request.file_path,
        request.duration_ms
    )
    return {
        "marked": node is not None,
        "node_id": node.id if node else None,
    }


@router.delete("/agents/{agent_id}/graph")
async def clear_graph(agent_id: str):
    """Clear the graph for an agent."""
    code_graph_service.clear_graph(agent_id)
    return {"status": "cleared"}
```

**Step 2: Add router to main.py**

Find the router imports section in `backend/main.py` and add:
```python
from routers.graph import router as graph_router
```

Find where routers are included and add:
```python
app.include_router(graph_router, tags=["graph"])
```

**Step 3: Commit**

```bash
git add backend/routers/graph.py backend/main.py
git commit -m "feat: add graph router with initialize, expand, and mark-visited endpoints"
```

---

## Task 5: Add Frontend Graph Types

**Files:**
- Modify: `frontend/types/index.ts`

**Step 1: Add graph types**

Add to `frontend/types/index.ts` after the existing Flow types:
```typescript
// === Code Graph ===

export type GraphNodeType = 'entry_point' | 'function' | 'external' | 'cycle';
export type RelevanceLevel = 'high' | 'medium' | 'low' | 'skip';

export interface RelevanceBreakdown {
  content_score: number;
  position_score: number;
  matched_patterns: string[];
}

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  file_path?: string;
  line_number?: number;
  module?: string;

  // Relevance
  relevance_level: RelevanceLevel;
  relevance_score: number;
  relevance_breakdown: RelevanceBreakdown;

  // Expansion
  is_expanded: boolean;
  child_count: number;
  children_loaded: boolean;

  // Agent activity
  visited: boolean;
  visited_at?: string;
  visit_duration_ms?: number;

  // Additional data
  data?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface CodeGraph {
  agent_id: string;
  repo_path: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  entry_point_ids: string[];
  created_at: string;
}

export interface GraphStats {
  total_nodes: number;
  entry_points: number;
  visited: number;
  high_relevance_unvisited: number;
  by_relevance: Record<RelevanceLevel, number>;
}
```

**Step 2: Commit**

```bash
git add frontend/types/index.ts
git commit -m "feat: add TypeScript types for code graph visualization"
```

---

## Task 6: Create CodeGraphNode Component

**Files:**
- Create: `frontend/components/CodeGraphVisualization/CodeGraphNode.tsx`

**Step 1: Create the node component**

Create directory and file:
```bash
mkdir -p frontend/components/CodeGraphVisualization
```

Create `frontend/components/CodeGraphVisualization/CodeGraphNode.tsx`:
```tsx
'use client';

import { memo } from 'react';
import { Handle, Position } from 'reactflow';
import {
  Network,
  Code,
  FileText,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  Circle,
} from 'lucide-react';
import clsx from 'clsx';
import type { GraphNode as GraphNodeType } from '@/types';

interface CodeGraphNodeProps {
  data: GraphNodeType & {
    onExpand?: (nodeId: string) => void;
  };
}

const typeIcons: Record<string, React.ReactNode> = {
  entry_point: <Network className="w-4 h-4" />,
  function: <Code className="w-4 h-4" />,
  external: <FileText className="w-4 h-4 text-vsc-text-muted" />,
  cycle: <RefreshCw className="w-4 h-4 text-sev-medium" />,
};

const relevanceColors: Record<string, string> = {
  high: 'border-sev-critical bg-sev-critical/10',
  medium: 'border-sev-medium bg-sev-medium/10',
  low: 'border-vsc-border bg-vsc-sidebar',
  skip: 'border-vsc-border-subtle bg-vsc-bg opacity-60',
};

const relevanceBadgeColors: Record<string, string> = {
  high: 'bg-sev-critical text-white',
  medium: 'bg-sev-medium text-black',
  low: 'bg-vsc-border text-vsc-text-muted',
  skip: 'bg-vsc-border-subtle text-vsc-text-muted',
};

function CodeGraphNodeComponent({ data }: CodeGraphNodeProps) {
  const canExpand = data.type !== 'external' && data.type !== 'cycle' && !data.children_loaded;
  const isExpanded = data.is_expanded;

  const handleExpandClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (canExpand && data.onExpand) {
      data.onExpand(data.id);
    }
  };

  return (
    <div
      className={clsx(
        'px-3 py-2 rounded-lg border-2 min-w-[180px] max-w-[280px]',
        'transition-all duration-150 hover:shadow-lg cursor-pointer',
        relevanceColors[data.relevance_level],
        data.visited && 'ring-2 ring-vsc-accent ring-offset-1 ring-offset-vsc-bg'
      )}
    >
      <Handle type="target" position={Position.Top} className="!bg-vsc-border" />

      {/* Header row */}
      <div className="flex items-center gap-2">
        <span className="text-vsc-text-muted">
          {typeIcons[data.type] || <Code className="w-4 h-4" />}
        </span>

        <span className="text-sm font-medium truncate flex-1 text-vsc-text">
          {data.label}
        </span>

        {/* Relevance badge */}
        <span
          className={clsx(
            'text-xs px-1.5 py-0.5 rounded font-medium uppercase',
            relevanceBadgeColors[data.relevance_level]
          )}
        >
          {data.relevance_level === 'high' ? 'HIGH' :
           data.relevance_level === 'medium' ? 'MED' :
           data.relevance_level === 'low' ? 'LOW' : 'SKIP'}
        </span>

        {/* Expand button */}
        {(canExpand || isExpanded) && (
          <button
            onClick={handleExpandClick}
            className="p-0.5 hover:bg-vsc-border rounded"
            disabled={!canExpand}
          >
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-vsc-text-muted" />
            ) : (
              <ChevronRight className="w-4 h-4 text-vsc-text-muted" />
            )}
          </button>
        )}
      </div>

      {/* File path */}
      {data.file_path && (
        <div className="text-xs text-vsc-text-muted truncate mt-1">
          {data.file_path}
          {data.line_number && `:${data.line_number}`}
        </div>
      )}

      {/* Footer row */}
      <div className="flex items-center justify-between mt-1.5">
        {/* Visited indicator */}
        <div className="flex items-center gap-1">
          {data.visited ? (
            <>
              <Circle className="w-2 h-2 fill-vsc-accent text-vsc-accent" />
              <span className="text-xs text-vsc-text-muted">Viewed</span>
            </>
          ) : (
            <span className="text-xs text-vsc-text-muted">
              {data.child_count > 0 && `(${data.child_count} calls)`}
            </span>
          )}
        </div>

        {/* Duration if visited */}
        {data.visit_duration_ms && (
          <span className="text-xs text-vsc-text-muted">
            {data.visit_duration_ms}ms
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-vsc-border" />
    </div>
  );
}

export const CodeGraphNode = memo(CodeGraphNodeComponent);
```

**Step 2: Commit**

```bash
git add frontend/components/CodeGraphVisualization/CodeGraphNode.tsx
git commit -m "feat: add CodeGraphNode component with relevance badges and expand button"
```

---

## Task 7: Create Main CodeGraphVisualization Component

**Files:**
- Create: `frontend/components/CodeGraphVisualization/CodeGraphVisualization.tsx`
- Create: `frontend/components/CodeGraphVisualization/index.ts`

**Step 1: Create main visualization component**

Create `frontend/components/CodeGraphVisualization/CodeGraphVisualization.tsx`:
```tsx
'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';
import { Filter, Expand, Minimize2, RotateCcw } from 'lucide-react';
import clsx from 'clsx';

import { CodeGraphNode } from './CodeGraphNode';
import type { CodeGraph, GraphNode, GraphEdge, RelevanceLevel, GraphStats } from '@/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface CodeGraphVisualizationProps {
  agentId: string | null;
  repoPath?: string;
}

const nodeTypes = {
  graphNode: CodeGraphNode,
};

// Layout using dagre
function getLayoutedElements(
  nodes: Node[],
  edges: Edge[],
  direction: 'TB' | 'LR' = 'TB'
) {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: direction, nodesep: 50, ranksep: 80 });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 200, height: 80 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 100,
        y: nodeWithPosition.y - 40,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

export function CodeGraphVisualization({ agentId, repoPath }: CodeGraphVisualizationProps) {
  const [graph, setGraph] = useState<CodeGraph | null>(null);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [filters, setFilters] = useState<Set<RelevanceLevel>>(
    new Set(['high', 'medium', 'low'])
  );
  const [isLoading, setIsLoading] = useState(false);

  // Fetch graph data
  const fetchGraph = useCallback(async () => {
    if (!agentId) return;

    try {
      const response = await fetch(`${API_BASE}/agents/${agentId}/graph`);
      if (response.ok) {
        const data = await response.json();
        setGraph(data);
      }
    } catch (error) {
      console.error('Failed to fetch graph:', error);
    }
  }, [agentId]);

  // Fetch stats
  const fetchStats = useCallback(async () => {
    if (!agentId) return;

    try {
      const response = await fetch(`${API_BASE}/agents/${agentId}/graph/stats`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  }, [agentId]);

  // Initialize graph
  const initializeGraph = useCallback(async () => {
    if (!agentId || !repoPath) return;

    setIsLoading(true);
    try {
      const response = await fetch(`${API_BASE}/agents/${agentId}/graph/initialize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_path: repoPath }),
      });
      if (response.ok) {
        const data = await response.json();
        setGraph(data);
      }
    } catch (error) {
      console.error('Failed to initialize graph:', error);
    } finally {
      setIsLoading(false);
    }
  }, [agentId, repoPath]);

  // Expand node
  const handleExpandNode = useCallback(async (nodeId: string) => {
    if (!agentId) return;

    try {
      const response = await fetch(
        `${API_BASE}/agents/${agentId}/graph/expand/${nodeId}`,
        { method: 'POST' }
      );
      if (response.ok) {
        fetchGraph();
      }
    } catch (error) {
      console.error('Failed to expand node:', error);
    }
  }, [agentId, fetchGraph]);

  // Convert graph data to ReactFlow format
  useEffect(() => {
    if (!graph) return;

    const filteredNodes = graph.nodes.filter(
      (n) => filters.has(n.relevance_level)
    );

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = graph.edges.filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    const rfNodes: Node[] = filteredNodes.map((node) => ({
      id: node.id,
      type: 'graphNode',
      position: { x: 0, y: 0 },
      data: { ...node, onExpand: handleExpandNode },
    }));

    const rfEdges: Edge[] = filteredEdges.map((edge) => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.label,
      markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: '#404040' },
    }));

    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
      rfNodes,
      rfEdges
    );

    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
  }, [graph, filters, handleExpandNode, setNodes, setEdges]);

  // Initial fetch
  useEffect(() => {
    fetchGraph();
    fetchStats();

    // Poll for updates
    const interval = setInterval(() => {
      fetchGraph();
      fetchStats();
    }, 5000);

    return () => clearInterval(interval);
  }, [fetchGraph, fetchStats]);

  // Filter toggle
  const toggleFilter = (level: RelevanceLevel) => {
    setFilters((prev) => {
      const next = new Set(prev);
      if (next.has(level)) {
        next.delete(level);
      } else {
        next.add(level);
      }
      return next;
    });
  };

  if (!agentId) {
    return (
      <div className="flex items-center justify-center h-full text-vsc-text-muted">
        Select an agent to view code graph
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Controls bar */}
      <div className="flex items-center justify-between p-2 border-b border-vsc-border bg-vsc-sidebar">
        {/* Filters */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-vsc-text-muted" />
          {(['high', 'medium', 'low', 'skip'] as RelevanceLevel[]).map((level) => (
            <button
              key={level}
              onClick={() => toggleFilter(level)}
              className={clsx(
                'px-2 py-1 text-xs rounded font-medium uppercase transition-colors',
                filters.has(level)
                  ? level === 'high'
                    ? 'bg-sev-critical text-white'
                    : level === 'medium'
                    ? 'bg-sev-medium text-black'
                    : level === 'low'
                    ? 'bg-vsc-border text-vsc-text'
                    : 'bg-vsc-border-subtle text-vsc-text-muted'
                  : 'bg-vsc-bg text-vsc-text-muted border border-vsc-border'
              )}
            >
              {level}
            </button>
          ))}
        </div>

        {/* Stats */}
        {stats && (
          <div className="flex items-center gap-4 text-xs text-vsc-text-muted">
            <span>Entry points: {stats.entry_points}</span>
            <span>Visited: {stats.visited}/{stats.total_nodes}</span>
            <span className="text-sev-critical">
              High unvisited: {stats.high_relevance_unvisited}
            </span>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2">
          {repoPath && (
            <button
              onClick={initializeGraph}
              disabled={isLoading}
              className="px-2 py-1 text-xs bg-vsc-accent text-white rounded hover:bg-vsc-accent/80 disabled:opacity-50"
            >
              {isLoading ? 'Loading...' : 'Refresh'}
            </button>
          )}
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.1}
          maxZoom={2}
        >
          <Background color="#333" gap={16} />
          <Controls />
          <MiniMap
            nodeColor={(node) => {
              const data = node.data as GraphNode;
              if (data.visited) return '#007acc';
              switch (data.relevance_level) {
                case 'high': return '#e51400';
                case 'medium': return '#e5a000';
                case 'low': return '#404040';
                default: return '#252525';
              }
            }}
          />
        </ReactFlow>
      </div>
    </div>
  );
}
```

**Step 2: Create index export**

Create `frontend/components/CodeGraphVisualization/index.ts`:
```typescript
export { CodeGraphVisualization } from './CodeGraphVisualization';
export { CodeGraphNode } from './CodeGraphNode';
```

**Step 3: Install dagre**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/frontend && npm install dagre @types/dagre`

**Step 4: Commit**

```bash
git add frontend/components/CodeGraphVisualization/ frontend/package.json frontend/package-lock.json
git commit -m "feat: add CodeGraphVisualization component with dagre layout and filtering"
```

---

## Task 8: Update React Agent to Use Code Graph

**Files:**
- Modify: `backend/agents/react_agent.py`

**Step 1: Add code graph integration**

Find the imports at the top of `backend/agents/react_agent.py` and add:
```python
from services.code_graph_service import code_graph_service
```

Find where `flow_service.initialize_flow` is called (around line 227) and add after it:
```python
# Initialize code graph for visualization
try:
    await code_graph_service.initialize_graph(self.id, self.repo_path)
except Exception as e:
    self.logger.warning(f"Failed to initialize code graph: {e}")
```

Find where `read_file` tool results are processed and add code to mark visited:
```python
# After successful file read, mark in code graph
if tool_name == "read_file":
    file_path = arguments.get("path", "")
    code_graph_service.mark_visited(self.id, file_path, duration_ms)
```

**Step 2: Commit**

```bash
git add backend/agents/react_agent.py
git commit -m "feat: integrate code graph service with react agent for file visit tracking"
```

---

## Task 9: Add API Client Methods for Graph

**Files:**
- Modify: `frontend/lib/api.ts`

**Step 1: Add graph API methods**

Add to `frontend/lib/api.ts`:
```typescript
// Code Graph API
export const codeGraph = {
  async initialize(agentId: string, repoPath: string): Promise<CodeGraph> {
    return request<CodeGraph>(`/agents/${agentId}/graph/initialize`, {
      method: 'POST',
      body: JSON.stringify({ repo_path: repoPath }),
    });
  },

  async get(agentId: string): Promise<CodeGraph> {
    return request<CodeGraph>(`/agents/${agentId}/graph`);
  },

  async getStats(agentId: string): Promise<GraphStats> {
    return request<GraphStats>(`/agents/${agentId}/graph/stats`);
  },

  async expandNode(agentId: string, nodeId: string): Promise<{ expanded_node_id: string; new_nodes: GraphNode[] }> {
    return request(`/agents/${agentId}/graph/expand/${nodeId}`, {
      method: 'POST',
    });
  },

  async markVisited(agentId: string, filePath: string, durationMs?: number): Promise<{ marked: boolean; node_id?: string }> {
    return request(`/agents/${agentId}/graph/mark-visited`, {
      method: 'POST',
      body: JSON.stringify({ file_path: filePath, duration_ms: durationMs }),
    });
  },

  async clear(agentId: string): Promise<void> {
    return request(`/agents/${agentId}/graph`, { method: 'DELETE' });
  },
};
```

Also add the type imports at the top:
```typescript
import type { CodeGraph, GraphStats, GraphNode } from '@/types';
```

**Step 2: Commit**

```bash
git add frontend/lib/api.ts
git commit -m "feat: add API client methods for code graph operations"
```

---

## Task 10: Integration Test

**Files:**
- None (manual testing)

**Step 1: Run backend tests**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && pytest tests/test_relevance_scorer.py -v`
Expected: All tests pass

**Step 2: Start services**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack && docker-compose up -d`

**Step 3: Test graph initialization**

Run:
```bash
curl -X POST http://localhost:8000/agents/test-agent/graph/initialize \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/your/repo"}'
```
Expected: Returns graph with entry points

**Step 4: Test node expansion**

Run:
```bash
curl -X POST http://localhost:8000/agents/test-agent/graph/expand/ep_xxxxx
```
Expected: Returns new child nodes

**Step 5: Verify frontend**

Open http://localhost:3000, start an agent, verify the code graph visualization shows entry points with relevance badges.

---

## Summary

This plan implements:

1. **Relevance scoring module** - Scores nodes by content patterns + graph position
2. **Code graph data models** - GraphNode, GraphEdge, CodeGraph with relevance and visit tracking
3. **Code graph service** - Manages graphs, entry point discovery, node expansion, visit marking
4. **Graph router** - REST endpoints for graph operations
5. **Frontend types** - TypeScript interfaces for graph data
6. **CodeGraphNode component** - Visual node with relevance badge, expand button, visit indicator
7. **CodeGraphVisualization** - Main component with dagre layout, filtering, stats
8. **React agent integration** - Initializes graph, marks visited files
9. **API client** - Frontend methods for graph operations

Total tasks: 10
