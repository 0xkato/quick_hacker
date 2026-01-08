# CASS Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a two-phase security scanner that maps codebase architecture into a knowledge graph before running deep security analysis with Ultrathink.

**Architecture:** Agentic explorer builds knowledge graph using 50+ tools, user reviews graph, then scanner generates attack surface candidates and feeds rich context to Ultrathink cascade.

**Tech Stack:** Python 3.10+, FastAPI, Pydantic, asyncio, React/TypeScript, ReactFlow for graph visualization.

---

## Task 1: Knowledge Graph Schema

**Files:**
- Create: `backend/cass/__init__.py`
- Create: `backend/cass/graph/__init__.py`
- Create: `backend/cass/graph/schema.py`
- Test: `backend/tests/cass/test_graph_schema.py`

**Step 1: Create package structure**

```bash
mkdir -p backend/cass/graph
touch backend/cass/__init__.py
touch backend/cass/graph/__init__.py
```

**Step 2: Write the failing test**

```python
# backend/tests/cass/test_graph_schema.py
"""Tests for knowledge graph schema."""

import pytest
from cass.graph.schema import (
    NodeType,
    RelationshipType,
    Node,
    Relationship,
    NodeProperties,
)


def test_node_types_exist():
    """All security-critical node types should be defined."""
    assert NodeType.ENTRY_POINT
    assert NodeType.INPUT_VECTOR
    assert NodeType.DATA_SINK
    assert NodeType.VALIDATOR
    assert NodeType.AUTH_CHECK
    assert NodeType.DATA_CLASSIFICATION
    assert NodeType.SECRET
    assert NodeType.DEPENDENCY


def test_relationship_types_exist():
    """All relationship types should be defined."""
    assert RelationshipType.RECEIVES_INPUT
    assert RelationshipType.FLOWS_TO
    assert RelationshipType.VALIDATES
    assert RelationshipType.AUTHENTICATES
    assert RelationshipType.HANDLES_DATA
    assert RelationshipType.DEPENDS_ON
    assert RelationshipType.CALLS


def test_node_creation():
    """Nodes should be creatable with type and properties."""
    node = Node(
        id="node-1",
        type=NodeType.ENTRY_POINT,
        properties=NodeProperties(
            name="/api/login",
            file_path="src/routes/auth.py",
            line_number=42,
            metadata={"method": "POST"},
        ),
    )
    assert node.id == "node-1"
    assert node.type == NodeType.ENTRY_POINT
    assert node.properties.name == "/api/login"


def test_relationship_creation():
    """Relationships connect two nodes."""
    rel = Relationship(
        id="rel-1",
        type=RelationshipType.RECEIVES_INPUT,
        source_id="node-1",
        target_id="node-2",
        properties={"validated": False},
    )
    assert rel.source_id == "node-1"
    assert rel.target_id == "node-2"
```

**Step 3: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_graph_schema.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'cass'`

**Step 4: Write minimal implementation**

```python
# backend/cass/graph/schema.py
"""Knowledge graph schema definitions."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    """Types of nodes in the knowledge graph."""
    # Entry points
    ENTRY_POINT = "entry_point"
    HTTP_ROUTE = "http_route"
    GRAPHQL_RESOLVER = "graphql_resolver"
    WEBSOCKET_HANDLER = "websocket_handler"
    CLI_COMMAND = "cli_command"
    EVENT_LISTENER = "event_listener"

    # Input vectors
    INPUT_VECTOR = "input_vector"
    QUERY_PARAM = "query_param"
    REQUEST_BODY = "request_body"
    HEADER = "header"
    COOKIE = "cookie"
    FILE_UPLOAD = "file_upload"
    ENV_VAR = "env_var"

    # Data flow
    DATA_SINK = "data_sink"
    SQL_QUERY = "sql_query"
    COMMAND_EXEC = "command_exec"
    FILE_OPERATION = "file_operation"
    NETWORK_REQUEST = "network_request"
    MEMORY_OPERATION = "memory_operation"

    # Security
    VALIDATOR = "validator"
    SANITIZER = "sanitizer"
    AUTH_CHECK = "auth_check"
    AUTHZ_CHECK = "authz_check"

    # Data
    DATA_CLASSIFICATION = "data_classification"
    PII_FIELD = "pii_field"
    SECRET = "secret"
    CRYPTO_OPERATION = "crypto_operation"

    # Code structure
    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"
    DEPENDENCY = "dependency"


class RelationshipType(str, Enum):
    """Types of relationships between nodes."""
    RECEIVES_INPUT = "receives_input"
    FLOWS_TO = "flows_to"
    VALIDATES = "validates"
    SANITIZES = "sanitizes"
    AUTHENTICATES = "authenticates"
    AUTHORIZES = "authorizes"
    HANDLES_DATA = "handles_data"
    DEPENDS_ON = "depends_on"
    CALLS = "calls"
    IMPORTS = "imports"
    RETURNS = "returns"
    CONTAINS = "contains"


class NodeProperties(BaseModel):
    """Properties attached to a node."""
    name: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    risk_score: Optional[float] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Node(BaseModel):
    """A node in the knowledge graph."""
    id: str
    type: NodeType
    properties: NodeProperties
    tags: list[str] = Field(default_factory=list)
    explored: bool = False


class Relationship(BaseModel):
    """A relationship between two nodes."""
    id: str
    type: RelationshipType
    source_id: str
    target_id: str
    properties: dict[str, Any] = Field(default_factory=dict)
```

**Step 5: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_graph_schema.py -v
```

Expected: PASS (4 tests)

**Step 6: Commit**

```bash
git add backend/cass/ backend/tests/cass/
git commit -m "feat(cass): add knowledge graph schema with node and relationship types"
```

---

## Task 2: Knowledge Graph Store

**Files:**
- Create: `backend/cass/graph/store.py`
- Test: `backend/tests/cass/test_graph_store.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_graph_store.py
"""Tests for knowledge graph store."""

import pytest
from cass.graph.schema import Node, NodeType, NodeProperties, Relationship, RelationshipType
from cass.graph.store import KnowledgeGraph


@pytest.fixture
def graph():
    return KnowledgeGraph()


@pytest.fixture
def sample_nodes():
    return [
        Node(
            id="route-1",
            type=NodeType.HTTP_ROUTE,
            properties=NodeProperties(name="/login", file_path="auth.py", line_number=10),
        ),
        Node(
            id="param-1",
            type=NodeType.QUERY_PARAM,
            properties=NodeProperties(name="username", file_path="auth.py", line_number=10),
        ),
        Node(
            id="sink-1",
            type=NodeType.SQL_QUERY,
            properties=NodeProperties(name="db.execute", file_path="auth.py", line_number=25),
        ),
    ]


def test_add_node(graph, sample_nodes):
    """Can add nodes to graph."""
    graph.add_node(sample_nodes[0])
    assert graph.get_node("route-1") is not None
    assert graph.get_node("route-1").type == NodeType.HTTP_ROUTE


def test_add_relationship(graph, sample_nodes):
    """Can add relationships between nodes."""
    for node in sample_nodes:
        graph.add_node(node)

    rel = Relationship(
        id="rel-1",
        type=RelationshipType.RECEIVES_INPUT,
        source_id="route-1",
        target_id="param-1",
    )
    graph.add_relationship(rel)

    rels = graph.get_relationships("route-1")
    assert len(rels) == 1
    assert rels[0].target_id == "param-1"


def test_query_by_type(graph, sample_nodes):
    """Can query nodes by type."""
    for node in sample_nodes:
        graph.add_node(node)

    routes = graph.query_nodes(type=NodeType.HTTP_ROUTE)
    assert len(routes) == 1
    assert routes[0].id == "route-1"


def test_find_path(graph, sample_nodes):
    """Can find paths between nodes."""
    for node in sample_nodes:
        graph.add_node(node)

    graph.add_relationship(Relationship(
        id="rel-1", type=RelationshipType.RECEIVES_INPUT,
        source_id="route-1", target_id="param-1",
    ))
    graph.add_relationship(Relationship(
        id="rel-2", type=RelationshipType.FLOWS_TO,
        source_id="param-1", target_id="sink-1",
    ))

    paths = graph.find_paths("route-1", "sink-1")
    assert len(paths) == 1
    assert paths[0] == ["route-1", "param-1", "sink-1"]


def test_graph_stats(graph, sample_nodes):
    """Can get graph statistics."""
    for node in sample_nodes:
        graph.add_node(node)

    stats = graph.stats()
    assert stats["total_nodes"] == 3
    assert stats["nodes_by_type"][NodeType.HTTP_ROUTE] == 1
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_graph_store.py -v
```

Expected: FAIL with `cannot import name 'KnowledgeGraph'`

**Step 3: Write minimal implementation**

```python
# backend/cass/graph/store.py
"""In-memory knowledge graph storage."""

from collections import defaultdict
from typing import Optional
from .schema import Node, NodeType, Relationship, RelationshipType


class KnowledgeGraph:
    """In-memory graph storage with query capabilities."""

    def __init__(self):
        self._nodes: dict[str, Node] = {}
        self._relationships: dict[str, Relationship] = {}
        self._outgoing: dict[str, list[str]] = defaultdict(list)  # node_id -> [rel_ids]
        self._incoming: dict[str, list[str]] = defaultdict(list)  # node_id -> [rel_ids]
        self._by_type: dict[NodeType, set[str]] = defaultdict(set)  # type -> {node_ids}

    def add_node(self, node: Node) -> None:
        """Add a node to the graph."""
        self._nodes[node.id] = node
        self._by_type[node.type].add(node.id)

    def get_node(self, node_id: str) -> Optional[Node]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def update_node(self, node_id: str, **updates) -> Optional[Node]:
        """Update node properties."""
        node = self._nodes.get(node_id)
        if node:
            for key, value in updates.items():
                if hasattr(node.properties, key):
                    setattr(node.properties, key, value)
                elif key in ["explored", "tags"]:
                    setattr(node, key, value)
        return node

    def add_relationship(self, rel: Relationship) -> None:
        """Add a relationship between nodes."""
        if rel.source_id not in self._nodes or rel.target_id not in self._nodes:
            raise ValueError(f"Both nodes must exist: {rel.source_id}, {rel.target_id}")
        self._relationships[rel.id] = rel
        self._outgoing[rel.source_id].append(rel.id)
        self._incoming[rel.target_id].append(rel.id)

    def get_relationships(
        self,
        node_id: str,
        direction: str = "outgoing",
        rel_type: Optional[RelationshipType] = None,
    ) -> list[Relationship]:
        """Get relationships for a node."""
        rel_ids = self._outgoing[node_id] if direction == "outgoing" else self._incoming[node_id]
        rels = [self._relationships[rid] for rid in rel_ids]
        if rel_type:
            rels = [r for r in rels if r.type == rel_type]
        return rels

    def query_nodes(
        self,
        type: Optional[NodeType] = None,
        tag: Optional[str] = None,
        explored: Optional[bool] = None,
        file_path: Optional[str] = None,
    ) -> list[Node]:
        """Query nodes by criteria."""
        if type:
            node_ids = self._by_type.get(type, set())
            nodes = [self._nodes[nid] for nid in node_ids]
        else:
            nodes = list(self._nodes.values())

        if tag is not None:
            nodes = [n for n in nodes if tag in n.tags]
        if explored is not None:
            nodes = [n for n in nodes if n.explored == explored]
        if file_path is not None:
            nodes = [n for n in nodes if n.properties.file_path == file_path]

        return nodes

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
    ) -> list[list[str]]:
        """Find all paths between two nodes using BFS."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return []

        paths = []
        queue = [(source_id, [source_id])]

        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue

            if current == target_id:
                paths.append(path)
                continue

            for rel_id in self._outgoing[current]:
                rel = self._relationships[rel_id]
                if rel.target_id not in path:  # Avoid cycles
                    queue.append((rel.target_id, path + [rel.target_id]))

        return paths

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
    ) -> list[Node]:
        """Get neighboring nodes."""
        neighbors = set()

        if direction in ["outgoing", "both"]:
            for rel_id in self._outgoing[node_id]:
                neighbors.add(self._relationships[rel_id].target_id)

        if direction in ["incoming", "both"]:
            for rel_id in self._incoming[node_id]:
                neighbors.add(self._relationships[rel_id].source_id)

        return [self._nodes[nid] for nid in neighbors if nid in self._nodes]

    def stats(self) -> dict:
        """Get graph statistics."""
        return {
            "total_nodes": len(self._nodes),
            "total_relationships": len(self._relationships),
            "nodes_by_type": {t: len(ids) for t, ids in self._by_type.items()},
            "explored_count": len([n for n in self._nodes.values() if n.explored]),
            "unexplored_count": len([n for n in self._nodes.values() if not n.explored]),
        }

    def to_dict(self) -> dict:
        """Export graph to dictionary."""
        return {
            "nodes": [n.model_dump() for n in self._nodes.values()],
            "relationships": [r.model_dump() for r in self._relationships.values()],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KnowledgeGraph":
        """Import graph from dictionary."""
        graph = cls()
        for node_data in data.get("nodes", []):
            graph.add_node(Node(**node_data))
        for rel_data in data.get("relationships", []):
            graph.add_relationship(Relationship(**rel_data))
        return graph
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_graph_store.py -v
```

Expected: PASS (5 tests)

**Step 5: Commit**

```bash
git add backend/cass/graph/store.py backend/tests/cass/test_graph_store.py
git commit -m "feat(cass): add knowledge graph store with query and path finding"
```

---

## Task 3: Graph Query Helpers

**Files:**
- Create: `backend/cass/graph/queries.py`
- Test: `backend/tests/cass/test_graph_queries.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_graph_queries.py
"""Tests for graph query helpers."""

import pytest
from cass.graph.schema import Node, NodeType, NodeProperties, Relationship, RelationshipType
from cass.graph.store import KnowledgeGraph
from cass.graph.queries import GraphQueries


@pytest.fixture
def populated_graph():
    """Graph with realistic security data."""
    graph = KnowledgeGraph()

    # Entry point
    graph.add_node(Node(
        id="route-login",
        type=NodeType.HTTP_ROUTE,
        properties=NodeProperties(name="POST /login", file_path="auth.py", line_number=10),
    ))

    # Input vectors
    graph.add_node(Node(
        id="param-user",
        type=NodeType.REQUEST_BODY,
        properties=NodeProperties(name="username", file_path="auth.py", line_number=12),
    ))
    graph.add_node(Node(
        id="param-pass",
        type=NodeType.REQUEST_BODY,
        properties=NodeProperties(name="password", file_path="auth.py", line_number=12),
        tags=["pii"],
    ))

    # Validator
    graph.add_node(Node(
        id="validator-1",
        type=NodeType.VALIDATOR,
        properties=NodeProperties(name="validate_input", file_path="auth.py", line_number=15),
    ))

    # Sink
    graph.add_node(Node(
        id="sink-sql",
        type=NodeType.SQL_QUERY,
        properties=NodeProperties(name="db.execute", file_path="auth.py", line_number=25),
    ))

    # Relationships
    graph.add_relationship(Relationship(
        id="r1", type=RelationshipType.RECEIVES_INPUT,
        source_id="route-login", target_id="param-user",
    ))
    graph.add_relationship(Relationship(
        id="r2", type=RelationshipType.RECEIVES_INPUT,
        source_id="route-login", target_id="param-pass",
    ))
    graph.add_relationship(Relationship(
        id="r3", type=RelationshipType.VALIDATES,
        source_id="validator-1", target_id="param-user",
    ))
    graph.add_relationship(Relationship(
        id="r4", type=RelationshipType.FLOWS_TO,
        source_id="param-user", target_id="sink-sql",
    ))
    graph.add_relationship(Relationship(
        id="r5", type=RelationshipType.FLOWS_TO,
        source_id="param-pass", target_id="sink-sql",
    ))

    return graph


def test_find_entry_points(populated_graph):
    """Find all entry points."""
    queries = GraphQueries(populated_graph)
    entries = queries.find_entry_points()
    assert len(entries) == 1
    assert entries[0].id == "route-login"


def test_find_dangerous_sinks(populated_graph):
    """Find all dangerous sinks."""
    queries = GraphQueries(populated_graph)
    sinks = queries.find_dangerous_sinks()
    assert len(sinks) == 1
    assert sinks[0].type == NodeType.SQL_QUERY


def test_find_unvalidated_inputs(populated_graph):
    """Find inputs that flow to sinks without validation."""
    queries = GraphQueries(populated_graph)
    unvalidated = queries.find_unvalidated_inputs()
    # param-pass has no validator
    assert len(unvalidated) == 1
    assert unvalidated[0].id == "param-pass"


def test_find_attack_paths(populated_graph):
    """Find paths from entry points to sinks."""
    queries = GraphQueries(populated_graph)
    paths = queries.find_attack_paths()
    assert len(paths) >= 1
    # Should find route-login -> param-* -> sink-sql


def test_get_risk_summary(populated_graph):
    """Get risk summary for the graph."""
    queries = GraphQueries(populated_graph)
    summary = queries.get_risk_summary()
    assert summary["entry_points"] == 1
    assert summary["dangerous_sinks"] == 1
    assert summary["unvalidated_inputs"] >= 1
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_graph_queries.py -v
```

Expected: FAIL with `cannot import name 'GraphQueries'`

**Step 3: Write minimal implementation**

```python
# backend/cass/graph/queries.py
"""High-level query helpers for the knowledge graph."""

from typing import Optional
from .schema import Node, NodeType, RelationshipType
from .store import KnowledgeGraph


ENTRY_POINT_TYPES = {
    NodeType.ENTRY_POINT,
    NodeType.HTTP_ROUTE,
    NodeType.GRAPHQL_RESOLVER,
    NodeType.WEBSOCKET_HANDLER,
    NodeType.CLI_COMMAND,
    NodeType.EVENT_LISTENER,
}

INPUT_VECTOR_TYPES = {
    NodeType.INPUT_VECTOR,
    NodeType.QUERY_PARAM,
    NodeType.REQUEST_BODY,
    NodeType.HEADER,
    NodeType.COOKIE,
    NodeType.FILE_UPLOAD,
    NodeType.ENV_VAR,
}

DANGEROUS_SINK_TYPES = {
    NodeType.DATA_SINK,
    NodeType.SQL_QUERY,
    NodeType.COMMAND_EXEC,
    NodeType.FILE_OPERATION,
    NodeType.NETWORK_REQUEST,
    NodeType.MEMORY_OPERATION,
}

VALIDATOR_TYPES = {
    NodeType.VALIDATOR,
    NodeType.SANITIZER,
}


class GraphQueries:
    """High-level queries for security analysis."""

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def find_entry_points(self) -> list[Node]:
        """Find all entry points in the graph."""
        results = []
        for node_type in ENTRY_POINT_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_input_vectors(self) -> list[Node]:
        """Find all input vectors."""
        results = []
        for node_type in INPUT_VECTOR_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_dangerous_sinks(self) -> list[Node]:
        """Find all dangerous sinks."""
        results = []
        for node_type in DANGEROUS_SINK_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_validators(self) -> list[Node]:
        """Find all validators and sanitizers."""
        results = []
        for node_type in VALIDATOR_TYPES:
            results.extend(self.graph.query_nodes(type=node_type))
        return results

    def find_unvalidated_inputs(self) -> list[Node]:
        """Find inputs that are not validated before reaching sinks."""
        unvalidated = []
        inputs = self.find_input_vectors()
        validators = {v.id for v in self.find_validators()}

        for input_node in inputs:
            # Check if any validator validates this input
            has_validator = False
            incoming = self.graph.get_relationships(input_node.id, direction="incoming")
            for rel in incoming:
                if rel.type == RelationshipType.VALIDATES and rel.source_id in validators:
                    has_validator = True
                    break

            if not has_validator:
                # Check if it flows to a dangerous sink
                sinks = self.find_dangerous_sinks()
                for sink in sinks:
                    paths = self.graph.find_paths(input_node.id, sink.id)
                    if paths:
                        unvalidated.append(input_node)
                        break

        return unvalidated

    def find_attack_paths(
        self,
        entry_point_id: Optional[str] = None,
        sink_id: Optional[str] = None,
    ) -> list[dict]:
        """Find paths from entry points to dangerous sinks."""
        attack_paths = []

        entries = [self.graph.get_node(entry_point_id)] if entry_point_id else self.find_entry_points()
        sinks = [self.graph.get_node(sink_id)] if sink_id else self.find_dangerous_sinks()

        for entry in entries:
            if not entry:
                continue
            for sink in sinks:
                if not sink:
                    continue
                paths = self.graph.find_paths(entry.id, sink.id)
                for path in paths:
                    attack_paths.append({
                        "entry_point": entry,
                        "sink": sink,
                        "path": path,
                        "path_nodes": [self.graph.get_node(nid) for nid in path],
                    })

        return attack_paths

    def find_unauthenticated_routes(self) -> list[Node]:
        """Find entry points without auth checks."""
        unauthenticated = []
        auth_checks = {n.id for n in self.graph.query_nodes(type=NodeType.AUTH_CHECK)}

        for entry in self.find_entry_points():
            has_auth = False
            incoming = self.graph.get_relationships(entry.id, direction="incoming")
            for rel in incoming:
                if rel.type == RelationshipType.AUTHENTICATES:
                    has_auth = True
                    break

            if not has_auth:
                unauthenticated.append(entry)

        return unauthenticated

    def get_risk_summary(self) -> dict:
        """Get a summary of security-relevant statistics."""
        entry_points = self.find_entry_points()
        sinks = self.find_dangerous_sinks()
        unvalidated = self.find_unvalidated_inputs()
        unauthenticated = self.find_unauthenticated_routes()
        attack_paths = self.find_attack_paths()

        return {
            "entry_points": len(entry_points),
            "input_vectors": len(self.find_input_vectors()),
            "dangerous_sinks": len(sinks),
            "validators": len(self.find_validators()),
            "unvalidated_inputs": len(unvalidated),
            "unauthenticated_routes": len(unauthenticated),
            "attack_paths": len(attack_paths),
            "high_risk_paths": len([p for p in attack_paths if any(
                n.id in [u.id for u in unvalidated] for n in p["path_nodes"] if n
            )]),
        }
```

**Step 4: Update graph __init__.py exports**

```python
# backend/cass/graph/__init__.py
"""Knowledge graph package."""

from .schema import Node, NodeType, NodeProperties, Relationship, RelationshipType
from .store import KnowledgeGraph
from .queries import GraphQueries

__all__ = [
    "Node",
    "NodeType",
    "NodeProperties",
    "Relationship",
    "RelationshipType",
    "KnowledgeGraph",
    "GraphQueries",
]
```

**Step 5: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_graph_queries.py -v
```

Expected: PASS (5 tests)

**Step 6: Commit**

```bash
git add backend/cass/graph/
git commit -m "feat(cass): add graph query helpers for security analysis"
```

---

## Task 4: CASS Configuration

**Files:**
- Create: `backend/cass/config.py`
- Test: `backend/tests/cass/test_cass_config.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_cass_config.py
"""Tests for CASS configuration."""

import pytest
from cass.config import CASSConfig, ExplorationStrategy, Phase


def test_default_config():
    """Default config should have sensible values."""
    config = CASSConfig()
    assert config.max_files_per_pass > 0
    assert config.max_depth > 0
    assert config.exploration_strategy == ExplorationStrategy.SECURITY_FIRST


def test_coverage_threshold():
    """Coverage threshold controls when mapping completes."""
    config = CASSConfig(coverage_threshold=0.9)
    assert config.coverage_threshold == 0.9


def test_phase_enum():
    """Phases should be defined."""
    assert Phase.MAPPING
    assert Phase.REVIEW
    assert Phase.SCANNING
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_cass_config.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/cass/config.py
"""CASS configuration."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Phase(str, Enum):
    """CASS operation phases."""
    MAPPING = "mapping"      # Phase 1: Architecture discovery
    REVIEW = "review"        # User reviews knowledge graph
    SCANNING = "scanning"    # Phase 2: Security analysis


class ExplorationStrategy(str, Enum):
    """How the agent prioritizes exploration."""
    BREADTH_FIRST = "breadth_first"      # Map everything shallowly first
    DEPTH_FIRST = "depth_first"          # Follow each path deeply
    SECURITY_FIRST = "security_first"    # Prioritize high-risk areas


class CASSConfig(BaseModel):
    """Configuration for CASS."""

    # Exploration settings
    exploration_strategy: ExplorationStrategy = ExplorationStrategy.SECURITY_FIRST
    max_files_per_pass: int = Field(default=50, ge=1)
    max_depth: int = Field(default=10, ge=1)
    coverage_threshold: float = Field(default=0.8, ge=0.0, le=1.0)

    # Timeouts (seconds)
    mapping_timeout: int = Field(default=600, ge=60)  # 10 min default
    tool_timeout: int = Field(default=30, ge=5)

    # LLM settings
    model: str = "claude-sonnet-4-20250514"
    max_tokens_per_reasoning: int = Field(default=4096, ge=256)

    # Framework detection
    auto_detect_frameworks: bool = True
    known_frameworks: list[str] = Field(default_factory=list)

    # File filtering
    include_patterns: list[str] = Field(default_factory=lambda: ["**/*.py", "**/*.js", "**/*.ts", "**/*.go", "**/*.java", "**/*.rb", "**/*.php", "**/*.rs", "**/*.c", "**/*.cpp"])
    exclude_patterns: list[str] = Field(default_factory=lambda: ["**/node_modules/**", "**/.git/**", "**/vendor/**", "**/dist/**", "**/build/**", "**/__pycache__/**"])

    # Security focus
    prioritize_entry_points: bool = True
    prioritize_auth: bool = True
    prioritize_data_sinks: bool = True
    detect_memory_issues: bool = True
    detect_secrets: bool = True

    # Output
    emit_progress: bool = True
    progress_interval: int = Field(default=5, ge=1)  # seconds


class ScanConfig(BaseModel):
    """Configuration for Phase 2 scanning."""

    # What to scan
    scan_all_paths: bool = False
    min_risk_score: float = Field(default=0.3, ge=0.0, le=1.0)
    vulnerability_types: Optional[list[str]] = None  # None = all

    # Ultrathink integration
    use_ultrathink: bool = True
    ultrathink_min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)

    # Output
    max_findings: int = Field(default=100, ge=1)
    include_low_confidence: bool = False
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_cass_config.py -v
```

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/cass/config.py backend/tests/cass/test_cass_config.py
git commit -m "feat(cass): add configuration for exploration and scanning"
```

---

## Task 5: File Tools

**Files:**
- Create: `backend/cass/tools/__init__.py`
- Create: `backend/cass/tools/file_tools.py`
- Test: `backend/tests/cass/test_file_tools.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_file_tools.py
"""Tests for file exploration tools."""

import pytest
import tempfile
import os
from pathlib import Path
from cass.tools.file_tools import FileTools


@pytest.fixture
def temp_project():
    """Create a temporary project structure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create structure
        src = Path(tmpdir) / "src"
        src.mkdir()

        (src / "main.py").write_text("def main():\n    print('hello')\n")
        (src / "auth.py").write_text("def login(user, password):\n    return True\n")

        routes = src / "routes"
        routes.mkdir()
        (routes / "api.py").write_text("@app.route('/users')\ndef get_users():\n    pass\n")

        yield tmpdir


def test_read_file(temp_project):
    """Can read file contents."""
    tools = FileTools(temp_project)
    content = tools.read_file("src/main.py")
    assert "def main():" in content


def test_list_directory(temp_project):
    """Can list directory contents."""
    tools = FileTools(temp_project)
    entries = tools.list_directory("src")
    names = [e["name"] for e in entries]
    assert "main.py" in names
    assert "auth.py" in names
    assert "routes" in names


def test_search_code(temp_project):
    """Can search for patterns."""
    tools = FileTools(temp_project)
    results = tools.search_code("@app.route")
    assert len(results) == 1
    assert "api.py" in results[0]["file"]


def test_get_file_info(temp_project):
    """Can get file metadata."""
    tools = FileTools(temp_project)
    info = tools.get_file_info("src/main.py")
    assert info["language"] == "python"
    assert info["line_count"] == 2
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_file_tools.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/cass/tools/file_tools.py
"""File exploration tools for CASS agent."""

import os
import re
import fnmatch
from pathlib import Path
from typing import Optional


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sol": "solidity",
}


class FileTools:
    """Tools for exploring the file system."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        """Read file contents, optionally a specific line range."""
        full_path = self.repo_path / path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        content = full_path.read_text(errors="replace")

        if start_line is not None or end_line is not None:
            lines = content.split("\n")
            start = (start_line or 1) - 1
            end = end_line or len(lines)
            content = "\n".join(lines[start:end])

        return content

    def list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        include_hidden: bool = False,
    ) -> list[dict]:
        """List directory contents."""
        full_path = self.repo_path / path
        if not full_path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        entries = []
        iterator = full_path.rglob("*") if recursive else full_path.iterdir()

        for entry in iterator:
            if not include_hidden and entry.name.startswith("."):
                continue

            rel_path = entry.relative_to(self.repo_path)
            entries.append({
                "name": entry.name,
                "path": str(rel_path),
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else None,
                "extension": entry.suffix if entry.is_file() else None,
            })

        return sorted(entries, key=lambda x: (not x["is_dir"], x["name"]))

    def search_code(
        self,
        pattern: str,
        path: str = ".",
        file_pattern: Optional[str] = None,
        max_results: int = 100,
    ) -> list[dict]:
        """Search for regex pattern in files."""
        full_path = self.repo_path / path
        results = []
        regex = re.compile(pattern)

        for file_path in full_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_pattern and not fnmatch.fnmatch(file_path.name, file_pattern):
                continue
            if file_path.suffix not in LANGUAGE_EXTENSIONS:
                continue

            try:
                content = file_path.read_text(errors="replace")
                for i, line in enumerate(content.split("\n"), 1):
                    if regex.search(line):
                        results.append({
                            "file": str(file_path.relative_to(self.repo_path)),
                            "line": i,
                            "content": line.strip(),
                            "match": regex.search(line).group(0),
                        })
                        if len(results) >= max_results:
                            return results
            except Exception:
                continue

        return results

    def get_file_info(self, path: str) -> dict:
        """Get file metadata."""
        full_path = self.repo_path / path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        stat = full_path.stat()
        content = full_path.read_text(errors="replace")

        return {
            "path": path,
            "name": full_path.name,
            "extension": full_path.suffix,
            "language": LANGUAGE_EXTENSIONS.get(full_path.suffix, "unknown"),
            "size": stat.st_size,
            "line_count": len(content.split("\n")),
            "modified": stat.st_mtime,
        }

    def find_files(
        self,
        pattern: str,
        path: str = ".",
    ) -> list[str]:
        """Find files matching a glob pattern."""
        full_path = self.repo_path / path
        matches = list(full_path.glob(pattern))
        return [str(m.relative_to(self.repo_path)) for m in matches if m.is_file()]
```

```python
# backend/cass/tools/__init__.py
"""CASS tools package."""

from .file_tools import FileTools

__all__ = ["FileTools"]
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_file_tools.py -v
```

Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add backend/cass/tools/
git commit -m "feat(cass): add file exploration tools"
```

---

## Task 6: Framework Detection Tools

**Files:**
- Create: `backend/cass/tools/framework_parsers.py`
- Test: `backend/tests/cass/test_framework_parsers.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_framework_parsers.py
"""Tests for framework detection and parsing."""

import pytest
import tempfile
from pathlib import Path
from cass.tools.framework_parsers import FrameworkParsers


@pytest.fixture
def flask_project():
    """Create a Flask-like project."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "requirements.txt").write_text("flask==2.0.0\nsqlalchemy==1.4.0\n")
        (Path(tmpdir) / "app.py").write_text('''
from flask import Flask, request
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    return "ok"

@app.route('/users/<int:user_id>')
def get_user(user_id):
    return str(user_id)
''')
        yield tmpdir


@pytest.fixture
def fastapi_project():
    """Create a FastAPI-like project."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "requirements.txt").write_text("fastapi==0.100.0\nuvicorn\n")
        (Path(tmpdir) / "main.py").write_text('''
from fastapi import FastAPI, Query
app = FastAPI()

@app.get("/items/{item_id}")
async def read_item(item_id: int, q: str = Query(None)):
    return {"item_id": item_id}

@app.post("/users/")
async def create_user(user: dict):
    return user
''')
        yield tmpdir


def test_detect_flask(flask_project):
    """Detect Flask framework."""
    parsers = FrameworkParsers(flask_project)
    frameworks = parsers.detect_frameworks()
    assert "flask" in frameworks["backend"]


def test_detect_fastapi(fastapi_project):
    """Detect FastAPI framework."""
    parsers = FrameworkParsers(fastapi_project)
    frameworks = parsers.detect_frameworks()
    assert "fastapi" in frameworks["backend"]


def test_parse_flask_routes(flask_project):
    """Parse Flask routes."""
    parsers = FrameworkParsers(flask_project)
    routes = parsers.parse_routes()
    assert len(routes) == 2

    login_route = next(r for r in routes if r["path"] == "/login")
    assert "POST" in login_route["methods"]
    assert login_route["handler"] == "login"


def test_parse_fastapi_routes(fastapi_project):
    """Parse FastAPI routes."""
    parsers = FrameworkParsers(fastapi_project)
    routes = parsers.parse_routes()
    assert len(routes) == 2

    items_route = next(r for r in routes if "items" in r["path"])
    assert items_route["method"] == "GET"
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_framework_parsers.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/cass/tools/framework_parsers.py
"""Framework detection and route parsing tools."""

import re
from pathlib import Path
from typing import Optional


class FrameworkParsers:
    """Detect frameworks and parse their conventions."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self._detected_frameworks: Optional[dict] = None

    def detect_frameworks(self) -> dict:
        """Detect frameworks used in the project."""
        if self._detected_frameworks:
            return self._detected_frameworks

        frameworks = {
            "backend": [],
            "frontend": [],
            "orm": [],
            "auth": [],
        }

        # Check Python dependencies
        for req_file in ["requirements.txt", "Pipfile", "pyproject.toml"]:
            req_path = self.repo_path / req_file
            if req_path.exists():
                content = req_path.read_text().lower()

                # Backend frameworks
                if "flask" in content:
                    frameworks["backend"].append("flask")
                if "fastapi" in content:
                    frameworks["backend"].append("fastapi")
                if "django" in content:
                    frameworks["backend"].append("django")
                if "tornado" in content:
                    frameworks["backend"].append("tornado")

                # ORMs
                if "sqlalchemy" in content:
                    frameworks["orm"].append("sqlalchemy")
                if "django" in content:
                    frameworks["orm"].append("django-orm")
                if "peewee" in content:
                    frameworks["orm"].append("peewee")

                # Auth
                if "flask-login" in content:
                    frameworks["auth"].append("flask-login")
                if "authlib" in content:
                    frameworks["auth"].append("authlib")
                if "pyjwt" in content or "python-jose" in content:
                    frameworks["auth"].append("jwt")

        # Check Node.js dependencies
        package_json = self.repo_path / "package.json"
        if package_json.exists():
            content = package_json.read_text().lower()

            if "express" in content:
                frameworks["backend"].append("express")
            if "fastify" in content:
                frameworks["backend"].append("fastify")
            if "next" in content:
                frameworks["frontend"].append("nextjs")
            if "react" in content:
                frameworks["frontend"].append("react")
            if "vue" in content:
                frameworks["frontend"].append("vue")
            if "sequelize" in content:
                frameworks["orm"].append("sequelize")
            if "prisma" in content:
                frameworks["orm"].append("prisma")
            if "passport" in content:
                frameworks["auth"].append("passport")
            if "jsonwebtoken" in content:
                frameworks["auth"].append("jwt")

        self._detected_frameworks = frameworks
        return frameworks

    def parse_routes(self) -> list[dict]:
        """Parse HTTP routes from the codebase."""
        routes = []
        frameworks = self.detect_frameworks()

        # Parse based on detected framework
        if "flask" in frameworks["backend"]:
            routes.extend(self._parse_flask_routes())
        if "fastapi" in frameworks["backend"]:
            routes.extend(self._parse_fastapi_routes())
        if "express" in frameworks["backend"]:
            routes.extend(self._parse_express_routes())
        if "django" in frameworks["backend"]:
            routes.extend(self._parse_django_routes())

        return routes

    def _parse_flask_routes(self) -> list[dict]:
        """Parse Flask @app.route decorators."""
        routes = []
        pattern = r'@\w+\.route\([\'"]([^\'"]+)[\'"](?:,\s*methods=\[([^\]]+)\])?\)'
        handler_pattern = r'def\s+(\w+)\s*\('

        for py_file in self.repo_path.rglob("*.py"):
            try:
                content = py_file.read_text()
                lines = content.split("\n")

                for i, line in enumerate(lines):
                    match = re.search(pattern, line)
                    if match:
                        path = match.group(1)
                        methods_str = match.group(2)
                        methods = ["GET"]
                        if methods_str:
                            methods = [m.strip().strip("'\"") for m in methods_str.split(",")]

                        # Find handler function
                        handler = "unknown"
                        for j in range(i + 1, min(i + 5, len(lines))):
                            handler_match = re.search(handler_pattern, lines[j])
                            if handler_match:
                                handler = handler_match.group(1)
                                break

                        routes.append({
                            "path": path,
                            "methods": methods,
                            "method": methods[0],
                            "handler": handler,
                            "file": str(py_file.relative_to(self.repo_path)),
                            "line": i + 1,
                            "framework": "flask",
                        })
            except Exception:
                continue

        return routes

    def _parse_fastapi_routes(self) -> list[dict]:
        """Parse FastAPI route decorators."""
        routes = []
        pattern = r'@\w+\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]'
        handler_pattern = r'(?:async\s+)?def\s+(\w+)\s*\('

        for py_file in self.repo_path.rglob("*.py"):
            try:
                content = py_file.read_text()
                lines = content.split("\n")

                for i, line in enumerate(lines):
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        method = match.group(1).upper()
                        path = match.group(2)

                        # Find handler function
                        handler = "unknown"
                        for j in range(i + 1, min(i + 5, len(lines))):
                            handler_match = re.search(handler_pattern, lines[j])
                            if handler_match:
                                handler = handler_match.group(1)
                                break

                        routes.append({
                            "path": path,
                            "method": method,
                            "methods": [method],
                            "handler": handler,
                            "file": str(py_file.relative_to(self.repo_path)),
                            "line": i + 1,
                            "framework": "fastapi",
                        })
            except Exception:
                continue

        return routes

    def _parse_express_routes(self) -> list[dict]:
        """Parse Express.js routes."""
        routes = []
        pattern = r'(?:app|router)\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]'

        for js_file in self.repo_path.rglob("*.js"):
            try:
                content = js_file.read_text()
                for i, line in enumerate(content.split("\n"), 1):
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        routes.append({
                            "path": match.group(2),
                            "method": match.group(1).upper(),
                            "methods": [match.group(1).upper()],
                            "handler": "anonymous",
                            "file": str(js_file.relative_to(self.repo_path)),
                            "line": i,
                            "framework": "express",
                        })
            except Exception:
                continue

        return routes

    def _parse_django_routes(self) -> list[dict]:
        """Parse Django URL patterns."""
        routes = []
        pattern = r'path\([\'"]([^\'"]+)[\'"],\s*(\w+)'

        for py_file in self.repo_path.rglob("urls.py"):
            try:
                content = py_file.read_text()
                for i, line in enumerate(content.split("\n"), 1):
                    match = re.search(pattern, line)
                    if match:
                        routes.append({
                            "path": "/" + match.group(1),
                            "method": "ALL",
                            "methods": ["GET", "POST", "PUT", "DELETE"],
                            "handler": match.group(2),
                            "file": str(py_file.relative_to(self.repo_path)),
                            "line": i,
                            "framework": "django",
                        })
            except Exception:
                continue

        return routes

    def detect_languages(self) -> dict[str, int]:
        """Detect languages and their file counts."""
        extensions = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".go": "go",
            ".java": "java",
            ".rb": "ruby",
            ".php": "php",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
        }

        counts = {}
        for ext, lang in extensions.items():
            count = len(list(self.repo_path.rglob(f"*{ext}")))
            if count > 0:
                counts[lang] = count

        return counts
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_framework_parsers.py -v
```

Expected: PASS (4 tests)

**Step 5: Update tools __init__.py**

```python
# backend/cass/tools/__init__.py
"""CASS tools package."""

from .file_tools import FileTools
from .framework_parsers import FrameworkParsers

__all__ = ["FileTools", "FrameworkParsers"]
```

**Step 6: Commit**

```bash
git add backend/cass/tools/
git commit -m "feat(cass): add framework detection and route parsing tools"
```

---

## Task 7: Security Detection Tools

**Files:**
- Create: `backend/cass/tools/security_detectors.py`
- Test: `backend/tests/cass/test_security_detectors.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_security_detectors.py
"""Tests for security detection tools."""

import pytest
import tempfile
from pathlib import Path
from cass.tools.security_detectors import SecurityDetectors


@pytest.fixture
def vulnerable_project():
    """Create a project with security issues."""
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "config.py").write_text('''
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://user:password123@localhost/db"
''')

        (Path(tmpdir) / "auth.py").write_text('''
import os
import subprocess

def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

def run_command(cmd):
    subprocess.call(cmd, shell=True)

def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()
''')

        (Path(tmpdir) / "memory.c").write_text('''
void vulnerable_function(char *input) {
    char buffer[100];
    strcpy(buffer, input);

    int *ptr = malloc(sizeof(int));
    free(ptr);
    *ptr = 10;  // use after free
}
''')
        yield tmpdir


def test_find_secrets(vulnerable_project):
    """Find hardcoded secrets."""
    detectors = SecurityDetectors(vulnerable_project)
    secrets = detectors.find_secrets()
    assert len(secrets) >= 2
    assert any("API_KEY" in s["name"] for s in secrets)


def test_find_sql_sinks(vulnerable_project):
    """Find SQL query sinks."""
    detectors = SecurityDetectors(vulnerable_project)
    sinks = detectors.find_sinks()
    sql_sinks = [s for s in sinks if s["type"] == "sql"]
    assert len(sql_sinks) >= 1


def test_find_command_sinks(vulnerable_project):
    """Find command execution sinks."""
    detectors = SecurityDetectors(vulnerable_project)
    sinks = detectors.find_sinks()
    cmd_sinks = [s for s in sinks if s["type"] == "command"]
    assert len(cmd_sinks) >= 1


def test_find_memory_issues(vulnerable_project):
    """Find memory safety issues."""
    detectors = SecurityDetectors(vulnerable_project)
    issues = detectors.find_memory_issues()
    assert len(issues) >= 1
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_security_detectors.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/cass/tools/security_detectors.py
"""Security-focused detection tools."""

import re
from pathlib import Path
from typing import Optional


# Patterns for secret detection
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']+)["\']', "api_key"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']([^"\']+)["\']', "secret_key"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)["\']', "password"),
    (r'(?i)(token|auth[_-]?token)\s*[=:]\s*["\']([^"\']+)["\']', "token"),
    (r'(?i)(aws[_-]?access[_-]?key)\s*[=:]\s*["\']([^"\']+)["\']', "aws_key"),
    (r'(?i)(database[_-]?url|db[_-]?url)\s*[=:]\s*["\']([^"\']+)["\']', "database_url"),
    (r'sk-[a-zA-Z0-9]{20,}', "openai_key"),
    (r'ghp_[a-zA-Z0-9]{36}', "github_token"),
]

# Dangerous sink patterns by language
SINK_PATTERNS = {
    "python": {
        "sql": [
            r'\.execute\s*\(\s*[f"\'][^"\']*\{',  # f-string SQL
            r'\.execute\s*\(\s*["\'].*%s',  # % formatting SQL
            r'\.execute\s*\(\s*["\'].*\+',  # String concat SQL
            r'cursor\.execute\s*\(',
            r'\.raw\s*\(',  # Django raw SQL
        ],
        "command": [
            r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'eval\s*\(',
            r'exec\s*\(',
        ],
        "file": [
            r'open\s*\([^)]*["\'][^"\']*\+',  # Path concat
            r'open\s*\(\s*\w+\s*[,)]',  # Variable as path
            r'os\.path\.join\s*\([^)]*\+',
        ],
        "ssrf": [
            r'requests\.(get|post|put|delete)\s*\(\s*\w+',
            r'urllib\.request\.urlopen\s*\(\s*\w+',
            r'httpx\.(get|post)\s*\(\s*\w+',
        ],
    },
    "javascript": {
        "sql": [
            r'\.query\s*\(\s*[`"\'][^`"\']*\$\{',  # Template literal SQL
            r'\.query\s*\(\s*["\'].*\+',  # String concat SQL
        ],
        "command": [
            r'child_process\.exec\s*\(',
            r'eval\s*\(',
        ],
        "file": [
            r'fs\.(readFile|writeFile)\s*\(\s*\w+',
        ],
    },
    "c": {
        "memory": [
            r'strcpy\s*\(',
            r'strcat\s*\(',
            r'sprintf\s*\(',
            r'gets\s*\(',
            r'scanf\s*\([^)]*%s',
        ],
        "format_string": [
            r'printf\s*\(\s*\w+\s*\)',  # printf with variable format
            r'fprintf\s*\([^,]+,\s*\w+\s*\)',
        ],
    },
}

# Memory issue patterns
MEMORY_PATTERNS = {
    "buffer_overflow": [
        r'strcpy\s*\(',
        r'strcat\s*\(',
        r'sprintf\s*\(',
        r'gets\s*\(',
        r'\[\s*\w+\s*\]\s*=',  # Array access without bounds check (heuristic)
    ],
    "use_after_free": [
        r'free\s*\(\s*(\w+)\s*\).*\1\s*[=\[]',  # free then use (simple pattern)
    ],
    "format_string": [
        r'printf\s*\(\s*\w+\s*\)',
        r'sprintf\s*\(\s*[^,]+,\s*\w+\s*\)',
    ],
    "integer_overflow": [
        r'\w+\s*\*\s*\w+',  # Multiplication (heuristic)
        r'\w+\s*\+\s*\w+\s*<\s*\w+',  # Addition comparison pattern
    ],
}


class SecurityDetectors:
    """Tools for detecting security-relevant patterns."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def find_secrets(self, path: str = ".") -> list[dict]:
        """Find hardcoded secrets in the codebase."""
        secrets = []
        search_path = self.repo_path / path

        for file_path in search_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in [".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf"]:
                continue
            if any(p in str(file_path) for p in ["node_modules", ".git", "__pycache__", "venv"]):
                continue

            try:
                content = file_path.read_text(errors="replace")
                for pattern, secret_type in SECRET_PATTERNS:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count("\n") + 1
                        secrets.append({
                            "type": secret_type,
                            "name": match.group(1) if match.lastindex and match.lastindex >= 1 else secret_type,
                            "value_preview": match.group(0)[:50] + "..." if len(match.group(0)) > 50 else match.group(0),
                            "file": str(file_path.relative_to(self.repo_path)),
                            "line": line_num,
                        })
            except Exception:
                continue

        return secrets

    def find_sinks(self, path: str = ".") -> list[dict]:
        """Find dangerous sinks in the codebase."""
        sinks = []
        search_path = self.repo_path / path

        for file_path in search_path.rglob("*"):
            if not file_path.is_file():
                continue

            # Determine language
            lang = None
            if file_path.suffix == ".py":
                lang = "python"
            elif file_path.suffix in [".js", ".ts"]:
                lang = "javascript"
            elif file_path.suffix in [".c", ".cpp", ".h"]:
                lang = "c"

            if not lang or lang not in SINK_PATTERNS:
                continue

            try:
                content = file_path.read_text(errors="replace")
                lines = content.split("\n")

                for sink_type, patterns in SINK_PATTERNS[lang].items():
                    for pattern in patterns:
                        for i, line in enumerate(lines, 1):
                            if re.search(pattern, line):
                                sinks.append({
                                    "type": sink_type,
                                    "pattern": pattern,
                                    "code": line.strip(),
                                    "file": str(file_path.relative_to(self.repo_path)),
                                    "line": i,
                                    "language": lang,
                                })
            except Exception:
                continue

        return sinks

    def find_memory_issues(self, path: str = ".") -> list[dict]:
        """Find memory safety issues (C/C++ focused)."""
        issues = []
        search_path = self.repo_path / path

        for file_path in search_path.rglob("*"):
            if file_path.suffix not in [".c", ".cpp", ".h", ".hpp"]:
                continue

            try:
                content = file_path.read_text(errors="replace")
                lines = content.split("\n")

                for issue_type, patterns in MEMORY_PATTERNS.items():
                    for pattern in patterns:
                        for i, line in enumerate(lines, 1):
                            if re.search(pattern, line):
                                issues.append({
                                    "type": issue_type,
                                    "pattern": pattern,
                                    "code": line.strip(),
                                    "file": str(file_path.relative_to(self.repo_path)),
                                    "line": i,
                                    "severity": "high" if issue_type in ["buffer_overflow", "use_after_free"] else "medium",
                                })
            except Exception:
                continue

        return issues

    def find_input_vectors(self, path: str = ".") -> list[dict]:
        """Find user input sources."""
        vectors = []
        search_path = self.repo_path / path

        input_patterns = {
            "python": [
                (r'request\.(args|form|json|data|files|headers|cookies)', "http_input"),
                (r'input\s*\(', "stdin"),
                (r'sys\.argv', "cli_arg"),
                (r'os\.environ', "env_var"),
            ],
            "javascript": [
                (r'req\.(body|query|params|headers|cookies)', "http_input"),
                (r'process\.argv', "cli_arg"),
                (r'process\.env', "env_var"),
            ],
        }

        for file_path in search_path.rglob("*"):
            if not file_path.is_file():
                continue

            lang = None
            if file_path.suffix == ".py":
                lang = "python"
            elif file_path.suffix in [".js", ".ts"]:
                lang = "javascript"

            if not lang or lang not in input_patterns:
                continue

            try:
                content = file_path.read_text(errors="replace")
                lines = content.split("\n")

                for pattern, input_type in input_patterns[lang]:
                    for i, line in enumerate(lines, 1):
                        match = re.search(pattern, line)
                        if match:
                            vectors.append({
                                "type": input_type,
                                "match": match.group(0),
                                "code": line.strip(),
                                "file": str(file_path.relative_to(self.repo_path)),
                                "line": i,
                                "language": lang,
                            })
            except Exception:
                continue

        return vectors

    def find_auth_patterns(self, path: str = ".") -> list[dict]:
        """Find authentication/authorization patterns."""
        patterns = []
        search_path = self.repo_path / path

        auth_patterns = [
            (r'@login_required', "flask_login"),
            (r'@require_auth', "custom_auth"),
            (r'@authenticated', "custom_auth"),
            (r'IsAuthenticated', "drf_auth"),
            (r'jwt\.verify', "jwt_verify"),
            (r'bcrypt\.compare', "password_check"),
            (r'check_password', "password_check"),
            (r'verify_token', "token_verify"),
            (r'session\[', "session_check"),
        ]

        for file_path in search_path.rglob("*.py"):
            try:
                content = file_path.read_text(errors="replace")
                lines = content.split("\n")

                for pattern, auth_type in auth_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line):
                            patterns.append({
                                "type": auth_type,
                                "code": line.strip(),
                                "file": str(file_path.relative_to(self.repo_path)),
                                "line": i,
                            })
            except Exception:
                continue

        return patterns
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_security_detectors.py -v
```

Expected: PASS (4 tests)

**Step 5: Update tools __init__.py**

```python
# backend/cass/tools/__init__.py
"""CASS tools package."""

from .file_tools import FileTools
from .framework_parsers import FrameworkParsers
from .security_detectors import SecurityDetectors

__all__ = ["FileTools", "FrameworkParsers", "SecurityDetectors"]
```

**Step 6: Commit**

```bash
git add backend/cass/tools/
git commit -m "feat(cass): add security detection tools for secrets, sinks, memory issues"
```

---

## Task 8: Graph Tools (Tool Interface)

**Files:**
- Create: `backend/cass/tools/graph_tools.py`
- Test: `backend/tests/cass/test_graph_tools.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_graph_tools.py
"""Tests for graph manipulation tools."""

import pytest
from cass.graph import KnowledgeGraph, NodeType
from cass.tools.graph_tools import GraphTools


@pytest.fixture
def graph_tools():
    graph = KnowledgeGraph()
    return GraphTools(graph)


def test_add_entry_point(graph_tools):
    """Can add entry point nodes."""
    node_id = graph_tools.add_entry_point(
        name="POST /login",
        file_path="auth.py",
        line_number=10,
        method="POST",
        framework="flask",
    )
    assert node_id is not None
    node = graph_tools.graph.get_node(node_id)
    assert node.type == NodeType.HTTP_ROUTE


def test_add_input_vector(graph_tools):
    """Can add input vector nodes."""
    entry_id = graph_tools.add_entry_point(name="/login", file_path="auth.py", line_number=1)
    input_id = graph_tools.add_input_vector(
        name="username",
        input_type="request_body",
        file_path="auth.py",
        line_number=5,
        entry_point_id=entry_id,
    )

    # Check relationship was created
    rels = graph_tools.graph.get_relationships(entry_id)
    assert len(rels) == 1
    assert rels[0].target_id == input_id


def test_add_sink(graph_tools):
    """Can add dangerous sink nodes."""
    sink_id = graph_tools.add_sink(
        name="db.execute",
        sink_type="sql",
        file_path="db.py",
        line_number=20,
        code="db.execute(query)",
    )
    node = graph_tools.graph.get_node(sink_id)
    assert node.type == NodeType.SQL_QUERY


def test_connect_flow(graph_tools):
    """Can connect data flow between nodes."""
    source_id = graph_tools.add_input_vector(name="user_input", input_type="query_param", file_path="a.py", line_number=1)
    sink_id = graph_tools.add_sink(name="execute", sink_type="sql", file_path="b.py", line_number=10)

    graph_tools.connect_flow(source_id, sink_id)

    paths = graph_tools.graph.find_paths(source_id, sink_id)
    assert len(paths) == 1
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_graph_tools.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/cass/tools/graph_tools.py
"""Tools for manipulating the knowledge graph."""

import uuid
from typing import Optional, Any
from cass.graph import (
    KnowledgeGraph,
    Node,
    NodeType,
    NodeProperties,
    Relationship,
    RelationshipType,
)


class GraphTools:
    """High-level tools for building the knowledge graph."""

    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph

    def _generate_id(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    def add_entry_point(
        self,
        name: str,
        file_path: str,
        line_number: int,
        method: str = "GET",
        framework: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add an HTTP route or other entry point."""
        node_id = self._generate_id("entry")
        node = Node(
            id=node_id,
            type=NodeType.HTTP_ROUTE,
            properties=NodeProperties(
                name=name,
                file_path=file_path,
                line_number=line_number,
                framework=framework,
                metadata={"method": method, **metadata},
            ),
        )
        self.graph.add_node(node)
        return node_id

    def add_input_vector(
        self,
        name: str,
        input_type: str,
        file_path: str,
        line_number: int,
        entry_point_id: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add an input vector (query param, body field, etc.)."""
        type_map = {
            "query_param": NodeType.QUERY_PARAM,
            "request_body": NodeType.REQUEST_BODY,
            "header": NodeType.HEADER,
            "cookie": NodeType.COOKIE,
            "file_upload": NodeType.FILE_UPLOAD,
            "env_var": NodeType.ENV_VAR,
        }

        node_id = self._generate_id("input")
        node = Node(
            id=node_id,
            type=type_map.get(input_type, NodeType.INPUT_VECTOR),
            properties=NodeProperties(
                name=name,
                file_path=file_path,
                line_number=line_number,
                metadata=metadata,
            ),
        )
        self.graph.add_node(node)

        # Connect to entry point if provided
        if entry_point_id:
            self.graph.add_relationship(Relationship(
                id=self._generate_id("rel"),
                type=RelationshipType.RECEIVES_INPUT,
                source_id=entry_point_id,
                target_id=node_id,
            ))

        return node_id

    def add_sink(
        self,
        name: str,
        sink_type: str,
        file_path: str,
        line_number: int,
        code: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add a dangerous sink (SQL, command exec, etc.)."""
        type_map = {
            "sql": NodeType.SQL_QUERY,
            "command": NodeType.COMMAND_EXEC,
            "file": NodeType.FILE_OPERATION,
            "network": NodeType.NETWORK_REQUEST,
            "memory": NodeType.MEMORY_OPERATION,
        }

        node_id = self._generate_id("sink")
        node = Node(
            id=node_id,
            type=type_map.get(sink_type, NodeType.DATA_SINK),
            properties=NodeProperties(
                name=name,
                file_path=file_path,
                line_number=line_number,
                code_snippet=code,
                metadata=metadata,
            ),
        )
        self.graph.add_node(node)
        return node_id

    def add_validator(
        self,
        name: str,
        file_path: str,
        line_number: int,
        validates_ids: Optional[list[str]] = None,
        **metadata,
    ) -> str:
        """Add a validator/sanitizer."""
        node_id = self._generate_id("validator")
        node = Node(
            id=node_id,
            type=NodeType.VALIDATOR,
            properties=NodeProperties(
                name=name,
                file_path=file_path,
                line_number=line_number,
                metadata=metadata,
            ),
        )
        self.graph.add_node(node)

        # Connect to validated inputs
        if validates_ids:
            for input_id in validates_ids:
                self.graph.add_relationship(Relationship(
                    id=self._generate_id("rel"),
                    type=RelationshipType.VALIDATES,
                    source_id=node_id,
                    target_id=input_id,
                ))

        return node_id

    def add_auth_check(
        self,
        name: str,
        file_path: str,
        line_number: int,
        protects_ids: Optional[list[str]] = None,
        **metadata,
    ) -> str:
        """Add an authentication check."""
        node_id = self._generate_id("auth")
        node = Node(
            id=node_id,
            type=NodeType.AUTH_CHECK,
            properties=NodeProperties(
                name=name,
                file_path=file_path,
                line_number=line_number,
                metadata=metadata,
            ),
        )
        self.graph.add_node(node)

        # Connect to protected routes
        if protects_ids:
            for route_id in protects_ids:
                self.graph.add_relationship(Relationship(
                    id=self._generate_id("rel"),
                    type=RelationshipType.AUTHENTICATES,
                    source_id=node_id,
                    target_id=route_id,
                ))

        return node_id

    def add_secret(
        self,
        name: str,
        secret_type: str,
        file_path: str,
        line_number: int,
        **metadata,
    ) -> str:
        """Add a secret/credential."""
        node_id = self._generate_id("secret")
        node = Node(
            id=node_id,
            type=NodeType.SECRET,
            properties=NodeProperties(
                name=name,
                file_path=file_path,
                line_number=line_number,
                metadata={"secret_type": secret_type, **metadata},
            ),
            tags=["sensitive"],
        )
        self.graph.add_node(node)
        return node_id

    def add_function(
        self,
        name: str,
        file_path: str,
        line_number: int,
        line_end: Optional[int] = None,
        **metadata,
    ) -> str:
        """Add a function node."""
        node_id = self._generate_id("func")
        node = Node(
            id=node_id,
            type=NodeType.FUNCTION,
            properties=NodeProperties(
                name=name,
                file_path=file_path,
                line_number=line_number,
                line_end=line_end,
                metadata=metadata,
            ),
        )
        self.graph.add_node(node)
        return node_id

    def add_dependency(
        self,
        name: str,
        version: Optional[str] = None,
        **metadata,
    ) -> str:
        """Add a dependency/package."""
        node_id = self._generate_id("dep")
        node = Node(
            id=node_id,
            type=NodeType.DEPENDENCY,
            properties=NodeProperties(
                name=name,
                metadata={"version": version, **metadata},
            ),
        )
        self.graph.add_node(node)
        return node_id

    def connect_flow(
        self,
        source_id: str,
        target_id: str,
        flow_type: str = "flows_to",
    ) -> str:
        """Connect data flow between nodes."""
        type_map = {
            "flows_to": RelationshipType.FLOWS_TO,
            "calls": RelationshipType.CALLS,
            "imports": RelationshipType.IMPORTS,
            "returns": RelationshipType.RETURNS,
        }

        rel_id = self._generate_id("rel")
        self.graph.add_relationship(Relationship(
            id=rel_id,
            type=type_map.get(flow_type, RelationshipType.FLOWS_TO),
            source_id=source_id,
            target_id=target_id,
        ))
        return rel_id

    def mark_explored(self, node_id: str) -> None:
        """Mark a node as explored."""
        self.graph.update_node(node_id, explored=True)

    def tag_node(self, node_id: str, tag: str) -> None:
        """Add a tag to a node."""
        node = self.graph.get_node(node_id)
        if node and tag not in node.tags:
            node.tags.append(tag)
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_graph_tools.py -v
```

Expected: PASS (4 tests)

**Step 5: Update tools __init__.py**

```python
# backend/cass/tools/__init__.py
"""CASS tools package."""

from .file_tools import FileTools
from .framework_parsers import FrameworkParsers
from .security_detectors import SecurityDetectors
from .graph_tools import GraphTools

__all__ = ["FileTools", "FrameworkParsers", "SecurityDetectors", "GraphTools"]
```

**Step 6: Commit**

```bash
git add backend/cass/tools/
git commit -m "feat(cass): add graph manipulation tools for agent"
```

---

## Task 9: CASS Events (WebSocket)

**Files:**
- Create: `backend/cass/events.py`
- Test: `backend/tests/cass/test_events.py`

**Step 1: Write the failing test**

```python
# backend/tests/cass/test_events.py
"""Tests for CASS WebSocket events."""

import pytest
from unittest.mock import MagicMock, AsyncMock
from cass.events import CASSEventEmitter


@pytest.fixture
def emitter():
    callback = MagicMock()
    return CASSEventEmitter("agent-123", callback)


def test_emit_mapping_started(emitter):
    """Emits mapping started event."""
    emitter.emit_mapping_started(total_files=100)
    emitter.callback.assert_called_once()
    call_args = emitter.callback.call_args[0][0]
    assert call_args.type.value == "cass_mapping_started"


def test_emit_progress(emitter):
    """Emits progress event."""
    emitter.emit_progress(current=50, total=100, message="Scanning routes...")
    emitter.callback.assert_called_once()


def test_emit_discovery(emitter):
    """Emits discovery event."""
    emitter.emit_discovery(
        discovery_type="entry_point",
        name="/api/users",
        file_path="routes.py",
        line=10,
    )
    emitter.callback.assert_called_once()
    call_args = emitter.callback.call_args[0][0]
    assert call_args.data["discovery_type"] == "entry_point"


def test_emit_mapping_complete(emitter):
    """Emits mapping complete event."""
    emitter.emit_mapping_complete(
        nodes_count=150,
        relationships_count=300,
        duration_seconds=45.5,
    )
    emitter.callback.assert_called_once()
```

**Step 2: Run test to verify it fails**

```bash
cd backend && python -m pytest tests/cass/test_events.py -v
```

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/cass/events.py
"""WebSocket event emitter for CASS."""

from enum import Enum
from typing import Callable, Optional, Any
from models.schemas import WSMessage, WSMessageType


class CASSMessageType(str, Enum):
    """CASS-specific WebSocket message types."""
    MAPPING_STARTED = "cass_mapping_started"
    MAPPING_PROGRESS = "cass_mapping_progress"
    MAPPING_DISCOVERY = "cass_mapping_discovery"
    MAPPING_COMPLETE = "cass_mapping_complete"
    SCAN_STARTED = "cass_scan_started"
    SCAN_CANDIDATE = "cass_scan_candidate"
    SCAN_COMPLETE = "cass_scan_complete"
    GRAPH_UPDATE = "cass_graph_update"


# Register CASS message types with main WSMessageType
# This extends the existing enum at runtime
for msg_type in CASSMessageType:
    if not hasattr(WSMessageType, msg_type.name):
        # Add to enum (workaround for extending enums)
        pass


class CASSEventEmitter:
    """Emits WebSocket events for CASS operations."""

    def __init__(
        self,
        agent_id: str,
        callback: Callable[[WSMessage], None],
    ):
        self.agent_id = agent_id
        self.callback = callback

    def _emit(self, msg_type: str, data: dict) -> None:
        """Emit a WebSocket message."""
        # Create a WSMessage-like object with custom type
        msg = WSMessage(
            type=WSMessageType.LOG,  # Base type
            agent_id=self.agent_id,
            data={"cass_type": msg_type, **data},
        )
        # Override the type string for frontend
        msg.type = type("CustomType", (), {"value": msg_type})()
        self.callback(msg)

    def emit_mapping_started(
        self,
        total_files: int,
        frameworks: Optional[list[str]] = None,
    ) -> None:
        """Emit when architecture mapping begins."""
        self._emit(CASSMessageType.MAPPING_STARTED.value, {
            "total_files": total_files,
            "frameworks": frameworks or [],
        })

    def emit_progress(
        self,
        current: int,
        total: int,
        message: str,
        phase: str = "mapping",
    ) -> None:
        """Emit progress update."""
        self._emit(CASSMessageType.MAPPING_PROGRESS.value, {
            "current": current,
            "total": total,
            "percentage": round(current / total * 100, 1) if total > 0 else 0,
            "message": message,
            "phase": phase,
        })

    def emit_discovery(
        self,
        discovery_type: str,
        name: str,
        file_path: str,
        line: int,
        severity: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        """Emit when something significant is discovered."""
        self._emit(CASSMessageType.MAPPING_DISCOVERY.value, {
            "discovery_type": discovery_type,
            "name": name,
            "file_path": file_path,
            "line": line,
            "severity": severity,
            "details": details or {},
        })

    def emit_mapping_complete(
        self,
        nodes_count: int,
        relationships_count: int,
        duration_seconds: float,
        summary: Optional[dict] = None,
    ) -> None:
        """Emit when mapping phase completes."""
        self._emit(CASSMessageType.MAPPING_COMPLETE.value, {
            "nodes_count": nodes_count,
            "relationships_count": relationships_count,
            "duration_seconds": duration_seconds,
            "summary": summary or {},
        })

    def emit_scan_started(
        self,
        candidates_count: int,
    ) -> None:
        """Emit when security scan begins."""
        self._emit(CASSMessageType.SCAN_STARTED.value, {
            "candidates_count": candidates_count,
        })

    def emit_scan_candidate(
        self,
        candidate_id: str,
        entry_point: str,
        sink: str,
        risk_score: float,
        status: str,  # "analyzing", "verified", "rejected"
    ) -> None:
        """Emit update for a scan candidate."""
        self._emit(CASSMessageType.SCAN_CANDIDATE.value, {
            "candidate_id": candidate_id,
            "entry_point": entry_point,
            "sink": sink,
            "risk_score": risk_score,
            "status": status,
        })

    def emit_scan_complete(
        self,
        findings_count: int,
        verified_count: int,
        rejected_count: int,
        duration_seconds: float,
    ) -> None:
        """Emit when scan phase completes."""
        self._emit(CASSMessageType.SCAN_COMPLETE.value, {
            "findings_count": findings_count,
            "verified_count": verified_count,
            "rejected_count": rejected_count,
            "duration_seconds": duration_seconds,
        })

    def emit_graph_update(
        self,
        added_nodes: int = 0,
        added_relationships: int = 0,
        graph_stats: Optional[dict] = None,
    ) -> None:
        """Emit graph state update."""
        self._emit(CASSMessageType.GRAPH_UPDATE.value, {
            "added_nodes": added_nodes,
            "added_relationships": added_relationships,
            "stats": graph_stats or {},
        })
```

**Step 4: Run test to verify it passes**

```bash
cd backend && python -m pytest tests/cass/test_events.py -v
```

Expected: PASS (4 tests)

**Step 5: Commit**

```bash
git add backend/cass/events.py backend/tests/cass/test_events.py
git commit -m "feat(cass): add WebSocket event emitter for mapping and scanning"
```

---

## Task 10: Update CASS Package Exports

**Files:**
- Modify: `backend/cass/__init__.py`

**Step 1: Update exports**

```python
# backend/cass/__init__.py
"""CASS - Continuous Architecture Security Scanner."""

from .config import CASSConfig, ScanConfig, Phase, ExplorationStrategy
from .graph import (
    KnowledgeGraph,
    GraphQueries,
    Node,
    NodeType,
    NodeProperties,
    Relationship,
    RelationshipType,
)
from .tools import (
    FileTools,
    FrameworkParsers,
    SecurityDetectors,
    GraphTools,
)
from .events import CASSEventEmitter

__all__ = [
    # Config
    "CASSConfig",
    "ScanConfig",
    "Phase",
    "ExplorationStrategy",
    # Graph
    "KnowledgeGraph",
    "GraphQueries",
    "Node",
    "NodeType",
    "NodeProperties",
    "Relationship",
    "RelationshipType",
    # Tools
    "FileTools",
    "FrameworkParsers",
    "SecurityDetectors",
    "GraphTools",
    # Events
    "CASSEventEmitter",
]
```

**Step 2: Run all tests**

```bash
cd backend && python -m pytest tests/cass/ -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add backend/cass/__init__.py
git commit -m "feat(cass): update package exports"
```

---

## Summary: Tasks 1-10 Complete Foundation

Tasks 1-10 establish the core infrastructure:
- Knowledge graph schema, store, and queries
- Configuration for exploration and scanning
- File, framework, security, and graph tools
- WebSocket events

**Remaining tasks (to be detailed in follow-up):**
- Task 11: Explorer Agent (main loop)
- Task 12: Exploration Strategy
- Task 13: Agent Prompts
- Task 14: Attack Surface Generator
- Task 15: Context Builder for Ultrathink
- Task 16: Scan Orchestrator
- Task 17: CASS Agent Integration
- Task 18: Frontend ArchitecturePanel
- Task 19: Frontend GraphView
- Task 20: Integration Tests

**Continue?** If yes, I'll detail Tasks 11-20.
