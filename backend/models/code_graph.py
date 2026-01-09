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
