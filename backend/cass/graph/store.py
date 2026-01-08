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
