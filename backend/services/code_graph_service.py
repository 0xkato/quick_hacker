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
