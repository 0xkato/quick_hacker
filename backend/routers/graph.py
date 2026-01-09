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
