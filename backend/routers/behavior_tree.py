"""REST endpoints for the LLM Behavior Tree visualization."""

from fastapi import APIRouter, Query

from services.behavior_tree_service import behavior_tree_service

router = APIRouter(prefix="/behavior-tree", tags=["behavior_tree"])


@router.get("/{agent_id}")
async def get_behavior_tree(agent_id: str):
    """Get full behavior tree for an agent."""
    return behavior_tree_service.get_tree(agent_id)


@router.get("/{agent_id}/subtree/{node_id}")
async def get_subtree(
    agent_id: str,
    node_id: str,
    max_depth: int = Query(default=3, ge=1, le=10),
):
    """Get subtree under a node (for lazy loading deeper levels)."""
    return behavior_tree_service.get_subtree(agent_id, node_id, max_depth)
