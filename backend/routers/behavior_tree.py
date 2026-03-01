"""REST endpoints for the LLM Behavior Tree visualization."""

from fastapi import APIRouter, Query

from services.behavior_tree_service import behavior_tree_service

router = APIRouter(prefix="/behavior-tree", tags=["behavior_tree"])


@router.get("/{agent_id}")
async def get_behavior_tree(agent_id: str):
    """Get full behavior tree for an agent."""
    tree = behavior_tree_service.get_tree(agent_id)
    if tree:
        return tree
    # Fallback: load from database for completed/restarted agents
    return await behavior_tree_service.load_tree_from_db(agent_id)


@router.get("/{agent_id}/subtree/{node_id}")
async def get_subtree(
    agent_id: str,
    node_id: str,
    max_depth: int = Query(default=3, ge=1, le=10),
):
    """Get subtree under a node (for lazy loading deeper levels)."""
    subtree = behavior_tree_service.get_subtree(agent_id, node_id, max_depth)
    if subtree:
        return subtree
    # Fallback: load from DB and filter to subtree
    full_tree = await behavior_tree_service.load_tree_from_db(agent_id)
    if not full_tree:
        return []
    root_node = next((n for n in full_tree if n["id"] == node_id), None)
    if not root_node:
        return []
    root_depth = root_node["depth"]
    parent_map = {n["id"]: n["parent_id"] for n in full_tree}

    def is_descendant(nid: str) -> bool:
        visited: set[str] = set()
        cur: str | None = nid
        while cur and cur not in visited:
            visited.add(cur)
            if parent_map.get(cur) == node_id:
                return True
            cur = parent_map.get(cur)
        return False

    return [
        n for n in full_tree
        if n["id"] == node_id or (
            n["depth"] > root_depth
            and n["depth"] <= root_depth + max_depth
            and is_descendant(n["id"])
        )
    ]
