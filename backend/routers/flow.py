"""Flow router - API endpoints for investigation flow visualization."""

from fastapi import APIRouter
from services.flow_service import flow_service
from services.persistence_service import persistence_service

router = APIRouter()


@router.get("/agents/{agent_id}/flow")
async def get_agent_flow(agent_id: str):
    """Get the investigation flow for an agent."""
    flow = flow_service.get_flow(agent_id)
    if not flow:
        snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot and (snapshot.flow_nodes or snapshot.flow_edges):
            flow = flow_service.restore_flow(
                agent_id,
                nodes=snapshot.flow_nodes or [],
                edges=snapshot.flow_edges or [],
                current_node_id=snapshot.current_flow_node_id,
            )

    if not flow:
        # Return empty flow rather than 404 for agents that haven't started
        return {
            "session_id": agent_id,
            "nodes": [],
            "edges": [],
            "current_node_id": None,
        }
    return flow.to_dict()


@router.get("/agents/{agent_id}/flow/stats")
async def get_flow_stats(agent_id: str):
    """Get flow statistics for an agent."""
    stats = flow_service.get_flow_stats(agent_id)
    if not stats:
        snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot and (snapshot.flow_nodes or snapshot.flow_edges):
            flow_service.restore_flow(
                agent_id,
                nodes=snapshot.flow_nodes or [],
                edges=snapshot.flow_edges or [],
                current_node_id=snapshot.current_flow_node_id,
            )
            stats = flow_service.get_flow_stats(agent_id)
            if stats:
                return stats

        return {
            "total_nodes": 0,
            "total_edges": 0,
            "node_types": {},
            "status_counts": {},
            "total_duration_ms": 0,
        }
    return stats


@router.delete("/agents/{agent_id}/flow")
async def clear_agent_flow(agent_id: str):
    """Clear the flow for an agent."""
    flow_service.clear_flow(agent_id)
    return {"status": "cleared"}
