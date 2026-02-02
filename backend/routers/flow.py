"""Flow router - API endpoints for investigation flow visualization."""

from typing import List, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from services.flow_service import flow_service
from services.persistence_service import persistence_service
from services.reconstruction_service import reconstruction_service
from services.artifact_service import artifact_service

router = APIRouter()


class ReconstructionRequest(BaseModel):
    """Request body for investigation reconstruction."""
    events: List[Any] = Field(..., max_length=10000)


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


@router.post("/agents/{agent_id}/reconstruct")
async def reconstruct_investigation(agent_id: str, request: ReconstructionRequest):
    """
    Reconstruct investigation DAG from flat event stream.

    Takes a chronological list of flow events and reconstructs them into a
    structured DAG with spans, edges, and provenance tracking. This enables
    visualization of investigation branches, hypotheses, and artifact flow.

    Args:
        agent_id: Agent execution ID
        request: Reconstruction request with events list

    Returns:
        Dictionary with spans, edges, and event_to_span mapping
    """
    try:
        # Get all artifacts for this agent
        artifacts_dict = artifact_service.get_all_artifacts()

        # Reconstruct the investigation DAG
        spans, edges, event_to_span = reconstruction_service.reconstruct_investigation_dag(
            events=request.events,
            artifacts=artifacts_dict,
            agent_exec_id=agent_id
        )

        # Convert spans to serializable format
        spans_serialized = {
            span_id: {
                "span_id": span.span_id,
                "span_type": span.span_type.value if hasattr(span.span_type, 'value') else span.span_type,
                "hypothesis_id": span.hypothesis_id,
                "label": span.label,
                "state": span.state.value if hasattr(span.state, 'value') else span.state,
                "outcome": span.outcome.value if span.outcome and hasattr(span.outcome, 'value') else span.outcome,
                "parent_span_id": span.parent_span_id,
                "created_turn_id": span.created_turn_id,
                "completed_at": span.completed_at,
                "focus_gap": span.focus_gap,
                "focus_note": span.focus_note,
                "stage": span.stage,
                "event_ids": span.event_ids,
                "artifact_ids": span.artifact_ids,
            }
            for span_id, span in spans.items()
        }

        # Convert edges to serializable format
        edges_serialized = [
            {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "edge_type": edge.edge_type,
                "label": edge.label,
                "style": edge.style,
                "hidden": edge.hidden,
                "metadata": edge.metadata,
            }
            for edge in edges
        ]

        return {
            "spans": spans_serialized,
            "edges": edges_serialized,
            "event_to_span": event_to_span
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reconstruction failed: {str(e)}")
