"""Agent management API router."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks

from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentUpdate,
    Finding,
    APIResponse,
)
from services.agent_orchestrator import orchestrator
from services.observability_service import observability_service
from services.flow_service import flow_service
from services.persistence_service import persistence_service
from services.report_service import report_service
from providers import list_all_models


router = APIRouter()


@router.post("", response_model=Agent)
async def create_agent(request: AgentCreateRequest):
    """Create a new security auditing agent."""
    try:
        agent = await orchestrator.create_agent(request)
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{agent_id}/start", response_model=Agent)
async def start_agent(agent_id: str, background_tasks: BackgroundTasks):
    """Start an agent's analysis."""
    try:
        agent = await orchestrator.start_agent(agent_id)
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{agent_id}/pause", response_model=Agent)
async def pause_agent(agent_id: str):
    """Pause a running agent."""
    try:
        agent = await orchestrator.pause_agent(agent_id)
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{agent_id}/resume", response_model=Agent)
async def resume_agent(agent_id: str):
    """Resume a paused agent."""
    try:
        agent = await orchestrator.resume_agent(agent_id)
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{agent_id}/cancel", response_model=Agent)
async def cancel_agent(agent_id: str):
    """Cancel an agent."""
    try:
        agent = await orchestrator.cancel_agent(agent_id)
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=list[Agent])
async def list_agents(
    repo_id: Optional[str] = Query(None, description="Filter by repository"),
    status: Optional[AgentStatus] = Query(None, description="Filter by status"),
):
    """List all agents with optional filtering."""
    return await orchestrator.list_agents(repo_id, status)


@router.get("/stats")
async def get_agent_stats():
    """Get agent orchestrator statistics."""
    return await orchestrator.get_stats()


@router.get("/models")
async def get_available_models():
    """Get available AI models by provider."""
    return list_all_models()


@router.get("/{agent_id}", response_model=Agent)
async def get_agent(agent_id: str):
    """Get agent by ID."""
    agent = await orchestrator.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.delete("/{agent_id}", response_model=APIResponse)
async def delete_agent(agent_id: str):
    """Delete an agent and its findings."""
    success = await orchestrator.delete_agent(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found")
    return APIResponse(success=True, message="Agent deleted")


@router.get("/{agent_id}/findings", response_model=list[Finding])
async def get_agent_findings(agent_id: str):
    """Get findings for a specific agent."""
    findings = await orchestrator.get_findings(agent_id=agent_id)
    return findings


@router.get("/findings/all", response_model=list[Finding])
async def get_all_findings(
    repo_id: Optional[str] = Query(None, description="Filter by repository"),
):
    """Get all findings with optional filtering."""
    return await orchestrator.get_findings(repo_id=repo_id)


# === Observability Endpoints ===

@router.get("/{agent_id}/llm-interactions")
async def get_llm_interactions(
    agent_id: str,
    limit: Optional[int] = Query(None, description="Maximum number of interactions to return"),
    offset: int = Query(0, description="Number of interactions to skip"),
):
    """Get LLM interactions for an agent."""
    interactions = observability_service.get_interactions(agent_id, limit, offset)
    return [i.model_dump(exclude_none=True) for i in interactions]


@router.get("/{agent_id}/tool-details")
async def get_tool_details(
    agent_id: str,
    limit: Optional[int] = Query(None, description="Maximum number of tool details to return"),
    offset: int = Query(0, description="Number of tool details to skip"),
):
    """Get tool execution details for an agent."""
    details = observability_service.get_tool_details(agent_id, limit, offset)
    return [d.model_dump(exclude_none=True) for d in details]


@router.get("/{agent_id}/observability-stats")
async def get_observability_stats(agent_id: str):
    """Get observability statistics for an agent."""
    return observability_service.get_stats(agent_id)


@router.get("/{agent_id}/flow")
async def get_agent_flow(agent_id: str):
    """Get investigation flow for an agent."""
    flow = flow_service.get_flow(agent_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow.to_dict()


@router.get("/{agent_id}/flow/stats")
async def get_flow_stats(agent_id: str):
    """Get flow statistics for an agent."""
    stats = flow_service.get_flow_stats(agent_id)
    if not stats:
        raise HTTPException(status_code=404, detail="Flow not found")
    return stats


@router.delete("/{agent_id}/flow")
async def clear_agent_flow(agent_id: str):
    """Clear investigation flow for an agent."""
    flow_service.clear_flow(agent_id)
    return APIResponse(success=True, message="Flow cleared")


# === State Persistence Endpoints ===

@router.get("/{agent_id}/state")
async def get_agent_state(agent_id: str):
    """Get the saved state snapshot for an agent."""
    snapshot = persistence_service.load_agent_state(agent_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No saved state found")
    return snapshot.model_dump(exclude_none=True)


@router.get("/{agent_id}/state/summary")
async def get_agent_state_summary(agent_id: str):
    """Get a summary of the saved state for an agent."""
    summary = persistence_service.get_state_summary(agent_id)
    if not summary:
        raise HTTPException(status_code=404, detail="No saved state found")
    return summary


@router.delete("/{agent_id}/state")
async def delete_agent_state(agent_id: str):
    """Delete the saved state for an agent."""
    success = persistence_service.delete_agent_state(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail="No saved state found")
    return APIResponse(success=True, message="State deleted")


@router.get("/saved-states")
async def list_saved_states():
    """List all saved agent states."""
    return persistence_service.list_saved_states()


# === Report Endpoints ===

@router.get("/{agent_id}/report")
async def get_agent_report(agent_id: str, report_id: Optional[str] = Query(None)):
    """Get a report for an agent."""
    report = report_service.get_report(agent_id, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.model_dump(mode='json')


@router.get("/{agent_id}/report/download")
async def download_report(
    agent_id: str,
    format: str = Query("md", description="Format: md, json, or svg"),
):
    """Download report in specified format."""
    from fastapi.responses import FileResponse

    report = report_service.get_report(agent_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    if format == "md" and report.markdown_path:
        return FileResponse(
            report.markdown_path,
            media_type="text/markdown",
            filename=f"report_{agent_id}.md"
        )
    elif format == "json":
        # Return the JSON report file
        json_path = report.markdown_path.replace("_report.md", "_report.json")
        return FileResponse(
            json_path,
            media_type="application/json",
            filename=f"report_{agent_id}.json"
        )
    elif format == "svg" and report.flow_svg_path:
        return FileResponse(
            report.flow_svg_path,
            media_type="image/svg+xml",
            filename=f"flow_{agent_id}.svg"
        )
    else:
        raise HTTPException(status_code=400, detail=f"Invalid format or file not available: {format}")


@router.get("/reports/all")
async def list_all_reports(agent_id: Optional[str] = Query(None)):
    """List all available reports."""
    return report_service.list_reports(agent_id)
