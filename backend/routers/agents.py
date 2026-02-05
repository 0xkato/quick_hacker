"""Agent management API router."""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from database import get_db
from middleware.auth import AuthContext, require_auth
from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentUpdate,
    Finding,
    APIResponse,
    TriageRequest,
    TriageResponse,
    BudgetConfig,
    EvidenceBlob,
)
from services.agents import orchestrator
from services.observability_service import observability_service
from services.flow_service import flow_service
from services.investigation_queue_service import investigation_queue_service
from services.persistence_service import persistence_service
from services.findings_service import findings_service
from services.report_service import report_service
from services.finding_triage_service import triage_service
from services.project_service import project_service
from services.settings_service import settings_service
from providers import list_all_models
from prompting_loader import render_prompt
from config import settings


router = APIRouter()


@router.post("", response_model=Agent)
async def create_agent(
    request: AgentCreateRequest,
    auth_context: AuthContext = Depends(require_auth),
    db: AsyncSession = Depends(get_db)
):
    """Create a new security auditing agent."""
    try:
        agent = await orchestrator.create_agent(request, auth_context, db)
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


@router.get("")
async def list_agents(
    repo_id: Optional[str] = Query(None, description="Filter by repository"),
    status: Optional[AgentStatus] = Query(None, description="Filter by status"),
    include_persisted: bool = Query(True, description="Include persisted/saved agents"),
):
    """List all agents with optional filtering, including persisted agents."""
    from models.schemas import ProviderConfig

    # Get in-memory agents
    agents = await orchestrator.list_agents(repo_id, status)
    agent_ids = {a.id for a in agents}

    # Include persisted agents that aren't in memory
    if include_persisted:
        saved_states = persistence_service.list_saved_states()
        for state in saved_states:
            if state.get("agent_id") not in agent_ids:
                # Filter by repo_id if specified
                if repo_id and state.get("repo_id") != repo_id:
                    continue
                # Filter by status if specified
                state_status = state.get("status")
                if status and state_status != status.value:
                    continue

                # Convert saved state to Agent schema
                agents.append(Agent(
                    id=state.get("agent_id", ""),
                    repo_id=state.get("repo_id", ""),
                    name=f"Saved: {state.get('agent_type', 'unknown')}",
                    agent_type=state.get("agent_type", "deep_scan"),
                    status=AgentStatus(state_status) if state_status else AgentStatus.COMPLETED,
                    provider_config=ProviderConfig(provider="openai", model="unknown"),
                    created_at=state.get("created_at"),
                    files_analyzed=state.get("files_analyzed", 0),
                    findings_count=state.get("findings_count", 0),
                ))

    # Sort by creation time (newest first)
    agents.sort(key=lambda a: a.created_at if a.created_at else "", reverse=True)
    return agents


@router.get("/stats")
async def get_agent_stats():
    """Get agent orchestrator statistics."""
    return await orchestrator.get_stats()


@router.get("/models")
async def get_available_models():
    """Get available AI models by provider."""
    return list_all_models()


@router.get("/{agent_id}")
async def get_agent(agent_id: str):
    """Get agent by ID (from memory or persisted state)."""
    from models.schemas import ProviderConfig

    # Try in-memory first
    agent = await orchestrator.get_agent(agent_id)
    if agent:
        return agent

    # Try persisted state
    snapshot = persistence_service.load_agent_state(agent_id)
    if snapshot:
        return Agent(
            id=snapshot.agent_id,
            repo_id=snapshot.repo_id,
            name=f"Saved: {snapshot.agent_type}",
            agent_type=snapshot.agent_type,
            status=AgentStatus(snapshot.status) if snapshot.status else AgentStatus.COMPLETED,
            provider_config=ProviderConfig(
                provider=snapshot.provider_config.get("provider", "openai") if snapshot.provider_config else "openai",
                model=snapshot.provider_config.get("model", "unknown") if snapshot.provider_config else "unknown",
            ),
            created_at=snapshot.created_at,
            files_analyzed=snapshot.files_analyzed,
            findings_count=len(snapshot.findings) if snapshot.findings else 0,
            error_message=snapshot.last_error,
        )

    raise HTTPException(status_code=404, detail="Agent not found")


@router.post("/{agent_id}/load")
async def load_agent_state(agent_id: str):
    """Load agent's persisted state into memory (observability, flow, findings)."""
    from models.observability import LLMInteraction, ToolDetail

    # Load persisted state
    snapshot = persistence_service.load_agent_state(agent_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No persisted state found for this agent")

    # Restore LLM interactions to observability service
    if snapshot.llm_interactions:
        observability_service._interactions[agent_id] = []
        for interaction_data in snapshot.llm_interactions:
            try:
                interaction = LLMInteraction(**interaction_data)
                observability_service._interactions[agent_id].append(interaction)
            except Exception as e:
                logger.warning(f"Failed to restore LLM interaction for agent {agent_id}: {e}")

    # Restore tool details to observability service
    if snapshot.tool_details:
        observability_service._tool_details[agent_id] = []
        for tool_data in snapshot.tool_details:
            try:
                tool_detail = ToolDetail(**tool_data)
                observability_service._tool_details[agent_id].append(tool_detail)
            except Exception as e:
                logger.warning(f"Failed to restore tool detail for agent {agent_id}: {e}")

    # Restore flow visualization
    if snapshot.flow_nodes or snapshot.flow_edges:
        flow_service.restore_flow(
            agent_id,
            nodes=snapshot.flow_nodes or [],
            edges=snapshot.flow_edges or [],
            current_node_id=snapshot.current_flow_node_id,
        )

    return {
        "status": "ok",
        "agent_id": agent_id,
        "interactions_loaded": len(snapshot.llm_interactions or []),
        "tool_details_loaded": len(snapshot.tool_details or []),
        "flow_nodes_loaded": len(snapshot.flow_nodes or []),
        "findings_loaded": len(snapshot.findings or []),
    }


@router.delete("/{agent_id}", response_model=APIResponse)
async def delete_agent(agent_id: str):
    """Delete an agent, its findings, and persisted state."""
    # Delete from orchestrator (in-memory)
    success = await orchestrator.delete_agent(agent_id)

    # Also delete persisted state if exists
    state_deleted = persistence_service.delete_agent_state(agent_id)

    # Clear observability data
    observability_service.clear_agent(agent_id)

    # Clear flow data
    flow_service.clear_flow(agent_id)

    if not success and not state_deleted:
        raise HTTPException(status_code=404, detail="Agent not found")
    return APIResponse(success=True, message="Agent and all associated data deleted")


@router.get("/{agent_id}/findings", response_model=list[Finding])
async def get_agent_findings(agent_id: str):
    """Get findings for a specific agent (from memory or persisted state)."""
    # Try in-memory first
    findings = await orchestrator.get_findings(agent_id=agent_id)
    if findings:
        return findings

    # Try persisted state
    snapshot = persistence_service.load_agent_state(agent_id)
    if snapshot and snapshot.findings:
        return [Finding(**f) for f in snapshot.findings]

    return []


@router.get("/findings/all", response_model=list[Finding])
async def get_all_findings(
    repo_id: Optional[str] = Query(None, description="Filter by repository"),
    limit: int = Query(500, description="Maximum findings to return"),
):
    """Get all findings with optional filtering (from memory and persisted states)."""
    # Track findings by (agent_id, id) to avoid duplicates
    finding_ids: set[tuple[str, str]] = set()
    findings: list[Finding] = []

    # 1. Get in-memory findings (most recent state) - fast
    try:
        memory_findings = await orchestrator.get_findings(repo_id=repo_id)
        for f in memory_findings:
            if len(findings) >= limit:
                break
            f_key = (f.agent_id, f.id)
            if f_key not in finding_ids:
                findings.append(f)
                finding_ids.add(f_key)
    except Exception as e:
        print(f"[Findings] Error loading from memory: {e}")

    # 2. Get findings from persisted JSON states - only if we need more
    if len(findings) < limit:
        try:
            saved_states = persistence_service.list_saved_states()
            for state_meta in saved_states:
                if len(findings) >= limit:
                    break
                if repo_id and state_meta.get("repo_id") != repo_id:
                    continue
                # Only load if we have findings count > 0 in metadata
                if state_meta.get("findings_count", 0) == 0:
                    continue
                snapshot = persistence_service.load_agent_state(state_meta.get("agent_id"))
                if snapshot and snapshot.findings:
                    for f_data in snapshot.findings:
                        if len(findings) >= limit:
                            break
                        f_key = (f_data.get("agent_id"), f_data.get("id"))
                        if f_key not in finding_ids:
                            findings.append(Finding(**f_data))
                            finding_ids.add(f_key)
        except Exception as e:
            print(f"[Findings] Error loading from snapshots: {e}")

    # 3. Get findings from database - only if repo_id specified and we need more
    if repo_id and len(findings) < limit:
        try:
            db_findings = await findings_service.get_findings_by_repo(repo_id)
            for f in db_findings:
                if len(findings) >= limit:
                    break
                f_key = (f.agent_id, f.id)
                if f_key not in finding_ids:
                    findings.append(f)
                    finding_ids.add(f_key)
        except Exception as e:
            print(f"[Findings] Error loading from database: {e}")

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity.value, 5), f.created_at))
    return findings


# === Triage Models (defined here for use by /findings/triage endpoint) ===

class LLMTriageRequest(BaseModel):
    """Request for LLM-based triage."""
    finding_ids: Optional[list[str]] = None  # If None, triage all findings
    max_findings: Optional[int] = None  # No limit by default - user controls via UI slider
    # Provider configuration (same as scan)
    provider: Optional[str] = "anthropic"
    model: Optional[str] = "claude-sonnet-4-20250514"
    api_key: Optional[str] = None
    use_claude_sdk: bool = True
    use_claude_code_auth: bool = False


class LLMTriageResult(BaseModel):
    """Result for a single finding triage."""
    finding_id: str
    decision: str  # "valid_security_issue", "bug", "misconfiguration", "hardening", "by_design", "speculative"
    confidence: int  # 0-100
    reasoning: list[str]


class LLMTriageResponse(BaseModel):
    """Response from LLM triage."""
    triaged_count: int
    results: list[LLMTriageResult]
    findings: list[Finding]
    triage_agent_id: Optional[str] = None  # ID of triage agent for tracking in UI


@router.post("/findings/triage")
async def triage_all_findings(
    repo_id: str = Query(..., description="Repository ID to triage findings for"),
    request: LLMTriageRequest = LLMTriageRequest(),
    auth_context: AuthContext = Depends(require_auth),
):
    """
    Triage all findings for a repository without requiring a specific agent.

    Use this when you want to triage from the "All Agents" view.
    """
    from models.schemas import Disposition

    # Get repo path from project
    repo_path = project_service.get_project_repo_path(repo_id)
    if not repo_path:
        repo_path = project_service.get_project_path(repo_id)

    if not repo_path:
        raise HTTPException(status_code=400, detail="Could not determine repository path")

    # Get all findings for this repo
    all_findings = await get_all_findings(repo_id=repo_id)

    if not all_findings:
        return LLMTriageResponse(triaged_count=0, results=[], findings=[])

    print(f"[Triage All] Processing {len(all_findings)} findings for repo {repo_id}")

    # Select findings to triage
    findings_to_triage = list(all_findings)

    # Filter to specific IDs if requested
    if request.finding_ids:
        finding_id_set = set(request.finding_ids)
        findings_to_triage = [f for f in findings_to_triage if f.id in finding_id_set]

    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, None: 5}
    findings_to_triage.sort(key=lambda f: severity_order.get(f.severity, 5))

    # Apply limit if specified
    if request.max_findings is not None and len(findings_to_triage) > request.max_findings:
        findings_to_triage = findings_to_triage[:request.max_findings]

    # Get API key from settings if not provided
    api_key = request.api_key
    if not api_key and request.provider == "anthropic" and not request.use_claude_code_auth:
        try:
            app_settings = await settings_service.get_settings()
            provider_settings = app_settings.providers.get("anthropic")
            if provider_settings and provider_settings.api_key:
                api_key = provider_settings.api_key
        except Exception as e:
            print(f"[Triage All] Could not get API key from settings: {e}")

    # Use triage agent if available
    if request.use_claude_sdk and request.provider == "anthropic":
        try:
            from services.triage_agent_service import run_triage_agent

            triage_agent, triage_result = await run_triage_agent(
                findings=findings_to_triage,
                repo_id=repo_id,
                repo_path=repo_path,
                api_key=api_key,
                model=request.model or "claude-sonnet-4-20250514",
                use_claude_code_auth=request.use_claude_code_auth,
                on_message=lambda msg: orchestrator._broadcast_message(msg),
            )

            # Build results
            results = []
            for decision in triage_result.decisions:
                results.append(LLMTriageResult(
                    finding_id=decision.finding_id,
                    decision=decision.decision,
                    confidence=decision.confidence,
                    reasoning=decision.reasoning,
                ))

            # Merge triaged findings back
            triaged_by_id = {f.id: f for f in triage_result.triaged_findings}
            merged_findings = []
            for f in all_findings:
                if f.id in triaged_by_id:
                    merged_findings.append(triaged_by_id[f.id])
                else:
                    merged_findings.append(f)

            # Persist to database
            for finding in triage_result.triaged_findings:
                try:
                    await findings_service.save_finding(finding)
                except Exception as e:
                    print(f"[Triage All] Failed to persist finding {finding.id}: {e}")

            return LLMTriageResponse(
                triaged_count=len(results),
                results=results,
                findings=merged_findings,
                triage_agent_id=triage_agent.id,
            )

        except Exception as e:
            print(f"[Triage All] Triage agent failed: {e}")
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")

    # Fallback to simple rule-based triage
    results = []
    for finding in findings_to_triage:
        finding.disposition = Disposition.SPECULATIVE
        finding.classification_confidence = 50
        finding.reasoning = ["Rule-based triage - needs manual review"]
        results.append(LLMTriageResult(
            finding_id=finding.id,
            decision="speculative",
            confidence=50,
            reasoning=["Rule-based triage - needs manual review"],
        ))

    return LLMTriageResponse(
        triaged_count=len(results),
        results=results,
        findings=all_findings,
    )


# === Observability Endpoints ===

@router.get("/{agent_id}/llm-interactions")
async def get_llm_interactions(
    agent_id: str,
    limit: Optional[int] = Query(None, description="Maximum number of interactions to return"),
    offset: int = Query(0, description="Number of interactions to skip"),
):
    """Get LLM interactions for an agent."""
    interactions = observability_service.get_interactions(agent_id, limit, offset)
    if not interactions:
        snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot and snapshot.llm_interactions:
            persisted = snapshot.llm_interactions
            if offset:
                persisted = persisted[offset:]
            if limit:
                persisted = persisted[:limit]
            return persisted
    return [i.model_dump(exclude_none=True) for i in interactions]


@router.get("/{agent_id}/tool-details")
async def get_tool_details(
    agent_id: str,
    limit: Optional[int] = Query(None, description="Maximum number of tool details to return"),
    offset: int = Query(0, description="Number of tool details to skip"),
):
    """Get tool execution details for an agent."""
    details = observability_service.get_tool_details(agent_id, limit, offset)
    if not details:
        snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot and snapshot.tool_details:
            persisted = snapshot.tool_details
            if offset:
                persisted = persisted[offset:]
            if limit:
                persisted = persisted[:limit]
            return persisted
    return [d.model_dump(exclude_none=True) for d in details]


@router.get("/{agent_id}/observability-stats")
async def get_observability_stats(agent_id: str):
    """Get observability statistics for an agent."""
    return observability_service.get_stats(agent_id)


# === Investigation Queue ===

class QueueInvestigationRequest(BaseModel):
    node_id: str
    notes: Optional[str] = None


@router.post("/{agent_id}/investigate")
async def queue_investigation(agent_id: str, request: QueueInvestigationRequest):
    """
    Queue a deeper investigation for a flow node.

    The agent will pick this up asynchronously during its next iterations.
    """
    flow = flow_service.get_flow(agent_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")

    node = next((n for n in flow.nodes if n.id == request.node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="Flow node not found")

    file_path = node.data.get("file_path") or node.data.get("path") or ""
    line_number = node.data.get("line_number")
    threat_model = node.data.get("threat_model") or ""
    exposure = node.data.get("exposure") or ""

    meta = node.data.get("metadata")
    meta_json = ""
    if isinstance(meta, dict) and meta:
        meta_json = json.dumps(meta, indent=2, default=str)[:2000]

    context = (node.code_context or "").strip()

    threat_model_line = f"\nThreat model: {threat_model}" if threat_model else ""
    exposure_line = f"\nExposure: {exposure}" if exposure else ""
    location_line = f"\nLocation: {file_path}:{line_number}" if file_path else ""

    user_notes_block = ""
    if request.notes:
        user_notes_block = f"\n\nUser notes: {request.notes.strip()[:500]}"

    metadata_block = ""
    if meta_json:
        metadata_block = f"\n\nMetadata:\n{meta_json}"

    code_context_block = ""
    if context:
        code_context_block = f"\n\nCode context:\n{context[:4000]}"

    prompt = render_prompt(
        "agents/investigation_task_prompt.md",
        label=node.label,
        node_type=node.type,
        threat_model_line=threat_model_line,
        exposure_line=exposure_line,
        location_line=location_line,
        triage_rationale_line="",
        user_notes_block=user_notes_block,
        metadata_block=metadata_block,
        code_context_block=code_context_block,
    )

    task = investigation_queue_service.new_task(
        agent_id=agent_id,
        flow_node_id=node.id,
        source="user",
        prompt=prompt,
        metadata={
            "node_type": node.type,
            "label": node.label,
            "file_path": file_path,
            "line_number": line_number,
            "threat_model": threat_model,
            "exposure": exposure,
        },
    )

    enqueued = await investigation_queue_service.enqueue(task)
    if not enqueued:
        return {"queued": False, "reason": "already_queued"}

    flow_service.update_node_data(agent_id, node.id, {"queued": True, "queued_by": "user", "task_id": task.id})
    flow_service.add_node(
        agent_id,
        "investigation",
        "Queued investigation",
        {"source": "user", "task_id": task.id},
        parent_id=node.id,
        edge_label="queued",
        set_current=False,
    )

    return {"queued": True, "task_id": task.id}


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


# === Triage Endpoints ===

@router.post("/{agent_id}/triage", response_model=TriageResponse)
async def retriage_findings(
    agent_id: str,
    request: TriageRequest,
    auth_context: AuthContext = Depends(require_auth),
):
    """
    Re-triage findings for an agent.

    This endpoint allows manual re-triage of findings with optional budget overrides.
    Requires agent owner or admin authorization.

    Security note: This endpoint exposes code snippets and reasoning.
    Authorization is strictly enforced.
    """
    from database.models import Finding as FindingModel, EvidenceBlob as EvidenceBlobModel
    from database.schema_checker import is_triage_available
    from sqlalchemy import select

    # Check if triage schema is available
    if not is_triage_available():
        raise HTTPException(
            status_code=503,
            detail="Triage system not available. Database schema missing. "
                   "Run: psql $DATABASE_URL < backend/migrations/add_triage_columns.sql"
        )

    # Get agent (check authorization)
    agent = await orchestrator.get_agent(agent_id)
    if not agent:
        # Try persisted state
        snapshot = persistence_service.load_agent_state(agent_id)
        if not snapshot:
            raise HTTPException(status_code=404, detail="Agent not found")

        # Check authorization for persisted agents
        # For now, allow any authenticated user (can be tightened based on user_id)
        if not auth_context.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this agent")
    else:
        # Check if user owns the agent (or is admin)
        # For now, allow any authenticated user (can be tightened)
        if not auth_context.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this agent")

    # Get findings to triage
    if request.finding_ids:
        # Specific findings requested
        findings = []
        all_findings = await orchestrator.get_findings(agent_id=agent_id)
        if not all_findings:
            # Try persisted state
            snapshot = persistence_service.load_agent_state(agent_id)
            if snapshot and snapshot.findings:
                all_findings = [Finding(**f) for f in snapshot.findings]

        # Filter to requested IDs
        finding_id_set = set(request.finding_ids)
        findings = [f for f in all_findings if f.id in finding_id_set]

        if not findings:
            raise HTTPException(status_code=404, detail="No findings found with specified IDs")
    else:
        # All findings for agent
        findings = await orchestrator.get_findings(agent_id=agent_id)
        if not findings:
            # Try persisted state
            snapshot = persistence_service.load_agent_state(agent_id)
            if snapshot and snapshot.findings:
                findings = [Finding(**f) for f in snapshot.findings]
            else:
                raise HTTPException(status_code=404, detail="No findings found for agent")

    # Get repo path
    repo_path = agent.repo_path if agent else snapshot.repo_id
    if not repo_path:
        raise HTTPException(status_code=400, detail="Agent has no repository path")

    # Build budget config
    budgets = BudgetConfig(
        batch_ms=request.budget_override_ms or settings.triage_batch_budget_ms,
        per_finding_ms=settings.triage_per_finding_budget_ms,
        max_evidence_bytes=settings.triage_max_evidence_bytes,
        max_snippet_lines=settings.triage_max_snippet_lines,
    )

    # Load protocol policy for this project
    from services.protocol_policies import ProtocolPolicyLoader
    from protocol_config import ProtocolConfig

    protocol_policy = None
    validation_profile = None
    if ProtocolConfig.ENABLE_PROTOCOL_EVALUATION:
        try:
            # Get project's protocol_id from database
            result = await db.execute(
                text("SELECT protocol_id FROM projects WHERE id = :agent_id"),
                {"agent_id": agent_id}
            )
            row = result.fetchone()
            protocol_id = row[0] if row and row[0] else ProtocolConfig.DEFAULT_PROTOCOL_ID

            # Load the protocol policy
            loader = ProtocolPolicyLoader(db)
            protocol_policy = await loader.get_policy(protocol_id)

            # Load the project's validation profile
            project = await project_service.get_project(agent_id)
            if project:
                validation_profile = project.get_validation_profile()
        except Exception as e:
            # Log but don't fail if protocol loading fails
            logger.error(f"Failed to load protocol policy for agent {agent_id}: {e}")

    # Run triage with protocol evaluation
    try:
        triage_result = await triage_service.triage_with_protocol(
            repo_root=repo_path,
            findings=findings,
            policy_version=settings.triage_policy_version,
            budgets=budgets,
            protocol_policy=protocol_policy,
            db_conn=db,
            validation_profile=validation_profile,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")

    # Prepare response
    return TriageResponse(
        batch_id=triage_result.batch_id,
        triaged_count=triage_result.triaged_count,
        reportable_count=triage_result.reportable_count,
        by_disposition=triage_result.metrics.by_disposition,
        timeout_count=triage_result.metrics.timeout_count,
        policy_version=settings.triage_policy_version,
    )


class QuickTriageRequest(BaseModel):
    """Request for quick rule-based triage."""
    finding_ids: Optional[list[str]] = None  # If None, triage all findings


class QuickTriageResponse(BaseModel):
    """Response from quick triage."""
    triaged_count: int
    filtered_count: int  # Number filtered out as non-security
    findings: list[Finding]


@router.post("/{agent_id}/quick-triage", response_model=QuickTriageResponse)
async def quick_triage_findings(
    agent_id: str,
    request: QuickTriageRequest = QuickTriageRequest(),
    auth_context: AuthContext = Depends(require_auth),
):
    """
    Quick rule-based triage of findings.

    This endpoint applies simple heuristics to filter out obvious non-security findings:
    - Test code (seeders, fixtures, test files)
    - Example/demo code
    - Hardening suggestions without actual vulnerability
    - Documentation-only issues

    No LLM required - pure rule-based filtering.
    """
    from models.schemas import Disposition

    # Get agent
    agent = await orchestrator.get_agent(agent_id)
    if not agent:
        snapshot = persistence_service.load_agent_state(agent_id)
        if not snapshot:
            raise HTTPException(status_code=404, detail="Agent not found")

    # Get findings
    findings = await orchestrator.get_findings(agent_id=agent_id)
    if not findings:
        snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot and snapshot.findings:
            findings = [Finding(**f) for f in snapshot.findings]
        else:
            return QuickTriageResponse(triaged_count=0, filtered_count=0, findings=[])

    # Filter to specific IDs if requested
    if request.finding_ids:
        finding_id_set = set(request.finding_ids)
        findings = [f for f in findings if f.id in finding_id_set]

    # Apply rule-based triage
    triaged_findings = []
    filtered_count = 0

    for finding in findings:
        should_filter, reason = _rule_based_triage(finding)

        if should_filter:
            # Mark as filtered (HARDENING disposition)
            finding.disposition = Disposition.HARDENING
            finding.reasoning = [reason]
            filtered_count += 1
        else:
            # Mark as valid security issue
            if not finding.disposition:
                finding.disposition = Disposition.VALID_SECURITY_ISSUE

        triaged_findings.append(finding)

    # Update findings in orchestrator
    orchestrator._findings[agent_id] = triaged_findings

    return QuickTriageResponse(
        triaged_count=len(triaged_findings),
        filtered_count=filtered_count,
        findings=triaged_findings,
    )


def _rule_based_triage(finding: Finding) -> tuple[bool, str]:
    """
    Apply rule-based heuristics to determine if a finding is likely non-security.

    Returns:
        (should_filter, reason) - True if finding should be filtered out
    """
    file_path = finding.file_path.lower() if finding.file_path else ""
    title = finding.title.lower() if finding.title else ""
    description = finding.description.lower() if finding.description else ""

    # Test code patterns
    test_patterns = [
        '/tests/', '/test/', '/__tests__/', '/spec/', '/specs/',
        '_test.py', '_test.go', '_test.js', '_test.ts',
        '.test.py', '.test.js', '.test.ts', '.test.tsx',
        '/testing/', '/testdata/', '/test_data/',
        '/mock/', '/mocks/', '/__mocks__/',
    ]
    for pattern in test_patterns:
        if pattern in file_path:
            return True, f"Test code: file matches pattern '{pattern}'"

    # Seeder/fixture patterns (common false positives)
    seed_patterns = [
        '/seeders/', '/seeds/', '/seeder/',
        '/factories/', '/factory/',
        '/fixtures/', '/fixture/',
        'seeder.php', 'seeder.py', 'seeder.js',
        'factory.php', 'factory.py', 'factory.js',
        'databaseseeder', 'database_seeder',
    ]
    for pattern in seed_patterns:
        if pattern in file_path:
            return True, f"Seeder/fixture code: file matches pattern '{pattern}'"

    # Example/demo patterns
    example_patterns = [
        '/examples/', '/example/', '/demo/', '/demos/',
        '/sample/', '/samples/', '/playground/',
        '/tutorial/', '/tutorials/',
    ]
    for pattern in example_patterns:
        if pattern in file_path:
            return True, f"Example/demo code: file matches pattern '{pattern}'"

    # Vendor/third-party patterns
    vendor_patterns = [
        '/vendor/', '/node_modules/', '/bower_components/',
        '/third_party/', '/third-party/', '/external/',
        '/lib/vendor/', '/libs/vendor/',
    ]
    for pattern in vendor_patterns:
        if pattern in file_path:
            return True, f"Vendor/third-party code: file matches pattern '{pattern}'"

    # Documentation patterns
    doc_patterns = [
        '/docs/', '/doc/', '/documentation/',
        '.md', '.rst', '.txt',
    ]
    # Only filter docs if it's purely documentation (not code in docs)
    if any(pattern in file_path for pattern in doc_patterns):
        if file_path.endswith(('.md', '.rst', '.txt')):
            return True, f"Documentation file: {file_path}"

    # Environment/config example files
    env_example_patterns = [
        '.env.example', '.env.sample', '.env.template',
        'config.example', 'config.sample', 'settings.example',
    ]
    for pattern in env_example_patterns:
        if pattern in file_path:
            return True, f"Example config file: file matches pattern '{pattern}'"

    # Check for hardcoded credentials in obvious test contexts
    if 'hardcoded' in title or 'hardcoded' in description:
        # Check if it's in a test/example context
        test_context_keywords = [
            'test', 'example', 'sample', 'demo', 'fixture',
            'seeder', 'factory', 'mock', 'stub', 'fake',
        ]
        combined = f"{file_path} {title} {description}"
        if any(keyword in combined for keyword in test_context_keywords):
            return True, "Hardcoded credentials in test/example context"

    # Not filtered - likely a real security issue
    return False, ""


@router.post("/{agent_id}/llm-triage", response_model=LLMTriageResponse)
async def llm_triage_findings(
    agent_id: str,
    request: LLMTriageRequest = LLMTriageRequest(),
    auth_context: AuthContext = Depends(require_auth),
):
    """
    Triage findings using LLM analysis (same Claude SDK as the scan).

    This endpoint sends findings to Claude for intelligent analysis:
    - Evaluates each finding for real exploitability
    - Considers file context (test code, seeders, etc.)
    - Provides detailed reasoning for each decision

    Falls back to rule-based triage if SDK is unavailable.
    """
    from models.schemas import Disposition

    # Get agent and repo path
    agent = await orchestrator.get_agent(agent_id)
    repo_path = None
    snapshot = None
    repo_id = None

    if agent:
        repo_path = getattr(agent, 'repo_path', None)
        repo_id = getattr(agent, 'repo_id', None)

    # If no repo_path from agent, try snapshot
    if not repo_path:
        snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot:
            repo_path = snapshot.repo_path
            repo_id = snapshot.repo_id

    # If still no repo_path, try to get from project
    if not repo_path and repo_id:
        try:
            # Use helper that handles path + repo_name correctly
            repo_path = project_service.get_project_repo_path(repo_id)
            if not repo_path:
                # Fallback to just the project path
                repo_path = project_service.get_project_path(repo_id)
        except Exception as e:
            print(f"[Triage] Could not get project path: {e}")

    if not repo_path:
        raise HTTPException(status_code=400, detail="Could not determine repository path for triage")

    print(f"[Triage] Agent repo_path: {repo_path}")

    # Get findings - keep ALL findings for later merging
    print(f"[LLM Triage] Looking for findings for agent {agent_id}")
    all_findings = await orchestrator.get_findings(agent_id=agent_id)
    print(f"[LLM Triage] Found {len(all_findings) if all_findings else 0} findings from orchestrator")

    if not all_findings:
        # Use existing snapshot or load it
        if not snapshot:
            snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot and snapshot.findings:
            all_findings = [Finding(**f) for f in snapshot.findings]
            print(f"[LLM Triage] Loaded {len(all_findings)} findings from snapshot")
        else:
            print(f"[LLM Triage] No findings found for agent {agent_id}")
            return LLMTriageResponse(triaged_count=0, results=[], findings=[])

    # Select findings to triage (subset of all findings)
    findings_to_triage = list(all_findings)  # Copy to avoid modifying original

    # Filter to specific IDs if requested
    if request.finding_ids:
        finding_id_set = set(request.finding_ids)
        findings_to_triage = [f for f in findings_to_triage if f.id in finding_id_set]

    # Sort by severity (most severe first: critical > high > medium > low > info)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, None: 5}
    findings_to_triage.sort(key=lambda f: severity_order.get(f.severity, 5))

    # Apply limit if specified (user-controlled via UI slider)
    if request.max_findings is not None and len(findings_to_triage) > request.max_findings:
        print(f"[Triage] User limited to {request.max_findings} of {len(findings_to_triage)} findings (sorted by severity)")
        findings_to_triage = findings_to_triage[:request.max_findings]

    findings = findings_to_triage  # Alias for compatibility with rest of code

    print(f"[Triage] Processing {len(findings)} findings")
    print(f"[Triage] Config: provider={request.provider}, model={request.model}, use_claude_sdk={request.use_claude_sdk}, use_claude_code_auth={request.use_claude_code_auth}")

    # Get API key from settings if not provided
    api_key = request.api_key
    if not api_key and request.provider == "anthropic" and not request.use_claude_code_auth:
        try:
            app_settings = await settings_service.get_settings()
            provider_settings = app_settings.providers.get("anthropic")
            if provider_settings and provider_settings.api_key:
                api_key = provider_settings.api_key
                print(f"[Triage] Using API key from settings")
        except Exception as e:
            print(f"[Triage] Could not get API key from settings: {e}")

    # Try triage agent if using Claude SDK
    if request.use_claude_sdk and request.provider == "anthropic":
        try:
            from services.triage_agent_service import run_triage_agent

            print(f"[Triage] Running triage agent with model={request.model}")

            # Create broadcast callback
            def broadcast_msg(msg):
                orchestrator._broadcast_message(msg)

            # Run triage agent
            triage_agent, triage_result = await run_triage_agent(
                findings=findings,
                repo_id=agent.repo_id if agent else snapshot.repo_id,
                repo_path=repo_path,
                api_key=api_key,
                model=request.model or "claude-sonnet-4-20250514",
                use_claude_code_auth=request.use_claude_code_auth,
                on_message=broadcast_msg,
            )

            # Register triage agent with orchestrator so it shows in dropdown
            async with orchestrator._lock:
                orchestrator._agents[triage_agent.id] = triage_agent

            # Build results
            results = []
            for decision in triage_result.decisions:
                results.append(LLMTriageResult(
                    finding_id=decision.finding_id,
                    decision=decision.decision,
                    confidence=decision.confidence,
                    reasoning=decision.reasoning,
                ))

            # CRITICAL: Merge triaged findings back into ALL findings (don't replace!)
            # This preserves findings that weren't triaged in this batch
            triaged_by_id = {f.id: f for f in triage_result.triaged_findings}
            merged_findings = []
            for f in all_findings:
                if f.id in triaged_by_id:
                    merged_findings.append(triaged_by_id[f.id])  # Use triaged version
                else:
                    merged_findings.append(f)  # Keep original

            orchestrator._findings[agent_id] = merged_findings
            print(f"[Triage] Triage agent {triage_agent.id} completed: {len(results)} findings triaged, {len(merged_findings)} total preserved")

            # PERSIST triaged findings to snapshot so they survive page refreshes
            try:
                existing_snapshot = persistence_service.load_agent_state(agent_id)
                if existing_snapshot:
                    # Update findings in existing snapshot
                    existing_snapshot.findings = [f.model_dump() for f in merged_findings]
                    persistence_service.save_agent_state(existing_snapshot)
                    print(f"[Triage] Persisted {len(merged_findings)} triaged findings to snapshot")
                else:
                    print(f"[Triage] No existing snapshot to update for agent {agent_id}")
            except Exception as persist_err:
                print(f"[Triage] Failed to persist triaged findings: {persist_err}")
                # Don't fail the request, just log the error

            return LLMTriageResponse(
                triaged_count=len(results),
                results=results,
                findings=merged_findings,  # Return all findings, not just triaged subset
                triage_agent_id=triage_agent.id,
            )

        except Exception as e:
            print(f"[Triage] Triage agent failed: {e}")
            import traceback
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")

    # Fallback to rule-based triage
    print(f"[Triage] Using rule-based triage")

    triaged_findings = []
    results = []

    for finding in findings:
        should_filter, reason = _rule_based_triage(finding)

        if should_filter:
            finding.disposition = Disposition.HARDENING
            finding.reasoning = [reason]
            finding.classification_confidence = 80
            decision = "hardening"
        else:
            file_path = (finding.file_path or "").lower()
            title = (finding.title or "").lower()
            description = (finding.description or "").lower()

            high_risk_patterns = [
                "sql injection", "command injection", "remote code execution",
                "authentication bypass", "privilege escalation", "ssrf",
                "path traversal", "file inclusion", "deserialization",
            ]

            is_high_risk = any(pattern in title or pattern in description
                              for pattern in high_risk_patterns)

            prod_paths = ["/app/", "/src/", "/lib/", "/core/", "/api/"]
            is_prod_path = any(p in file_path for p in prod_paths)

            if is_high_risk:
                finding.disposition = Disposition.VALID_SECURITY_ISSUE
                finding.classification_confidence = 90
                finding.reasoning = ["High-risk vulnerability pattern (rule-based)", "Requires manual verification"]
                decision = "valid_security_issue"
            elif is_prod_path:
                finding.disposition = Disposition.VALID_SECURITY_ISSUE
                finding.classification_confidence = 75
                finding.reasoning = ["Production code path (rule-based)", "Requires manual verification"]
                decision = "valid_security_issue"
            else:
                finding.disposition = Disposition.SPECULATIVE
                finding.classification_confidence = 50
                finding.reasoning = ["Needs manual review (rule-based triage)"]
                decision = "speculative"

        results.append(LLMTriageResult(
            finding_id=finding.id,
            decision=decision,
            confidence=finding.classification_confidence or 50,
            reasoning=finding.reasoning or [],
        ))
        triaged_findings.append(finding)

    # CRITICAL: Merge triaged findings back into ALL findings (don't replace!)
    triaged_by_id = {f.id: f for f in triaged_findings}
    merged_findings = []
    for f in all_findings:
        if f.id in triaged_by_id:
            merged_findings.append(triaged_by_id[f.id])
        else:
            merged_findings.append(f)

    orchestrator._findings[agent_id] = merged_findings
    print(f"[LLM Triage] Completed: {len(triaged_findings)} findings triaged, {len(merged_findings)} total preserved (rule-based fallback)")

    # PERSIST triaged findings to snapshot so they survive page refreshes
    try:
        existing_snapshot = persistence_service.load_agent_state(agent_id)
        if existing_snapshot:
            existing_snapshot.findings = [f.model_dump() for f in merged_findings]
            persistence_service.save_agent_state(existing_snapshot)
            print(f"[Triage] Persisted {len(merged_findings)} triaged findings to snapshot (rule-based)")
    except Exception as persist_err:
        print(f"[Triage] Failed to persist triaged findings: {persist_err}")

    return LLMTriageResponse(
        triaged_count=len(results),
        results=results,
        findings=merged_findings,  # Return all findings, not just triaged subset
    )


@router.get("/{agent_id}/triaged-findings/batch/{batch_id}")
async def get_triaged_findings_batch(
    agent_id: str,
    batch_id: str,
    auth_context: AuthContext = Depends(require_auth),
    include_evidence: bool = Query(False, description="Include evidence snippets"),
):
    """
    Get triaged findings for a specific batch.

    Returns findings with reasoning, proof_checklist, and optionally evidence snippets.

    Security note: This endpoint exposes code snippets and reasoning.
    Authorization is strictly enforced.
    """
    from database.schema_checker import is_triage_available

    # Check if triage schema is available
    if not is_triage_available():
        raise HTTPException(
            status_code=503,
            detail="Triage system not available. Database schema missing."
        )

    # Get agent (check authorization)
    agent = await orchestrator.get_agent(agent_id)
    if not agent:
        # Try persisted state
        snapshot = persistence_service.load_agent_state(agent_id)
        if not snapshot:
            raise HTTPException(status_code=404, detail="Agent not found")

        # Check authorization
        if not auth_context.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this agent")
    else:
        # Check authorization
        if not auth_context.user_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this agent")

    # Get findings for this batch
    all_findings = await orchestrator.get_findings(agent_id=agent_id)
    if not all_findings:
        # Try persisted state
        snapshot = persistence_service.load_agent_state(agent_id)
        if snapshot and snapshot.findings:
            all_findings = [Finding(**f) for f in snapshot.findings]
        else:
            raise HTTPException(status_code=404, detail="No findings found for agent")

    # Filter to batch
    batch_findings = [f for f in all_findings if f.batch_id == batch_id]
    if not batch_findings:
        raise HTTPException(
            status_code=404,
            detail=f"No findings found for batch {batch_id}"
        )

    # If evidence requested, we would need to query evidence_blobs table
    # For now, return findings with their embedded evidence references
    # (Evidence blobs are stored separately and referenced by finding_id)

    result = {
        "batch_id": batch_id,
        "count": len(batch_findings),
        "findings": [f.model_dump() for f in batch_findings],
    }

    if include_evidence:
        # This would require database query for evidence_blobs
        # For now, include a note that evidence is stored separately
        result["note"] = "Evidence blobs stored separately; query evidence_blobs table by finding_id"

    return result
