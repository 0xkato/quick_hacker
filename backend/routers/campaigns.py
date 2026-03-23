"""Campaign CRUD endpoints -- create, list, get, lifecycle, plan, graph."""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import CampaignCreateRequest, CampaignResponse, LaneSpecResponse, TargetResponse
from services.campaign_service import campaign_service


class CreateLaneRequest(BaseModel):
    """Request body for creating a lane within a campaign."""
    target_id: str
    engine: str = "schemathesis"
    structure_model: str = "raw"
    input_producer: str = "mutation"
    feedback_models: list[str] | None = None
    oracle_packs: list[str] | None = None
    budget_seconds: int | None = None
    seed_sources: list[str] | None = None


class ReprioritizeRequest(BaseModel):
    """Request body for reprioritizing a target."""
    priority_score: float

router = APIRouter()


@router.post("", response_model=CampaignResponse)
async def create_campaign(
    request: CampaignCreateRequest,
    auth_context: AuthContext = Depends(require_auth),
):
    """Create a new campaign."""
    return await campaign_service.create_campaign(request)


@router.get("", response_model=list[CampaignResponse])
async def list_campaigns(
    repo_id: str | None = Query(None),
    auth_context: AuthContext = Depends(require_auth),
):
    """List campaigns, optionally filtered by repo_id."""
    return await campaign_service.list_campaigns(repo_id=repo_id)


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single campaign by ID."""
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign


@router.post("/{campaign_id}/plan", response_model=CampaignResponse)
async def plan_campaign(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Trigger planning phase -- validate contract, extract targets."""
    try:
        from campaigns.controller import campaign_controller
        return await campaign_controller.plan_campaign(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{campaign_id}/targets", response_model=list[TargetResponse])
async def list_campaign_targets(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List targets discovered for a campaign."""
    from services.target_service import target_service
    return await target_service.list_targets(campaign_id)


@router.post("/{campaign_id}/start", response_model=CampaignResponse)
async def start_campaign(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Start a campaign -- runs plan + compile phases."""
    try:
        from campaigns.controller import campaign_controller
        return await campaign_controller.start_campaign(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{campaign_id}/lanes", response_model=list[LaneSpecResponse])
async def list_campaign_lanes(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List lane specs for a campaign."""
    from services.lane_service import lane_service
    from services.target_service import target_service
    targets = await target_service.list_targets(campaign_id)
    all_lanes = []
    for t in targets:
        lanes = await lane_service.list_lane_specs(target_id=t.id)
        all_lanes.extend(lanes)
    return all_lanes


@router.get("/{campaign_id}/artifacts")
async def list_campaign_artifacts(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List all artifacts for a campaign."""
    from services.artifact_service import artifact_service
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return await artifact_service.list_artifacts(campaign_id)


@router.get("/{campaign_id}/artifact-buckets")
async def list_campaign_artifact_buckets(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List artifact dedup buckets for a campaign."""
    from services.artifact_service import artifact_service
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return await artifact_service.list_buckets(campaign_id)


@router.get("/{campaign_id}/coverage")
async def get_campaign_coverage(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get aggregated coverage summary for a campaign."""
    from services.coverage_service import coverage_service
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return await coverage_service.get_campaign_coverage_summary(campaign_id)


@router.get("/{campaign_id}/steering")
async def list_campaign_steering(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List steering decisions for a campaign."""
    from services.steering_service import steering_service
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return await steering_service.list_decisions(campaign_id)


@router.get("/{campaign_id}/issues")
async def list_campaign_issues(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List confirmed issues for a campaign."""
    from services.issue_service import issue_service
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return await issue_service.list_issues(campaign_id)


# ---------------------------------------------------------------------------
# Campaign lifecycle: pause / resume / cancel
# ---------------------------------------------------------------------------


@router.post("/{campaign_id}/pause", response_model=CampaignResponse)
async def pause_campaign(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Pause a running campaign."""
    result = await campaign_service.update_campaign_status(campaign_id, "paused")
    if not result:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return result


@router.post("/{campaign_id}/resume", response_model=CampaignResponse)
async def resume_campaign(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Resume a paused campaign."""
    result = await campaign_service.update_campaign_status(campaign_id, "running")
    if not result:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return result


@router.post("/{campaign_id}/cancel", response_model=CampaignResponse)
async def cancel_campaign(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Cancel a campaign."""
    result = await campaign_service.update_campaign_status(campaign_id, "cancelled")
    if not result:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return result


# ---------------------------------------------------------------------------
# Campaign plan & graph
# ---------------------------------------------------------------------------


@router.get("/{campaign_id}/plan")
async def get_campaign_plan(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get the current (latest revision) plan for a campaign."""
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    plan = await campaign_service.get_current_plan(campaign_id)
    if not plan:
        return {"id": None, "campaign_id": campaign_id, "revision": 0, "plan_data": {}, "created_at": None}
    return plan


@router.get("/{campaign_id}/plans")
async def list_campaign_plans(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get plan revision history for a campaign."""
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return await campaign_service.list_plans(campaign_id)


@router.get("/{campaign_id}/graph")
async def get_campaign_graph(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get campaign graph (targets, lanes, artifacts as nodes)."""
    from services.target_service import target_service
    from services.lane_service import lane_service
    from services.artifact_service import artifact_service

    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    targets = await target_service.list_targets(campaign_id)
    nodes = []
    edges = []

    for t in targets:
        nodes.append({"id": t.id, "type": "target", "label": t.entrypoint})
        lanes = await lane_service.list_lane_specs(target_id=t.id)
        for lane in lanes:
            nodes.append({"id": lane.id, "type": "lane", "label": lane.engine})
            edges.append({"source": t.id, "target": lane.id})

    artifacts = await artifact_service.list_artifacts(campaign_id)
    for a in artifacts:
        nodes.append({"id": a.id, "type": "artifact", "label": a.type.value})

    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# POST lane within campaign context
# ---------------------------------------------------------------------------


@router.post("/{campaign_id}/lanes", response_model=LaneSpecResponse)
async def create_campaign_lane(
    campaign_id: str,
    body: CreateLaneRequest,
    auth_context: AuthContext = Depends(require_auth),
):
    """Create a new lane spec within a campaign's target."""
    from services.lane_service import lane_service
    from services.target_service import target_service

    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Verify the target belongs to this campaign
    target = await target_service.get_target(body.target_id)
    if not target or target.campaign_id != campaign_id:
        raise HTTPException(status_code=400, detail="Target not found or does not belong to this campaign")

    return await lane_service.create_lane_spec(
        target_id=body.target_id,
        engine=body.engine,
        structure_model=body.structure_model,
        input_producer=body.input_producer,
        feedback_models=body.feedback_models,
        oracle_packs=body.oracle_packs,
        budget_seconds=body.budget_seconds,
        seed_sources=body.seed_sources,
    )
