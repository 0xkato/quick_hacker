"""Campaign CRUD endpoints -- create, list, get campaigns."""

from fastapi import APIRouter, HTTPException, Depends, Query
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import CampaignCreateRequest, CampaignResponse, LaneSpecResponse, TargetResponse
from services.campaign_service import campaign_service

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
