"""Campaign CRUD endpoints -- create, list, get campaigns."""

from fastapi import APIRouter, HTTPException, Depends, Query
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import CampaignCreateRequest, CampaignResponse
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
