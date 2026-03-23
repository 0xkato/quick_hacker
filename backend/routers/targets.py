"""Target endpoints -- get target details, lanes, and reprioritize."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import TargetResponse, LaneSpecResponse
from services.target_service import target_service

router = APIRouter()


class ReprioritizeRequest(BaseModel):
    """Request body for reprioritizing a target."""
    priority_score: float


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single target by ID."""
    target = await target_service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.get("/{target_id}/lanes", response_model=list[LaneSpecResponse])
async def list_target_lanes(
    target_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List lane specs for a target."""
    from services.lane_service import lane_service
    target = await target_service.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return await lane_service.list_lane_specs(target_id=target_id)


@router.post("/{target_id}/reprioritize", response_model=TargetResponse)
async def reprioritize_target(
    target_id: str,
    body: ReprioritizeRequest,
    auth_context: AuthContext = Depends(require_auth),
):
    """Update a target's priority score."""
    result = await target_service.update_target_priority(target_id, body.priority_score)
    if not result:
        raise HTTPException(status_code=404, detail="Target not found")
    return result
