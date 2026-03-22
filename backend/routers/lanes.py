"""Lane endpoints -- get lane details and harnesses."""

from fastapi import APIRouter, HTTPException, Depends
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import LaneSpecResponse
from services.lane_service import lane_service

router = APIRouter()


@router.get("/{lane_id}", response_model=LaneSpecResponse)
async def get_lane(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single lane spec by ID."""
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return lane


@router.get("/{lane_id}/harnesses")
async def list_lane_harnesses(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List harnesses for a lane spec."""
    from services.harness_service import harness_service
    harness = await harness_service.get_latest_for_lane(lane_id)
    return [harness] if harness else []
