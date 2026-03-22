"""Run lane endpoints -- get run details, metrics, and cancel."""

from fastapi import APIRouter, HTTPException, Depends
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import RunLaneResponse
from services.run_lane_service import run_lane_service
from services.coverage_service import coverage_service

router = APIRouter()


@router.get("/{run_id}", response_model=RunLaneResponse)
async def get_run(
    run_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single run lane by ID."""
    run = await run_lane_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.get("/{run_id}/metrics")
async def get_run_metrics(
    run_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get coverage metrics for a run lane."""
    # Verify run exists first
    run = await run_lane_service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return await coverage_service.get_lane_coverage(run_id)


@router.post("/{run_id}/cancel", response_model=RunLaneResponse)
async def cancel_run(
    run_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Cancel a run lane."""
    result = await run_lane_service.update_run_status(run_id, "cancelled")
    if not result:
        raise HTTPException(status_code=404, detail="Run not found")
    return result
