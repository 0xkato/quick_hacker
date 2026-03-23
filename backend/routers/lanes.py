"""Lane endpoints -- get lane details, harnesses, oracle-packs, runs, coverage, corpus."""

from fastapi import APIRouter, HTTPException, Depends
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import LaneSpecResponse, RunLaneResponse
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


@router.get("/{lane_id}/oracle-packs")
async def list_lane_oracle_packs(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List oracle packs for a lane spec."""
    from services.oracle_pack_service import oracle_pack_service
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return await oracle_pack_service.list_oracle_packs_for_lane(lane_id)


@router.post("/{lane_id}/recompile")
async def recompile_lane(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Enqueue lane recompilation (stub for v1)."""
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return {"status": "recompile_queued"}


@router.post("/{lane_id}/restart")
async def restart_lane(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Enqueue lane restart (stub for v1)."""
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return {"status": "restart_queued"}


@router.post("/{lane_id}/steer")
async def steer_lane(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Enqueue lane steering (stub for v1)."""
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return {"status": "steering_queued"}


@router.get("/{lane_id}/runs", response_model=list[RunLaneResponse])
async def list_lane_runs(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List all runs for a lane spec."""
    from services.run_lane_service import run_lane_service
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return await run_lane_service.list_runs(lane_id)


@router.get("/{lane_id}/coverage")
async def get_lane_coverage(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get aggregated coverage for a lane spec."""
    from services.coverage_service import coverage_service
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return await coverage_service.get_lane_coverage(lane_id)


@router.get("/{lane_id}/corpus")
async def get_lane_corpus(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get corpus summary for a lane spec (stub for v1)."""
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return {"items": [], "total_bytes": 0}


@router.post("/{lane_id}/corpus/prune")
async def prune_lane_corpus(
    lane_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Prune lane corpus (stub for v1)."""
    lane = await lane_service.get_lane_spec(lane_id)
    if not lane:
        raise HTTPException(status_code=404, detail="Lane not found")
    return {"status": "pruned", "removed": 0}
