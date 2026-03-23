"""Harness endpoints -- get harness details, validation, and revisions."""

from fastapi import APIRouter, HTTPException, Depends
from middleware.auth import AuthContext, require_auth
from services.harness_service import harness_service

router = APIRouter()


@router.get("/{harness_id}")
async def get_harness(
    harness_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single harness by ID."""
    harness = await harness_service.get_harness(harness_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Harness not found")
    return harness


@router.get("/{harness_id}/validation")
async def get_harness_validation(
    harness_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get validation results for a harness."""
    harness = await harness_service.get_harness(harness_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Harness not found")
    return {"validation_results": harness.get("validation_results")}


@router.get("/{harness_id}/revisions")
async def list_harness_revisions(
    harness_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List harness revisions (v1 has 1 revision)."""
    harness = await harness_service.get_harness(harness_id)
    if not harness:
        raise HTTPException(status_code=404, detail="Harness not found")
    return [harness]
