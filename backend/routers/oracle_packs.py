"""Oracle pack endpoints -- get oracle pack details and revisions."""

from fastapi import APIRouter, HTTPException, Depends
from middleware.auth import AuthContext, require_auth
from services.oracle_pack_service import oracle_pack_service

router = APIRouter()


@router.get("/{oracle_pack_id}")
async def get_oracle_pack(
    oracle_pack_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single oracle pack by ID."""
    pack = await oracle_pack_service.get_oracle_pack(oracle_pack_id)
    if not pack:
        raise HTTPException(status_code=404, detail="Oracle pack not found")
    return pack


@router.get("/{oracle_pack_id}/revisions")
async def list_oracle_pack_revisions(
    oracle_pack_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """List oracle pack revisions (v1 has 1 revision)."""
    pack = await oracle_pack_service.get_oracle_pack(oracle_pack_id)
    if not pack:
        raise HTTPException(status_code=404, detail="Oracle pack not found")
    return [pack]
