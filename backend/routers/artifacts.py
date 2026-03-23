"""Artifact endpoints -- get, classify, replay, minimize, evidence, buckets."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import ArtifactResponse
from services.artifact_service import artifact_service

router = APIRouter()


class ClassifyRequest(BaseModel):
    """Request body for artifact classification update."""
    classification: str
    analysis_outcome: str | None = None


# --- Static-prefix routes must come before parameterized routes ---


@router.get("/buckets/{bucket_id}")
async def get_artifact_bucket(
    bucket_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single artifact bucket by ID."""
    bucket = await artifact_service.get_bucket(bucket_id)
    if not bucket:
        raise HTTPException(status_code=404, detail="Artifact bucket not found")
    return bucket


# --- Parameterized artifact routes ---


@router.get("/{artifact_id}", response_model=ArtifactResponse)
async def get_artifact(
    artifact_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single artifact by ID."""
    artifact = await artifact_service.get_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact


@router.post("/{artifact_id}/replay")
async def replay_artifact(
    artifact_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Enqueue artifact replay (stub for v1)."""
    artifact = await artifact_service.get_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return {"status": "enqueued"}


@router.post("/{artifact_id}/minimize")
async def minimize_artifact(
    artifact_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Enqueue artifact minimization (stub for v1)."""
    artifact = await artifact_service.get_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return {"status": "enqueued"}


@router.post("/{artifact_id}/classify", response_model=ArtifactResponse)
async def classify_artifact(
    artifact_id: str,
    body: ClassifyRequest,
    auth_context: AuthContext = Depends(require_auth),
):
    """Update an artifact's classification."""
    result = await artifact_service.update_classification(
        artifact_id,
        classification=body.classification,
        analysis_outcome=body.analysis_outcome,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return result


@router.get("/{artifact_id}/evidence")
async def get_artifact_evidence(
    artifact_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get evidence references for an artifact."""
    artifact = await artifact_service.get_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return {"evidence_refs": artifact.evidence_refs or []}
