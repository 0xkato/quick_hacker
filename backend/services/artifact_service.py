"""Artifact service -- CRUD operations for artifacts and dedup buckets.

Provides create, read, list, classification-update, and bucket-management
operations against the artifacts and artifact_buckets tables.  All methods
use ``get_session()`` so each call gets its own transactional scope.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func as sa_func

from database.campaign_models import (
    Artifact as DBArtifact,
    ArtifactBucket as DBArtifactBucket,
    ExecutionBundle as DBExecBundle,
    RunLane as DBRunLane,
)
from database.connection import get_session
from models.campaign_enums import ArtifactClassification, ArtifactType, AnalysisOutcome
from models.campaign_schemas import ArtifactResponse


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_response(row: DBArtifact) -> ArtifactResponse:
    """Map a SQLAlchemy Artifact row to an ArtifactResponse."""
    return ArtifactResponse(
        id=row.id,
        run_lane_id=row.run_lane_id,
        type=ArtifactType(row.type),
        bucket_key=row.bucket_key,
        artifact_classification=(
            ArtifactClassification(row.artifact_classification)
            if row.artifact_classification is not None
            else None
        ),
        analysis_outcome=(
            AnalysisOutcome(row.analysis_outcome)
            if row.analysis_outcome is not None
            else None
        ),
        reproducible=row.reproducible,
        stability_score=row.stability_score,
        minimized=row.minimized,
        replay_recipe=row.replay_recipe,
        evidence_refs=row.evidence_refs,
        created_at=row.created_at,
    )


def _bucket_to_dict(row: DBArtifactBucket) -> dict:
    """Map a SQLAlchemy ArtifactBucket row to a plain dict."""
    return {
        "id": row.id,
        "campaign_id": row.campaign_id,
        "bucket_key": row.bucket_key,
        "artifact_count": row.artifact_count,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ArtifactService:
    """Thin service layer around the artifacts and artifact_buckets tables."""

    async def create_artifact(
        self,
        run_lane_id: str,
        type: str,
        bucket_key: str,
        artifact_classification: str = "issue_candidate",
        replay_recipe: dict | None = None,
        evidence_refs: list[str] | None = None,
    ) -> ArtifactResponse:
        """Persist a new artifact and return its response representation."""
        artifact_id = _short_id()

        db_artifact = DBArtifact(
            id=artifact_id,
            run_lane_id=run_lane_id,
            type=type,
            bucket_key=bucket_key,
            artifact_classification=artifact_classification,
            replay_recipe=replay_recipe,
            evidence_refs=evidence_refs,
        )

        async with get_session() as session:
            session.add(db_artifact)
            await session.flush()
            await session.refresh(db_artifact)
            return _db_to_response(db_artifact)

    async def get_artifact(
        self, artifact_id: str
    ) -> Optional[ArtifactResponse]:
        """Return a single artifact by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBArtifact, artifact_id)
            if row is None:
                return None
            return _db_to_response(row)

    async def list_artifacts(
        self, campaign_id: str
    ) -> list[ArtifactResponse]:
        """List all artifacts for a campaign.

        Joins through the run_lanes -> execution_bundles chain to
        ensure artifacts are scoped to the correct campaign, avoiding
        cross-campaign data leakage via bucket_key collisions.
        """
        async with get_session() as session:
            stmt = (
                select(DBArtifact)
                .join(DBRunLane, DBArtifact.run_lane_id == DBRunLane.id)
                .join(DBExecBundle, DBRunLane.execution_bundle_id == DBExecBundle.id)
                .where(DBExecBundle.campaign_id == campaign_id)
                .order_by(DBArtifact.created_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_response(r) for r in rows]

    async def update_classification(
        self,
        artifact_id: str,
        classification: str,
        analysis_outcome: str | None = None,
    ) -> Optional[ArtifactResponse]:
        """Update an artifact's classification and optional analysis outcome.

        Returns the updated ArtifactResponse, or None if the artifact
        does not exist.
        """
        async with get_session() as session:
            row = await session.get(DBArtifact, artifact_id)
            if row is None:
                return None

            row.artifact_classification = classification

            if analysis_outcome is not None:
                row.analysis_outcome = analysis_outcome

            await session.flush()
            await session.refresh(row)
            return _db_to_response(row)

    async def create_or_update_bucket(
        self,
        campaign_id: str,
        bucket_key: str,
        artifact_type: str,
    ) -> dict:
        """Upsert an artifact bucket: create if new, increment count if existing."""
        async with get_session() as session:
            stmt = (
                select(DBArtifactBucket)
                .where(DBArtifactBucket.campaign_id == campaign_id)
                .where(DBArtifactBucket.bucket_key == bucket_key)
            )
            result = await session.execute(stmt)
            row = result.scalars().first()

            if row is None:
                row = DBArtifactBucket(
                    id=_short_id(),
                    campaign_id=campaign_id,
                    bucket_key=bucket_key,
                    artifact_count=1,
                )
                session.add(row)
            else:
                row.artifact_count = row.artifact_count + 1
                row.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)

            await session.flush()
            await session.refresh(row)
            return _bucket_to_dict(row)

    async def list_buckets(
        self, campaign_id: str
    ) -> list[dict]:
        """List all artifact buckets for a campaign."""
        async with get_session() as session:
            stmt = (
                select(DBArtifactBucket)
                .where(DBArtifactBucket.campaign_id == campaign_id)
                .order_by(DBArtifactBucket.first_seen_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_bucket_to_dict(r) for r in rows]

    async def get_bucket(
        self, bucket_id: str
    ) -> Optional[dict]:
        """Return a single artifact bucket by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBArtifactBucket, bucket_id)
            if row is None:
                return None
            return _bucket_to_dict(row)


# Module-level singleton
artifact_service = ArtifactService()
