"""Execution bundle service -- CRUD operations for lane execution bundles.

Provides create, read, and list operations against the execution_bundles
table.  Each bundle is a frozen snapshot of all inputs needed to run a
lane.  All methods use ``get_session()`` so each call gets its own
transactional scope.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.campaign_models import ExecutionBundle as DBExecutionBundle
from database.connection import get_session
from models.campaign_schemas import ExecutionBundleResponse


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_response(row: DBExecutionBundle) -> ExecutionBundleResponse:
    """Map a SQLAlchemy ExecutionBundle row to an ExecutionBundleResponse."""
    return ExecutionBundleResponse(
        id=row.id,
        campaign_id=row.campaign_id,
        campaign_plan_revision=row.campaign_plan_revision,
        lane_spec_id=row.lane_spec_id,
        lane_spec_revision=row.lane_spec_revision,
        harness_id=row.harness_id,
        harness_revision=row.harness_revision,
        oracle_pack_id=row.oracle_pack_id,
        oracle_pack_revision=row.oracle_pack_revision,
        seed_set_id=row.seed_set_id,
        dictionary_id=row.dictionary_id,
        mutator_id=row.mutator_id,
        build_artifact_ref=row.build_artifact_ref,
        env_snapshot_id=row.env_snapshot_id,
        created_at=row.created_at,
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ExecutionBundleService:
    """Thin service layer around the execution_bundles table."""

    async def create_bundle(
        self,
        campaign_id: str,
        campaign_plan_revision: int,
        lane_spec_id: str,
        lane_spec_revision: int,
        harness_id: str,
        harness_revision: int,
        oracle_pack_id: str | None = None,
        oracle_pack_revision: int | None = None,
        seed_set_id: str | None = None,
        dictionary_id: str | None = None,
        mutator_id: str | None = None,
        build_artifact_ref: str | None = None,
        env_snapshot_id: str | None = None,
    ) -> ExecutionBundleResponse:
        """Persist a new execution bundle and return its response."""
        bundle_id = _short_id()

        db_bundle = DBExecutionBundle(
            id=bundle_id,
            campaign_id=campaign_id,
            campaign_plan_revision=campaign_plan_revision,
            lane_spec_id=lane_spec_id,
            lane_spec_revision=lane_spec_revision,
            harness_id=harness_id,
            harness_revision=harness_revision,
            oracle_pack_id=oracle_pack_id,
            oracle_pack_revision=oracle_pack_revision,
            seed_set_id=seed_set_id,
            dictionary_id=dictionary_id,
            mutator_id=mutator_id,
            build_artifact_ref=build_artifact_ref,
            env_snapshot_id=env_snapshot_id,
        )

        async with get_session() as session:
            session.add(db_bundle)
            await session.flush()
            await session.refresh(db_bundle)
            return _db_to_response(db_bundle)

    async def get_bundle(
        self, bundle_id: str
    ) -> Optional[ExecutionBundleResponse]:
        """Return a single bundle by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBExecutionBundle, bundle_id)
            if row is None:
                return None
            return _db_to_response(row)

    async def list_bundles(
        self, campaign_id: str
    ) -> list[ExecutionBundleResponse]:
        """List all execution bundles for a campaign."""
        async with get_session() as session:
            stmt = select(DBExecutionBundle).where(
                DBExecutionBundle.campaign_id == campaign_id
            ).order_by(DBExecutionBundle.created_at.desc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_response(r) for r in rows]


# Module-level singleton
execution_bundle_service = ExecutionBundleService()
