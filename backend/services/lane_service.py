"""Lane-spec service -- CRUD operations for campaign lane specifications.

Provides create (single and batch), read, list, and status-update
operations against the lane_specs table.  All methods use ``get_session()``
so each call gets its own transactional scope.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.campaign_models import LaneSpec as DBLaneSpec
from database.connection import get_session
from models.campaign_enums import (
    FeedbackModel,
    InputProducer,
    LaneSpecStatus,
    StructureModel,
)
from models.campaign_schemas import LaneSpecResponse


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_response(row: DBLaneSpec) -> LaneSpecResponse:
    """Map a SQLAlchemy LaneSpec row to a LaneSpecResponse."""
    return LaneSpecResponse(
        id=row.id,
        target_id=row.target_id,
        revision=row.revision if row.revision is not None else 1,
        structure_model=StructureModel(row.structure_model) if row.structure_model else StructureModel.RAW,
        input_producer=InputProducer(row.input_producer) if row.input_producer else InputProducer.MUTATION,
        feedback_models=[FeedbackModel(f) for f in (row.feedback_models or [])],
        oracle_packs=row.oracle_packs or [],
        engine=row.engine or "",
        budget_seconds=row.budget_seconds,
        seed_sources=row.seed_sources,
        status=LaneSpecStatus(row.status) if row.status else LaneSpecStatus.PLANNED,
        created_at=row.created_at,
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class LaneService:
    """Thin service layer around the lane_specs table."""

    async def create_lane_spec(
        self,
        target_id: str,
        engine: str,
        structure_model: str,
        input_producer: str,
        feedback_models: list[str] | None = None,
        oracle_packs: list[str] | None = None,
        budget_seconds: int | None = None,
        seed_sources: list[str] | None = None,
    ) -> LaneSpecResponse:
        """Persist a new lane spec and return its response representation."""
        lane_id = _short_id()

        db_lane = DBLaneSpec(
            id=lane_id,
            target_id=target_id,
            engine=engine,
            structure_model=structure_model,
            input_producer=input_producer,
            feedback_models=feedback_models,
            oracle_packs=oracle_packs,
            budget_seconds=budget_seconds,
            seed_sources=seed_sources,
        )

        async with get_session() as session:
            session.add(db_lane)
            await session.flush()
            await session.refresh(db_lane)
            return _db_to_response(db_lane)

    async def create_lane_specs_batch(
        self,
        target_id: str,
        specs: list[dict],
    ) -> list[LaneSpecResponse]:
        """Create multiple lane specs in a single transaction."""
        db_lanes = []
        for s in specs:
            db_lane = DBLaneSpec(
                id=_short_id(),
                target_id=s.get("target_id", target_id),
                engine=s.get("engine"),
                structure_model=s.get("structure_model"),
                input_producer=s.get("input_producer"),
                feedback_models=s.get("feedback_models"),
                oracle_packs=s.get("oracle_packs"),
                budget_seconds=s.get("budget_seconds"),
                seed_sources=s.get("seed_sources"),
            )
            db_lanes.append(db_lane)

        async with get_session() as session:
            for db_lane in db_lanes:
                session.add(db_lane)
            await session.flush()
            for db_lane in db_lanes:
                await session.refresh(db_lane)
            return [_db_to_response(l) for l in db_lanes]

    async def get_lane_spec(
        self, lane_spec_id: str
    ) -> Optional[LaneSpecResponse]:
        """Return a single lane spec by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBLaneSpec, lane_spec_id)
            if row is None:
                return None
            return _db_to_response(row)

    async def list_lane_specs(
        self,
        campaign_id: str | None = None,
        target_id: str | None = None,
    ) -> list[LaneSpecResponse]:
        """List lane specs, optionally filtered by campaign_id or target_id."""
        from database.campaign_models import Target as DBTarget

        async with get_session() as session:
            stmt = select(DBLaneSpec)
            if campaign_id is not None:
                stmt = stmt.join(DBTarget, DBLaneSpec.target_id == DBTarget.id).where(
                    DBTarget.campaign_id == campaign_id
                )
            if target_id is not None:
                stmt = stmt.where(DBLaneSpec.target_id == target_id)
            stmt = stmt.order_by(DBLaneSpec.created_at.desc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_response(r) for r in rows]

    async def update_lane_spec_status(
        self,
        lane_spec_id: str,
        status: str,
    ) -> Optional[LaneSpecResponse]:
        """Update a lane spec's status.

        Returns the updated LaneSpecResponse, or None if the lane spec
        does not exist.
        """
        async with get_session() as session:
            row = await session.get(DBLaneSpec, lane_spec_id)
            if row is None:
                return None

            row.status = status

            await session.flush()
            await session.refresh(row)
            return _db_to_response(row)


# Module-level singleton
lane_service = LaneService()
