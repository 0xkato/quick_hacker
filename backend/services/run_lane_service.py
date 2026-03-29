"""Run lane service -- CRUD operations for lane execution runs.

Provides create, read, list, and status-update operations against the
run_lanes table.  All methods use ``get_session()`` so each call gets
its own transactional scope.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.campaign_models import RunLane as DBRunLane
from database.connection import get_session
from models.campaign_enums import ResourceProfile, RunLaneStatus
from models.campaign_schemas import RunLaneResponse


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_response(row: DBRunLane) -> RunLaneResponse:
    """Map a SQLAlchemy RunLane row to a RunLaneResponse."""
    return RunLaneResponse(
        id=row.id,
        lane_spec_id=row.lane_spec_id,
        execution_bundle_id=row.execution_bundle_id,
        status=RunLaneStatus(row.status),
        started_at=row.started_at,
        completed_at=row.completed_at,
        cpu_limit=row.cpu_limit,
        memory_limit_mb=row.memory_limit_mb,
        disk_limit_mb=row.disk_limit_mb,
        timeout_seconds=row.timeout_seconds,
        resource_profile=(
            ResourceProfile(row.resource_profile)
            if row.resource_profile is not None
            else None
        ),
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class RunLaneService:
    """Thin service layer around the run_lanes table."""

    async def create_run(
        self,
        lane_spec_id: str,
        execution_bundle_id: str,
        timeout_seconds: int = 1800,
        resource_profile: str = "light",
        cpu_limit: float = 1.0,
        memory_limit_mb: int = 1024,
        disk_limit_mb: int = 2048,
    ) -> RunLaneResponse:
        """Persist a new run lane and return its response representation."""
        run_id = _short_id()

        db_run = DBRunLane(
            id=run_id,
            lane_spec_id=lane_spec_id,
            execution_bundle_id=execution_bundle_id,
            status="queued",
            timeout_seconds=timeout_seconds,
            resource_profile=resource_profile,
            cpu_limit=cpu_limit,
            memory_limit_mb=memory_limit_mb,
            disk_limit_mb=disk_limit_mb,
        )

        async with get_session() as session:
            session.add(db_run)
            await session.flush()
            await session.refresh(db_run)
            return _db_to_response(db_run)

    async def get_run(
        self, run_id: str
    ) -> Optional[RunLaneResponse]:
        """Return a single run lane by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBRunLane, run_id)
            if row is None:
                return None
            return _db_to_response(row)

    async def list_runs(
        self, lane_spec_id: str
    ) -> list[RunLaneResponse]:
        """List all run lanes for a lane spec."""
        async with get_session() as session:
            stmt = select(DBRunLane).where(
                DBRunLane.lane_spec_id == lane_spec_id
            ).order_by(DBRunLane.started_at.desc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_response(r) for r in rows]

    async def update_run_status(
        self,
        run_id: str,
        status: str,
        **kwargs,
    ) -> Optional[RunLaneResponse]:
        """Update a run lane's status (and optional started_at / completed_at).

        Returns the updated RunLaneResponse, or None if the run
        does not exist.
        """
        async with get_session() as session:
            row = await session.get(DBRunLane, run_id)
            if row is None:
                return None

            row.status = status

            if "started_at" in kwargs:
                row.started_at = kwargs["started_at"]
            if "completed_at" in kwargs:
                row.completed_at = kwargs["completed_at"]

            await session.flush()
            await session.refresh(row)
            return _db_to_response(row)


# Module-level singleton
run_lane_service = RunLaneService()
