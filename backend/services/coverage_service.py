"""Coverage service -- record and query coverage snapshots.

Provides snapshot recording, per-lane listing, and campaign-level
summary operations against the coverage_snapshots table.  All methods
use ``get_session()`` so each call gets its own transactional scope.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from database.campaign_models import CoverageSnapshot as DBCoverageSnapshot
from database.connection import get_session


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_dict(row: DBCoverageSnapshot) -> dict[str, Any]:
    """Map a SQLAlchemy CoverageSnapshot row to a plain dict."""
    return {
        "id": row.id,
        "run_lane_id": row.run_lane_id,
        "snapshot_data": row.snapshot_data,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class CoverageService:
    """Thin service layer around the coverage_snapshots table."""

    async def record_snapshot(
        self,
        run_lane_id: str,
        snapshot_data: dict,
    ) -> dict[str, Any]:
        """Persist a new coverage snapshot and return it as a plain dict."""
        snapshot_id = _short_id()

        db_snapshot = DBCoverageSnapshot(
            id=snapshot_id,
            run_lane_id=run_lane_id,
            snapshot_data=snapshot_data,
        )

        async with get_session() as session:
            session.add(db_snapshot)
            await session.flush()
            await session.refresh(db_snapshot)
            return _db_to_dict(db_snapshot)

    async def get_lane_coverage(
        self, run_lane_id: str
    ) -> list[dict[str, Any]]:
        """List all coverage snapshots for a run lane."""
        async with get_session() as session:
            stmt = select(DBCoverageSnapshot).where(
                DBCoverageSnapshot.run_lane_id == run_lane_id
            ).order_by(DBCoverageSnapshot.created_at.asc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_dict(r) for r in rows]

    async def get_campaign_coverage_summary(
        self, campaign_id: str
    ) -> dict[str, Any]:
        """Aggregate coverage stats for a campaign.

        v1: placeholder -- returns an empty dict.  Real aggregation
        (joining run_lanes -> lane_specs -> targets -> campaigns)
        will be added in a later iteration.
        """
        return {}


# Module-level singleton
coverage_service = CoverageService()
