"""Harness service -- CRUD operations for test harnesses.

Provides create, get, and get-latest operations against the harnesses
table.  All methods use ``get_session()`` so each call gets its own
transactional scope.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.campaign_models import Harness as DBHarness
from database.connection import get_session


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_dict(row: DBHarness) -> dict:
    """Map a SQLAlchemy Harness row to a plain dict."""
    return {
        "id": row.id,
        "lane_spec_id": row.lane_spec_id,
        "revision": row.revision if row.revision is not None else 1,
        "code_ref": row.code_ref,
        "validation_results": row.validation_results,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class HarnessService:
    """Thin service layer around the harnesses table."""

    async def create_harness(
        self,
        lane_spec_id: str,
        code_ref: str,
        validation_results: dict | None = None,
    ) -> dict:
        """Persist a new harness and return its dict representation."""
        harness_id = _short_id()

        db_harness = DBHarness(
            id=harness_id,
            lane_spec_id=lane_spec_id,
            code_ref=code_ref,
            validation_results=validation_results,
        )

        async with get_session() as session:
            session.add(db_harness)
            await session.flush()
            await session.refresh(db_harness)
            return _db_to_dict(db_harness)

    async def get_harness(
        self, harness_id: str
    ) -> Optional[dict]:
        """Return a single harness by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBHarness, harness_id)
            if row is None:
                return None
            return _db_to_dict(row)

    async def get_latest_for_lane(
        self, lane_spec_id: str
    ) -> Optional[dict]:
        """Return the latest harness for a lane spec, or None."""
        async with get_session() as session:
            stmt = (
                select(DBHarness)
                .where(DBHarness.lane_spec_id == lane_spec_id)
                .order_by(DBHarness.revision.desc())
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row is None:
                return None
            return _db_to_dict(row)


# Module-level singleton
harness_service = HarnessService()
