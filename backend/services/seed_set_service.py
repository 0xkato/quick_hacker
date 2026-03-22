"""Seed-set service -- CRUD operations for seed corpus configurations.

Provides create and get operations against the seed_sets table.
All methods use ``get_session()`` so each call gets its own transactional
scope.
"""

from __future__ import annotations

import uuid
from typing import Optional

from database.campaign_models import SeedSet as DBSeedSet
from database.connection import get_session


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_dict(row: DBSeedSet) -> dict:
    """Map a SQLAlchemy SeedSet row to a plain dict."""
    return {
        "id": row.id,
        "lane_spec_id": row.lane_spec_id,
        "sources": row.sources,
        "item_count": row.item_count if row.item_count is not None else 0,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class SeedSetService:
    """Thin service layer around the seed_sets table."""

    async def create_seed_set(
        self,
        lane_spec_id: str,
        sources: list[str],
        item_count: int = 0,
    ) -> dict:
        """Persist a new seed set and return its dict representation."""
        seed_id = _short_id()

        db_seed = DBSeedSet(
            id=seed_id,
            lane_spec_id=lane_spec_id,
            sources=sources,
            item_count=item_count,
        )

        async with get_session() as session:
            session.add(db_seed)
            await session.flush()
            await session.refresh(db_seed)
            return _db_to_dict(db_seed)

    async def get_seed_set(
        self, seed_set_id: str
    ) -> Optional[dict]:
        """Return a single seed set by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBSeedSet, seed_set_id)
            if row is None:
                return None
            return _db_to_dict(row)


# Module-level singleton
seed_set_service = SeedSetService()
