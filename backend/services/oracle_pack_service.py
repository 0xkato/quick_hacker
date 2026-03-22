"""Oracle-pack service -- CRUD operations for oracle configurations.

Provides create and get operations against the oracle_packs table.
All methods use ``get_session()`` so each call gets its own transactional
scope.
"""

from __future__ import annotations

import uuid
from typing import Optional

from database.campaign_models import OraclePack as DBOraclePack
from database.connection import get_session


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_dict(row: DBOraclePack) -> dict:
    """Map a SQLAlchemy OraclePack row to a plain dict."""
    return {
        "id": row.id,
        "lane_spec_id": row.lane_spec_id,
        "revision": row.revision if row.revision is not None else 1,
        "config": row.config,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class OraclePackService:
    """Thin service layer around the oracle_packs table."""

    async def create_oracle_pack(
        self,
        lane_spec_id: str,
        config: dict,
    ) -> dict:
        """Persist a new oracle pack and return its dict representation."""
        pack_id = _short_id()

        db_pack = DBOraclePack(
            id=pack_id,
            lane_spec_id=lane_spec_id,
            config=config,
        )

        async with get_session() as session:
            session.add(db_pack)
            await session.flush()
            await session.refresh(db_pack)
            return _db_to_dict(db_pack)

    async def get_oracle_pack(
        self, oracle_pack_id: str
    ) -> Optional[dict]:
        """Return a single oracle pack by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBOraclePack, oracle_pack_id)
            if row is None:
                return None
            return _db_to_dict(row)


# Module-level singleton
oracle_pack_service = OraclePackService()
