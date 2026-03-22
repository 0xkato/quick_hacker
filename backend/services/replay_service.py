"""Replay service -- CRUD operations for replay_runs table.

Provides create, read, and update operations for replay runs
that track artifact reproduction attempts.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.campaign_models import ReplayRun as DBReplayRun
from database.connection import get_session


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_dict(row: DBReplayRun) -> dict:
    """Map a SQLAlchemy ReplayRun row to a plain dict."""
    return {
        "id": row.id,
        "artifact_id": row.artifact_id,
        "status": row.status,
        "stability_score": row.stability_score,
        "attempts": row.attempts,
        "result": row.result,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class ReplayService:
    """Thin service layer around the replay_runs table."""

    async def create_replay_run(
        self,
        artifact_id: str,
        status: str = "pending",
    ) -> dict:
        """Persist a new replay run and return its dict representation."""
        replay_id = _short_id()

        db_replay = DBReplayRun(
            id=replay_id,
            artifact_id=artifact_id,
            status=status,
        )

        async with get_session() as session:
            session.add(db_replay)
            await session.flush()
            await session.refresh(db_replay)
            return _db_to_dict(db_replay)

    async def update_replay_run(
        self,
        replay_id: str,
        status: str,
        stability_score: Optional[float] = None,
        attempts: Optional[int] = None,
        result: Optional[dict] = None,
    ) -> dict:
        """Update a replay run's status and optional fields.

        Returns the updated dict, or raises if the replay run
        does not exist.
        """
        async with get_session() as session:
            row = await session.get(DBReplayRun, replay_id)
            if row is None:
                raise ValueError(f"Replay run {replay_id} not found")

            row.status = status

            if stability_score is not None:
                row.stability_score = stability_score
            if attempts is not None:
                row.attempts = attempts
            if result is not None:
                row.result = result

            await session.flush()
            await session.refresh(row)
            return _db_to_dict(row)

    async def get_replay_run(
        self, replay_id: str
    ) -> Optional[dict]:
        """Return a single replay run by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBReplayRun, replay_id)
            if row is None:
                return None
            return _db_to_dict(row)


# Module-level singleton
replay_service = ReplayService()
