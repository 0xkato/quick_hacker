"""Target registry service -- CRUD operations for campaign targets.

Provides create (single and batch), read, list, and priority-update
operations against the targets table.  All methods use ``get_session()``
so each call gets its own transactional scope.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.campaign_models import Target as DBTarget
from database.connection import get_session
from models.campaign_enums import TargetKind
from models.campaign_schemas import TargetResponse


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_response(row: DBTarget) -> TargetResponse:
    """Map a SQLAlchemy Target row to a TargetResponse."""
    return TargetResponse(
        id=row.id,
        campaign_id=row.campaign_id,
        kind=TargetKind(row.kind),
        entrypoint=row.entrypoint,
        language=row.language,
        schemas=row.schemas,
        stateful=row.stateful if row.stateful is not None else False,
        actors=row.actors,
        reset_strategy=row.reset_strategy,
        priority_score=row.priority_score if row.priority_score is not None else 0.0,
        created_at=row.created_at,
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class TargetService:
    """Thin service layer around the targets table."""

    async def create_target(
        self,
        campaign_id: str,
        kind: str,
        entrypoint: str,
        language: str | None = None,
        **kwargs,
    ) -> TargetResponse:
        """Persist a new target and return its response representation."""
        target_id = _short_id()

        db_target = DBTarget(
            id=target_id,
            campaign_id=campaign_id,
            kind=kind,
            entrypoint=entrypoint,
            language=language,
            schemas=kwargs.get("schemas"),
            stateful=kwargs.get("stateful", False),
            actors=kwargs.get("actors"),
            reset_strategy=kwargs.get("reset_strategy"),
            priority_score=kwargs.get("priority_score"),
        )

        async with get_session() as session:
            session.add(db_target)
            await session.flush()
            await session.refresh(db_target)
            return _db_to_response(db_target)

    async def create_targets_batch(
        self,
        campaign_id: str,
        targets: list[dict],
    ) -> list[TargetResponse]:
        """Create multiple targets in a single transaction.

        Uses add_all + flush for bulk performance. Skips per-row refresh;
        created_at is set client-side so we don't need server defaults.
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db_targets = []
        for t in targets:
            db_target = DBTarget(
                id=_short_id(),
                campaign_id=campaign_id,
                kind=t["kind"],
                entrypoint=t["entrypoint"],
                language=t.get("language"),
                schemas=t.get("schemas"),
                stateful=t.get("stateful", False),
                actors=t.get("actors"),
                reset_strategy=t.get("reset_strategy"),
                priority_score=t.get("priority_score"),
                created_at=now,
            )
            db_targets.append(db_target)

        async with get_session() as session:
            session.add_all(db_targets)
            await session.flush()
            return [_db_to_response(t) for t in db_targets]

    async def get_target(
        self, target_id: str
    ) -> Optional[TargetResponse]:
        """Return a single target by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBTarget, target_id)
            if row is None:
                return None
            return _db_to_response(row)

    async def list_targets(
        self, campaign_id: str
    ) -> list[TargetResponse]:
        """List all targets for a campaign."""
        async with get_session() as session:
            stmt = select(DBTarget).where(
                DBTarget.campaign_id == campaign_id
            ).order_by(DBTarget.created_at.desc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_response(r) for r in rows]

    async def update_target_priority(
        self,
        target_id: str,
        priority_score: float,
    ) -> Optional[TargetResponse]:
        """Update a target's priority score.

        Returns the updated TargetResponse, or None if the target
        does not exist.
        """
        async with get_session() as session:
            row = await session.get(DBTarget, target_id)
            if row is None:
                return None

            row.priority_score = priority_score

            await session.flush()
            await session.refresh(row)
            return _db_to_response(row)


# Module-level singleton
target_service = TargetService()
