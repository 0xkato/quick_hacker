"""Steering service -- record and query automated steering decisions.

Provides CRUD operations against the steering_decisions table.
All methods use ``get_session()`` so each call gets its own
transactional scope.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from database.campaign_models import SteeringDecision as DBSteeringDecision
from database.connection import get_session


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_dict(row: DBSteeringDecision) -> dict[str, Any]:
    """Map a SQLAlchemy SteeringDecision row to a plain dict."""
    return {
        "id": row.id,
        "campaign_id": row.campaign_id,
        "decision_type": row.decision.get("decision_type") if row.decision else None,
        "triggering_metrics": row.triggering_metrics,
        "recommendation": row.decision.get("recommendation") if row.decision else None,
        "affected_lane_ids": row.decision.get("affected_lane_ids", []) if row.decision else [],
        "expected_effect": row.expected_effect,
        "actual_effect": row.actual_effect,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class SteeringService:
    """Thin service layer around the steering_decisions table."""

    async def record_decision(
        self,
        campaign_id: str,
        decision_type: str,
        triggering_metrics: dict,
        recommendation: str,
        affected_lane_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Persist a new steering decision and return it as a plain dict."""
        decision_id = _short_id()

        db_decision = DBSteeringDecision(
            id=decision_id,
            campaign_id=campaign_id,
            triggering_metrics=triggering_metrics,
            decision={
                "decision_type": decision_type,
                "recommendation": recommendation,
                "affected_lane_ids": affected_lane_ids or [],
            },
            expected_effect=recommendation,
        )

        async with get_session() as session:
            session.add(db_decision)
            await session.flush()
            await session.refresh(db_decision)
            return _db_to_dict(db_decision)

    async def list_decisions(
        self, campaign_id: str
    ) -> list[dict[str, Any]]:
        """List all steering decisions for a campaign, newest first."""
        async with get_session() as session:
            stmt = (
                select(DBSteeringDecision)
                .where(DBSteeringDecision.campaign_id == campaign_id)
                .order_by(DBSteeringDecision.created_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_dict(r) for r in rows]

    async def get_latest_decision(
        self, campaign_id: str
    ) -> dict[str, Any] | None:
        """Return the most recent steering decision, or None if none exist."""
        async with get_session() as session:
            stmt = (
                select(DBSteeringDecision)
                .where(DBSteeringDecision.campaign_id == campaign_id)
                .order_by(DBSteeringDecision.created_at.desc())
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row is None:
                return None
            return _db_to_dict(row)


# Module-level singleton
steering_service = SteeringService()
