"""Campaign service -- CRUD operations for campaign lifecycle.

Provides create, read, list, and status-update operations against the
campaigns table.  All methods use ``get_session()`` so each call gets
its own transactional scope.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from database.campaign_models import Campaign as DBCampaign
from database.connection import get_session
from models.campaign_enums import CampaignPreset, CampaignStatus
from models.campaign_schemas import CampaignCreateRequest, CampaignResponse

# ---------------------------------------------------------------------------
# Preset budget map (seconds)
# ---------------------------------------------------------------------------

PRESET_BUDGETS: dict[str, int] = {
    "quick": 600,        # 10 min
    "medium": 1800,      # 30 min
    "advanced": 7200,    # 2 hrs
    "pro": 21600,        # 6 hrs
    "ultra": 86400,      # 24 hrs
    "evil": 259200,      # 72 hrs
}


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_response(row: DBCampaign) -> CampaignResponse:
    """Map a SQLAlchemy Campaign row to a CampaignResponse."""
    return CampaignResponse(
        id=row.id,
        repo_id=row.repo_id,
        status=CampaignStatus(row.status),
        preset=CampaignPreset(row.preset),
        budget_seconds=row.budget_seconds,
        max_parallel_lanes=row.max_parallel_lanes or 2,
        lm_provider=row.lm_provider or "claude_cli",
        lm_model=row.lm_model or "claude-opus-4-6",
        created_at=row.created_at,
        started_at=row.started_at,
        completed_at=row.completed_at,
        error_message=row.error_message,
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class CampaignService:
    """Thin service layer around the campaigns table."""

    async def create_campaign(
        self, request: CampaignCreateRequest
    ) -> CampaignResponse:
        """Persist a new campaign and return its response representation."""
        campaign_id = _short_id()

        # Resolve budget: explicit override wins, else look up preset.
        budget = request.budget_seconds
        if budget is None:
            budget = PRESET_BUDGETS.get(request.campaign_preset)

        db_campaign = DBCampaign(
            id=campaign_id,
            repo_id=request.repo_id,
            status=CampaignStatus.CREATED.value,
            preset=request.campaign_preset,
            budget_seconds=budget,
            max_parallel_lanes=request.max_parallel_lanes,
            lm_provider=request.lm_provider,
            lm_model=request.lm_model,
            config={
                "target_scope": request.target_scope,
                "methodology_overrides": request.methodology_overrides,
                "enabled_engines": request.enabled_engines,
                "max_lm_jobs": request.max_lm_jobs,
                "seed_sources": request.seed_sources,
                "corpus_reuse_policy": request.corpus_reuse_policy,
                "actor_profiles": request.actor_profiles,
                "env_profile": request.env_profile,
                "directed_targets": request.directed_targets,
                "custom_oracles": request.custom_oracles,
                "target_filters": request.target_filters,
                "steering_interval_seconds": request.steering_interval_seconds,
                "plateau_window_seconds": request.plateau_window_seconds,
                "max_compilation_failures_per_lane": request.max_compilation_failures_per_lane,
                "max_steering_cycles": request.max_steering_cycles,
                "repro_attempts": request.repro_attempts,
                "minimization_budget_seconds": request.minimization_budget_seconds,
            },
        )

        async with get_session() as session:
            session.add(db_campaign)
            await session.flush()
            # Refresh to populate server defaults (created_at).
            await session.refresh(db_campaign)
            return _db_to_response(db_campaign)

    async def get_campaign(
        self, campaign_id: str
    ) -> Optional[CampaignResponse]:
        """Return a single campaign by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBCampaign, campaign_id)
            if row is None:
                return None
            return _db_to_response(row)

    async def list_campaigns(
        self, repo_id: str | None = None
    ) -> list[CampaignResponse]:
        """List campaigns, optionally filtering by repo_id."""
        async with get_session() as session:
            stmt = select(DBCampaign)
            if repo_id is not None:
                stmt = stmt.where(DBCampaign.repo_id == repo_id)
            stmt = stmt.order_by(DBCampaign.created_at.desc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_response(r) for r in rows]

    async def update_campaign_status(
        self,
        campaign_id: str,
        status: str,
        **kwargs,
    ) -> Optional[CampaignResponse]:
        """Update a campaign's status and optional metadata fields.

        Accepted kwargs:
            started_at, completed_at, error_message
        """
        async with get_session() as session:
            row = await session.get(DBCampaign, campaign_id)
            if row is None:
                return None

            row.status = status

            if "started_at" in kwargs:
                row.started_at = kwargs["started_at"]
            if "completed_at" in kwargs:
                row.completed_at = kwargs["completed_at"]
            if "error_message" in kwargs:
                row.error_message = kwargs["error_message"]

            await session.flush()
            await session.refresh(row)
            return _db_to_response(row)


# Module-level singleton
campaign_service = CampaignService()
