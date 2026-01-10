"""Time-tiered scan configuration helpers.

Scan tiers are user-facing time budgets that determine how long an audit should run.
They are intentionally separate from provider/model "tier" settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


SCAN_TIER_BUDGET_SECONDS: dict[str, int] = {
    "quick": 5 * 60,
    "medium": 15 * 60,
    "advanced": 45 * 60,
    "pro": 90 * 60,
    "ultra": 4 * 60 * 60,
    "evil": 24 * 60 * 60,
}

DEFAULT_SCAN_TIER = "quick"

# Hard bounds for custom timing overrides.
MIN_TIME_BUDGET_SECONDS = 60
MAX_TIME_BUDGET_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class ResolvedScanBudget:
    scan_tier: str
    time_budget_seconds: int
    is_custom_budget: bool


def _normalize_scan_tier(scan_tier: Optional[str]) -> Optional[str]:
    if scan_tier is None:
        return None
    normalized = scan_tier.strip().lower()
    return normalized or None


def resolve_scan_budget(
    *,
    scan_tier: Optional[str],
    time_budget_seconds: Optional[int],
) -> ResolvedScanBudget:
    """Resolve a scan tier + optional override into an effective time budget.

    Rules:
    - If time_budget_seconds is provided, it overrides scan_tier validation.
    - If scan_tier is omitted, default to quick.
    - If scan_tier is invalid and no override is provided, raise ValueError.
    """
    if time_budget_seconds is not None:
        if not (MIN_TIME_BUDGET_SECONDS <= time_budget_seconds <= MAX_TIME_BUDGET_SECONDS):
            raise ValueError(
                f"time_budget_seconds must be between {MIN_TIME_BUDGET_SECONDS} and {MAX_TIME_BUDGET_SECONDS}"
            )
        normalized = _normalize_scan_tier(scan_tier) or "custom"
        return ResolvedScanBudget(
            scan_tier=normalized,
            time_budget_seconds=int(time_budget_seconds),
            is_custom_budget=True,
        )

    normalized = _normalize_scan_tier(scan_tier) or DEFAULT_SCAN_TIER
    if normalized not in SCAN_TIER_BUDGET_SECONDS:
        valid = ", ".join(sorted(SCAN_TIER_BUDGET_SECONDS.keys()))
        raise ValueError(f"Invalid scan_tier '{scan_tier}'. Valid tiers: {valid}.")

    return ResolvedScanBudget(
        scan_tier=normalized,
        time_budget_seconds=SCAN_TIER_BUDGET_SECONDS[normalized],
        is_custom_budget=False,
    )

