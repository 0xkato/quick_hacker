"""Deterministic steering engine for v1 -- no LM calls.

Analyses campaign metrics (coverage snapshots, lane validity ratios,
artifact counts) and produces actionable steering decisions that the
controller can apply to running campaigns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class SteeringDecision:
    campaign_id: str
    decision_type: str  # "plateau_recovery", "validity_fix", "target_rebalance", "no_action"
    triggering_metrics: dict
    recommendation: str  # human-readable description
    affected_lane_ids: list[str] = field(default_factory=list)


def _parse_ts(value: str | datetime) -> datetime:
    """Coerce a string or datetime into a tz-aware datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    # ISO-8601 string
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def detect_plateau(
    coverage_snapshots: list[dict],
    window_seconds: int = 300,
) -> bool:
    """True if no new operations covered in the last *window_seconds*.

    Each snapshot has: ``operations_hit`` (int), ``created_at`` (str/datetime).
    Plateau = latest operations_hit == earliest operations_hit in window.

    Returns ``False`` for empty or single-element snapshot lists (not enough
    data to determine a plateau).
    """
    if len(coverage_snapshots) < 2:
        return False

    # Sort ascending by timestamp
    sorted_snaps = sorted(coverage_snapshots, key=lambda s: _parse_ts(s["created_at"]))

    latest_ts = _parse_ts(sorted_snaps[-1]["created_at"])
    cutoff = latest_ts.timestamp() - window_seconds

    # Filter to snapshots within the window
    window_snaps = [
        s for s in sorted_snaps
        if _parse_ts(s["created_at"]).timestamp() >= cutoff
    ]

    if len(window_snaps) < 2:
        return False

    earliest_ops = window_snaps[0].get("operations_hit", 0)
    latest_ops = window_snaps[-1].get("operations_hit", 0)

    return latest_ops == earliest_ops


def generate_steering_decision(
    campaign_id: str,
    lane_metrics: list[dict],
    coverage_snapshots: list[dict],
    artifact_counts: dict,
    plateau_window: int = 300,
) -> SteeringDecision | None:
    """Generate a steering decision based on current metrics.

    Returns ``None`` if no action is needed.

    Checks (evaluated in priority order):

    1. **Coverage plateau** -- no new operations in *plateau_window* seconds.
       Recommendation: inject new seeds or increase mutation rate.
    2. **Low validity ratio** -- any lane with ``validity_ratio < 0.1``.
       Recommendation: refine schema constraints.
    3. **No artifacts after 50 %+ budget** -- at least one lane has spent
       more than half its budget yet the campaign has zero artifacts.
       Recommendation: consider target rebalance.
    """

    # --- 1. Coverage plateau ------------------------------------------------
    if detect_plateau(coverage_snapshots, window_seconds=plateau_window):
        return SteeringDecision(
            campaign_id=campaign_id,
            decision_type="plateau_recovery",
            triggering_metrics={
                "snapshot_count": len(coverage_snapshots),
                "window_seconds": plateau_window,
            },
            recommendation="Inject new seeds or increase mutation rate",
            affected_lane_ids=[m["lane_id"] for m in lane_metrics],
        )

    # --- 2. Low validity ratio ----------------------------------------------
    low_validity_lanes = [
        m for m in lane_metrics
        if m.get("validity_ratio", 1.0) < 0.1
    ]
    if low_validity_lanes:
        return SteeringDecision(
            campaign_id=campaign_id,
            decision_type="validity_fix",
            triggering_metrics={
                "low_validity_lanes": [
                    {"lane_id": m["lane_id"], "validity_ratio": m["validity_ratio"]}
                    for m in low_validity_lanes
                ],
            },
            recommendation="Refine schema constraints",
            affected_lane_ids=[m["lane_id"] for m in low_validity_lanes],
        )

    # --- 3. No artifacts after 50%+ budget ----------------------------------
    total_artifacts = sum(artifact_counts.values()) if artifact_counts else 0
    high_budget_lanes = [
        m for m in lane_metrics
        if m.get("budget_used_pct", 0) >= 50.0
    ]
    if high_budget_lanes and total_artifacts == 0:
        return SteeringDecision(
            campaign_id=campaign_id,
            decision_type="target_rebalance",
            triggering_metrics={
                "total_artifacts": total_artifacts,
                "high_budget_lanes": [
                    {"lane_id": m["lane_id"], "budget_used_pct": m["budget_used_pct"]}
                    for m in high_budget_lanes
                ],
            },
            recommendation="Consider target rebalance",
            affected_lane_ids=[m["lane_id"] for m in high_budget_lanes],
        )

    return None
