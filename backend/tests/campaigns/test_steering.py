"""Tests for the deterministic steering engine."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from campaigns.steering import (
    SteeringDecision,
    detect_plateau,
    generate_steering_decision,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_TIME = datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc)


def _snap(ops: int, offset_seconds: int = 0) -> dict:
    """Build a coverage snapshot dict at _BASE_TIME + offset."""
    return {
        "operations_hit": ops,
        "created_at": _BASE_TIME + timedelta(seconds=offset_seconds),
    }


def _lane(
    lane_id: str = "lane1",
    validity_ratio: float = 0.8,
    requests_per_sec: float = 50.0,
    budget_used_pct: float = 25.0,
) -> dict:
    return {
        "lane_id": lane_id,
        "validity_ratio": validity_ratio,
        "requests_per_sec": requests_per_sec,
        "budget_used_pct": budget_used_pct,
    }


# ---------------------------------------------------------------------------
# detect_plateau
# ---------------------------------------------------------------------------


class TestDetectPlateau:
    def test_true_when_no_coverage_change(self):
        """Plateau detected when operations_hit stays flat within window."""
        snapshots = [
            _snap(10, 0),
            _snap(10, 60),
            _snap(10, 120),
            _snap(10, 180),
        ]
        assert detect_plateau(snapshots, window_seconds=300) is True

    def test_false_when_operations_increasing(self):
        """No plateau when operations_hit is growing."""
        snapshots = [
            _snap(5, 0),
            _snap(8, 60),
            _snap(12, 120),
            _snap(15, 180),
        ]
        assert detect_plateau(snapshots, window_seconds=300) is False

    def test_empty_snapshots_no_plateau(self):
        """Empty snapshot list should never indicate a plateau."""
        assert detect_plateau([], window_seconds=300) is False

    def test_single_snapshot_no_plateau(self):
        """A single snapshot is not enough to determine a plateau."""
        assert detect_plateau([_snap(10, 0)], window_seconds=300) is False

    def test_plateau_only_within_window(self):
        """Snapshots outside the window should not affect the result."""
        snapshots = [
            _snap(5, 0),       # outside 120s window from latest
            _snap(10, 100),    # inside window
            _snap(10, 200),    # latest
        ]
        # Window = 120s from latest (t=200). Only t=100 and t=200 are inside.
        assert detect_plateau(snapshots, window_seconds=120) is True

    def test_string_timestamps_accepted(self):
        """Timestamps as ISO-8601 strings should work."""
        snapshots = [
            {"operations_hit": 10, "created_at": "2026-03-22T12:00:00+00:00"},
            {"operations_hit": 10, "created_at": "2026-03-22T12:03:00+00:00"},
        ]
        assert detect_plateau(snapshots, window_seconds=300) is True


# ---------------------------------------------------------------------------
# generate_steering_decision
# ---------------------------------------------------------------------------


class TestGenerateSteeringDecision:
    def test_plateau_recovery_decision(self):
        """A coverage plateau should produce a plateau_recovery decision."""
        snapshots = [_snap(10, 0), _snap(10, 60), _snap(10, 120)]
        lanes = [_lane("lane1"), _lane("lane2")]

        decision = generate_steering_decision(
            campaign_id="camp01",
            lane_metrics=lanes,
            coverage_snapshots=snapshots,
            artifact_counts={"crash": 2},
        )

        assert decision is not None
        assert isinstance(decision, SteeringDecision)
        assert decision.campaign_id == "camp01"
        assert decision.decision_type == "plateau_recovery"
        assert "Inject new seeds" in decision.recommendation
        assert set(decision.affected_lane_ids) == {"lane1", "lane2"}

    def test_low_validity_decision(self):
        """Low validity ratio (< 0.1) should produce a validity_fix decision."""
        snapshots = [_snap(5, 0), _snap(10, 60)]  # not a plateau
        lanes = [
            _lane("lane1", validity_ratio=0.05),
            _lane("lane2", validity_ratio=0.8),
        ]

        decision = generate_steering_decision(
            campaign_id="camp01",
            lane_metrics=lanes,
            coverage_snapshots=snapshots,
            artifact_counts={"crash": 1},
        )

        assert decision is not None
        assert decision.decision_type == "validity_fix"
        assert "schema constraints" in decision.recommendation.lower()
        assert decision.affected_lane_ids == ["lane1"]

    def test_target_rebalance_decision(self):
        """No artifacts after 50%+ budget should produce target_rebalance."""
        snapshots = [_snap(5, 0), _snap(10, 60)]  # not a plateau
        lanes = [_lane("lane1", validity_ratio=0.5, budget_used_pct=75.0)]

        decision = generate_steering_decision(
            campaign_id="camp01",
            lane_metrics=lanes,
            coverage_snapshots=snapshots,
            artifact_counts={},
        )

        assert decision is not None
        assert decision.decision_type == "target_rebalance"
        assert "rebalance" in decision.recommendation.lower()
        assert decision.affected_lane_ids == ["lane1"]

    def test_none_when_healthy(self):
        """All metrics healthy should return None (no action needed)."""
        snapshots = [_snap(5, 0), _snap(10, 60), _snap(15, 120)]
        lanes = [_lane("lane1", validity_ratio=0.8, budget_used_pct=30.0)]

        decision = generate_steering_decision(
            campaign_id="camp01",
            lane_metrics=lanes,
            coverage_snapshots=snapshots,
            artifact_counts={"crash": 3},
        )

        assert decision is None

    def test_plateau_takes_priority_over_validity(self):
        """Plateau check should fire before validity check."""
        snapshots = [_snap(10, 0), _snap(10, 60), _snap(10, 120)]
        lanes = [_lane("lane1", validity_ratio=0.01)]

        decision = generate_steering_decision(
            campaign_id="camp01",
            lane_metrics=lanes,
            coverage_snapshots=snapshots,
            artifact_counts={},
        )

        assert decision is not None
        assert decision.decision_type == "plateau_recovery"

    def test_no_lanes_returns_none(self):
        """Empty lane_metrics should safely return None."""
        decision = generate_steering_decision(
            campaign_id="camp01",
            lane_metrics=[],
            coverage_snapshots=[],
            artifact_counts={},
        )

        assert decision is None
