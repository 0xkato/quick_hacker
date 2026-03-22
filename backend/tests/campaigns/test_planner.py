"""Tests for the deterministic lane planner."""

from __future__ import annotations

from campaigns.planner import plan_lanes_for_targets


class TestLanePlanner:
    def test_plans_one_lane_per_api_target(self):
        targets = [
            {"id": "t1", "kind": "api_route", "entrypoint": "GET /users", "stateful": False},
            {"id": "t2", "kind": "api_route", "entrypoint": "POST /orders", "stateful": False},
        ]
        lanes = plan_lanes_for_targets(targets, "quick")
        assert len(lanes) == 2
        assert lanes[0]["target_id"] == "t1"
        assert lanes[0]["engine"] == "schemathesis"

    def test_stateful_gets_extra_feedback_and_oracles(self):
        targets = [{"id": "t1", "kind": "api_route", "entrypoint": "GET /admin", "stateful": True}]
        lanes = plan_lanes_for_targets(targets, "quick")
        assert "state_depth" in lanes[0]["feedback_models"]
        assert "authz_diff" in lanes[0]["oracle_packs"]

    def test_budget_scales_with_preset(self):
        targets = [{"id": "t1", "kind": "api_route", "entrypoint": "GET /x", "stateful": False}]
        quick = plan_lanes_for_targets(targets, "quick")
        pro = plan_lanes_for_targets(targets, "pro")
        assert quick[0]["budget_seconds"] == 60
        assert pro[0]["budget_seconds"] == 1800

    def test_non_api_targets_skipped(self):
        targets = [
            {"id": "t1", "kind": "parser", "entrypoint": "parse_xml", "stateful": False},
            {"id": "t2", "kind": "api_route", "entrypoint": "GET /x", "stateful": False},
        ]
        lanes = plan_lanes_for_targets(targets, "quick")
        assert len(lanes) == 1
        assert lanes[0]["target_id"] == "t2"

    def test_empty_targets_returns_empty(self):
        assert plan_lanes_for_targets([], "quick") == []

    def test_all_lanes_status_planned(self):
        targets = [{"id": "t1", "kind": "api_route", "entrypoint": "GET /x", "stateful": False}]
        lanes = plan_lanes_for_targets(targets, "quick")
        assert lanes[0]["status"] == "planned"
