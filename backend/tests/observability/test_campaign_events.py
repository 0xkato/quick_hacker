import pytest
from observability.campaign_events import (
    CampaignEvent,
    CampaignEventBroadcaster,
    CampaignEventType,
    THROTTLE_RULES,
    campaign_broadcaster,
)


class TestCampaignEventType:
    def test_all_19_event_types_exist(self):
        assert len(CampaignEventType) == 19

    def test_expected_event_type_values(self):
        expected = [
            "campaign_status",
            "target_upsert",
            "lane_upsert",
            "run_upsert",
            "lane_metrics",
            "coverage_update",
            "corpus_update",
            "artifact_bucket_opened",
            "artifact_bucket_updated",
            "artifact_classified",
            "replay_update",
            "issue_upsert",
            "steering_decision",
            "harness_validation_result",
            "lane_retired",
            "report_ready",
            "llm_job_update",
            "runner_log",
            "graph_update",
        ]
        actual = [e.value for e in CampaignEventType]
        assert actual == expected


class TestThrottleRules:
    def test_every_event_type_has_throttle_rule(self):
        for event_type in CampaignEventType:
            assert event_type in THROTTLE_RULES, f"Missing throttle rule for {event_type}"

    def test_no_extra_throttle_rules(self):
        assert len(THROTTLE_RULES) == len(CampaignEventType)

    def test_lane_metrics_throttle(self):
        assert THROTTLE_RULES[CampaignEventType.LANE_METRICS]["throttle_ms"] == 200

    def test_coverage_update_throttle(self):
        assert THROTTLE_RULES[CampaignEventType.COVERAGE_UPDATE]["throttle_ms"] == 1000

    def test_campaign_status_no_throttle(self):
        assert THROTTLE_RULES[CampaignEventType.CAMPAIGN_STATUS]["throttle_ms"] == 0

    def test_deduplicate_flags(self):
        assert THROTTLE_RULES[CampaignEventType.TARGET_UPSERT].get("deduplicate") is True
        assert THROTTLE_RULES[CampaignEventType.ISSUE_UPSERT].get("deduplicate") is True
        assert THROTTLE_RULES[CampaignEventType.LANE_UPSERT].get("deduplicate") is None


class TestCampaignEvent:
    def test_to_ws_message_structure(self):
        event = CampaignEvent(
            event_type=CampaignEventType.CAMPAIGN_STATUS,
            campaign_id="camp-123",
            data={"status": "running"},
            timestamp="2026-03-22T00:00:00",
        )
        msg = event.to_ws_message()
        assert msg == {
            "type": "campaign_status",
            "campaign_id": "camp-123",
            "data": {"status": "running"},
            "timestamp": "2026-03-22T00:00:00",
        }

    def test_default_timestamp_is_iso_format(self):
        event = CampaignEvent(
            event_type=CampaignEventType.LANE_UPSERT,
            campaign_id="camp-456",
            data={"lane_id": "lane-1"},
        )
        # ISO format check: contains T separator and no trailing Z (utcnow doesn't add it)
        assert "T" in event.timestamp
        msg = event.to_ws_message()
        assert msg["timestamp"] == event.timestamp

    def test_event_type_is_string_in_message(self):
        event = CampaignEvent(
            event_type=CampaignEventType.ARTIFACT_CLASSIFIED,
            campaign_id="camp-789",
            data={},
        )
        msg = event.to_ws_message()
        assert isinstance(msg["type"], str)
        assert msg["type"] == "artifact_classified"


class TestCampaignEventBroadcaster:
    def setup_method(self):
        self.broadcaster = CampaignEventBroadcaster()

    def test_emit_returns_ws_message(self):
        event = CampaignEvent(
            event_type=CampaignEventType.RUN_UPSERT,
            campaign_id="camp-1",
            data={"run_id": "run-1"},
        )
        msg = self.broadcaster.emit(event)
        assert msg["type"] == "run_upsert"
        assert msg["campaign_id"] == "camp-1"
        assert msg["data"]["run_id"] == "run-1"

    def test_emit_campaign_status(self):
        msg = self.broadcaster.emit_campaign_status("camp-1", "running", progress=42)
        assert msg["type"] == "campaign_status"
        assert msg["campaign_id"] == "camp-1"
        assert msg["data"]["status"] == "running"
        assert msg["data"]["progress"] == 42

    def test_emit_lane_retired(self):
        msg = self.broadcaster.emit_lane_retired("camp-1", "lane-7", "budget_exhausted")
        assert msg["type"] == "lane_retired"
        assert msg["data"]["lane_id"] == "lane-7"
        assert msg["data"]["reason"] == "budget_exhausted"

    def test_emit_artifact_bucket_opened(self):
        msg = self.broadcaster.emit_artifact_bucket_opened("camp-1", "bkt-1", "crash")
        assert msg["type"] == "artifact_bucket_opened"
        assert msg["data"]["bucket_key"] == "bkt-1"
        assert msg["data"]["type"] == "crash"

    def test_emit_issue_upsert(self):
        msg = self.broadcaster.emit_issue_upsert("camp-1", "iss-1", "confirmed", "high")
        assert msg["type"] == "issue_upsert"
        assert msg["data"]["issue_id"] == "iss-1"
        assert msg["data"]["disposition"] == "confirmed"
        assert msg["data"]["severity"] == "high"

    def test_emit_steering_decision(self):
        msg = self.broadcaster.emit_steering_decision("camp-1", "pivot", "switch_to_fuzzing")
        assert msg["type"] == "steering_decision"
        assert msg["data"]["decision_type"] == "pivot"
        assert msg["data"]["recommendation"] == "switch_to_fuzzing"

    def test_module_level_singleton(self):
        assert isinstance(campaign_broadcaster, CampaignEventBroadcaster)
