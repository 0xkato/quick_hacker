import asyncio
import json
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class CampaignEventType(str, Enum):
    CAMPAIGN_STATUS = "campaign_status"
    TARGET_UPSERT = "target_upsert"
    LANE_UPSERT = "lane_upsert"
    RUN_UPSERT = "run_upsert"
    LANE_METRICS = "lane_metrics"
    COVERAGE_UPDATE = "coverage_update"
    CORPUS_UPDATE = "corpus_update"
    ARTIFACT_BUCKET_OPENED = "artifact_bucket_opened"
    ARTIFACT_BUCKET_UPDATED = "artifact_bucket_updated"
    ARTIFACT_CLASSIFIED = "artifact_classified"
    REPLAY_UPDATE = "replay_update"
    ISSUE_UPSERT = "issue_upsert"
    STEERING_DECISION = "steering_decision"
    HARNESS_VALIDATION_RESULT = "harness_validation_result"
    LANE_RETIRED = "lane_retired"
    REPORT_READY = "report_ready"
    LLM_JOB_UPDATE = "llm_job_update"
    RUNNER_LOG = "runner_log"
    GRAPH_UPDATE = "graph_update"


# Throttling rules per event type
THROTTLE_RULES: dict[CampaignEventType, dict] = {
    CampaignEventType.CAMPAIGN_STATUS: {"throttle_ms": 0},
    CampaignEventType.TARGET_UPSERT: {"throttle_ms": 0, "deduplicate": True},
    CampaignEventType.LANE_UPSERT: {"throttle_ms": 0},
    CampaignEventType.RUN_UPSERT: {"throttle_ms": 0},
    CampaignEventType.LANE_METRICS: {"throttle_ms": 200},
    CampaignEventType.COVERAGE_UPDATE: {"throttle_ms": 1000},
    CampaignEventType.CORPUS_UPDATE: {"throttle_ms": 1000},
    CampaignEventType.ARTIFACT_BUCKET_OPENED: {"throttle_ms": 0},
    CampaignEventType.ARTIFACT_BUCKET_UPDATED: {"throttle_ms": 0},
    CampaignEventType.ARTIFACT_CLASSIFIED: {"throttle_ms": 0},
    CampaignEventType.REPLAY_UPDATE: {"throttle_ms": 0},
    CampaignEventType.ISSUE_UPSERT: {"throttle_ms": 0, "deduplicate": True},
    CampaignEventType.STEERING_DECISION: {"throttle_ms": 0},
    CampaignEventType.HARNESS_VALIDATION_RESULT: {"throttle_ms": 0},
    CampaignEventType.LANE_RETIRED: {"throttle_ms": 0},
    CampaignEventType.REPORT_READY: {"throttle_ms": 0},
    CampaignEventType.LLM_JOB_UPDATE: {"throttle_ms": 250},
    CampaignEventType.RUNNER_LOG: {"throttle_ms": 250},
    CampaignEventType.GRAPH_UPDATE: {"throttle_ms": 250},
}


@dataclass
class CampaignEvent:
    event_type: CampaignEventType
    campaign_id: str
    data: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_ws_message(self) -> dict:
        return {
            "type": self.event_type.value,
            "campaign_id": self.campaign_id,
            "data": self.data,
            "timestamp": self.timestamp,
        }


class CampaignEventBroadcaster:
    """Wraps WebSocket broadcasting with campaign-specific events and throttling.

    Call ``set_broadcast_fn`` during app startup to wire actual WebSocket
    broadcasting.  Without it, ``emit`` still returns the formatted message
    for testing/logging.
    """

    def __init__(self):
        self._broadcast_fn: Callable[[dict], Coroutine] | None = None

    def set_broadcast_fn(self, fn: Callable[[dict], Coroutine]):
        """Set the WebSocket broadcast function. Called during app startup."""
        self._broadcast_fn = fn

    def emit(self, event: CampaignEvent) -> dict:
        """Format event as WebSocket message and broadcast if wired.

        Returns the message dict regardless of broadcast success.
        """
        msg = event.to_ws_message()
        if self._broadcast_fn:
            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(self._broadcast_fn(msg))
                task.add_done_callback(self._handle_broadcast_error)
            except RuntimeError:
                # No running event loop -- best-effort skip
                logger.debug("No running event loop for campaign broadcast")
        return msg

    @staticmethod
    def _handle_broadcast_error(task: asyncio.Task):
        """Log exceptions from fire-and-forget broadcast tasks."""
        try:
            exc = task.exception()
            if exc is not None:
                logger.error(f"Campaign broadcast failed: {exc}")
        except asyncio.CancelledError:
            pass

    def emit_campaign_status(self, campaign_id: str, status: str, **extra) -> dict:
        return self.emit(CampaignEvent(
            event_type=CampaignEventType.CAMPAIGN_STATUS,
            campaign_id=campaign_id,
            data={"status": status, **extra},
        ))

    def emit_lane_retired(self, campaign_id: str, lane_id: str, reason: str) -> dict:
        return self.emit(CampaignEvent(
            event_type=CampaignEventType.LANE_RETIRED,
            campaign_id=campaign_id,
            data={"lane_id": lane_id, "reason": reason},
        ))

    def emit_artifact_bucket_opened(self, campaign_id: str, bucket_key: str, artifact_type: str) -> dict:
        return self.emit(CampaignEvent(
            event_type=CampaignEventType.ARTIFACT_BUCKET_OPENED,
            campaign_id=campaign_id,
            data={"bucket_key": bucket_key, "type": artifact_type},
        ))

    def emit_issue_upsert(self, campaign_id: str, issue_id: str, disposition: str, severity: str) -> dict:
        return self.emit(CampaignEvent(
            event_type=CampaignEventType.ISSUE_UPSERT,
            campaign_id=campaign_id,
            data={"issue_id": issue_id, "disposition": disposition, "severity": severity},
        ))

    def emit_steering_decision(self, campaign_id: str, decision_type: str, recommendation: str) -> dict:
        return self.emit(CampaignEvent(
            event_type=CampaignEventType.STEERING_DECISION,
            campaign_id=campaign_id,
            data={"decision_type": decision_type, "recommendation": recommendation},
        ))


campaign_broadcaster = CampaignEventBroadcaster()
