"""Campaign job scheduler — manages queue placement, retries, backpressure.

Responsibilities:
- Enqueue jobs to the correct Dramatiq queue
- Track active jobs per campaign
- Enforce max_parallel_lanes
- Supersede queued jobs when lane specs are revised
- One active steering job per campaign
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CampaignJobTracker:
    """Tracks active and queued jobs for a campaign."""
    campaign_id: str
    active_lane_runs: int = 0
    max_parallel_lanes: int = 2
    steering_active: bool = False
    queued_jobs: list[dict] = field(default_factory=list)


class CampaignScheduler:
    """Manages job scheduling across campaigns."""

    def __init__(self):
        self._trackers: dict[str, CampaignJobTracker] = {}

    def get_tracker(self, campaign_id: str, max_parallel: int = 2) -> CampaignJobTracker:
        if campaign_id not in self._trackers:
            self._trackers[campaign_id] = CampaignJobTracker(
                campaign_id=campaign_id,
                max_parallel_lanes=max_parallel,
            )
        return self._trackers[campaign_id]

    def can_enqueue_lane(self, campaign_id: str) -> bool:
        tracker = self._trackers.get(campaign_id)
        if not tracker:
            return True
        return tracker.active_lane_runs < tracker.max_parallel_lanes

    def record_lane_start(self, campaign_id: str):
        tracker = self.get_tracker(campaign_id)
        tracker.active_lane_runs += 1

    def record_lane_complete(self, campaign_id: str):
        tracker = self._trackers.get(campaign_id)
        if tracker and tracker.active_lane_runs > 0:
            tracker.active_lane_runs -= 1

    def can_steer(self, campaign_id: str) -> bool:
        tracker = self._trackers.get(campaign_id)
        if not tracker:
            return True
        return not tracker.steering_active

    def record_steering_start(self, campaign_id: str):
        tracker = self.get_tracker(campaign_id)
        tracker.steering_active = True

    def record_steering_complete(self, campaign_id: str):
        tracker = self._trackers.get(campaign_id)
        if tracker:
            tracker.steering_active = False

    def cleanup_campaign(self, campaign_id: str):
        self._trackers.pop(campaign_id, None)


campaign_scheduler = CampaignScheduler()
