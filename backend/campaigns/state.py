"""Campaign state manager — tracks campaign phase and metadata.

Centralizes campaign state transitions and provides a snapshot
for the frontend graph view.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class CampaignSnapshot:
    """Point-in-time snapshot of campaign state for UI rendering."""
    campaign_id: str
    status: str
    phase: str  # intake, extracting, planning, compiling, executing, steering, evidence, analyzing
    target_count: int = 0
    lane_count: int = 0
    run_count: int = 0
    artifact_count: int = 0
    issue_count: int = 0
    coverage_ops_hit: int = 0
    steering_decisions: int = 0
    elapsed_seconds: float = 0.0
    started_at: Optional[str] = None


class CampaignStateManager:
    """In-memory campaign state tracker."""

    def __init__(self):
        self._snapshots: dict[str, CampaignSnapshot] = {}

    def get_snapshot(self, campaign_id: str) -> CampaignSnapshot | None:
        return self._snapshots.get(campaign_id)

    def update_snapshot(self, campaign_id: str, **kwargs) -> CampaignSnapshot:
        if campaign_id not in self._snapshots:
            self._snapshots[campaign_id] = CampaignSnapshot(
                campaign_id=campaign_id,
                status="created",
                phase="idle",
            )
        snap = self._snapshots[campaign_id]
        for k, v in kwargs.items():
            if hasattr(snap, k):
                setattr(snap, k, v)
        return snap

    def remove_snapshot(self, campaign_id: str):
        self._snapshots.pop(campaign_id, None)

    def to_graph_data(self, campaign_id: str) -> dict:
        """Convert campaign state to graph nodes + edges for the frontend."""
        snap = self._snapshots.get(campaign_id)
        if not snap:
            return {"nodes": [], "edges": []}

        nodes = [
            {"id": "campaign", "type": "campaign", "label": f"Campaign {campaign_id[:8]}", "data": {"status": snap.status, "phase": snap.phase}},
        ]
        edges = []

        if snap.target_count > 0:
            nodes.append({"id": "targets", "type": "targets", "label": f"{snap.target_count} targets", "data": {}})
            edges.append({"id": "e-camp-targets", "source": "campaign", "target": "targets"})

        if snap.lane_count > 0:
            nodes.append({"id": "lanes", "type": "lanes", "label": f"{snap.lane_count} lanes", "data": {}})
            edges.append({"id": "e-targets-lanes", "source": "targets", "target": "lanes"})

        if snap.run_count > 0:
            nodes.append({"id": "runs", "type": "runs", "label": f"{snap.run_count} runs", "data": {}})
            edges.append({"id": "e-lanes-runs", "source": "lanes", "target": "runs"})

        if snap.artifact_count > 0:
            nodes.append({"id": "artifacts", "type": "artifacts", "label": f"{snap.artifact_count} artifacts", "data": {}})
            edges.append({"id": "e-runs-artifacts", "source": "runs", "target": "artifacts"})

        if snap.issue_count > 0:
            nodes.append({"id": "issues", "type": "issues", "label": f"{snap.issue_count} issues", "data": {}})
            edges.append({"id": "e-artifacts-issues", "source": "artifacts", "target": "issues"})

        if snap.steering_decisions > 0:
            nodes.append({"id": "steering", "type": "steering", "label": f"{snap.steering_decisions} decisions", "data": {}})
            edges.append({"id": "e-runs-steering", "source": "runs", "target": "steering"})
            edges.append({"id": "e-steering-lanes", "source": "steering", "target": "lanes"})

        return {"nodes": nodes, "edges": edges}


campaign_state_manager = CampaignStateManager()
