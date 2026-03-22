"""Flow tracking operations for ToolCore.

NOTE: The old flow_service has been removed as part of the campaign pivot.
These methods are retained as no-op stubs so existing code that references
FlowTrackingMixin does not break.
"""
from __future__ import annotations

from typing import Any, Optional


class FlowTrackingMixin:
    """Mixin for flow tracking operations (stubbed -- old flow_service removed)."""

    async def track_file_analysis(
        self, file_path: str, purpose: str = "analyzing"
    ) -> dict[str, Any]:
        return {"node_id": None, "status": "no_flow_service"}

    async def track_function_discovered(
        self,
        function_name: str,
        file_path: str,
        line_number: int,
        signature: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        return {"node_id": None}

    async def track_call_chain(
        self, from_function: str, calls: list[dict[str, str]]
    ) -> dict[str, Any]:
        return {"call_nodes": []}

    async def track_sink_identified(
        self,
        sink_type: str,
        file_path: str,
        line_number: int,
        code_snippet: Optional[str] = None,
    ) -> dict[str, Any]:
        return {"node_id": None, "marked_dangerous": False}

    async def track_entry_point(
        self,
        entry_type: str,
        file_path: str,
        line_number: int,
        route: Optional[str] = None,
        method: Optional[str] = None,
    ) -> dict[str, Any]:
        return {"node_id": None}

    async def track_triage_gate(
        self,
        batch_id: str,
        raw_count: int,
        triaged_count: int,
        reportable_count: int,
        by_disposition: dict[str, int],
        policy_version: str,
        finding_refs: list[tuple[str, str]],
    ) -> dict[str, Any]:
        return {"node_id": None}
