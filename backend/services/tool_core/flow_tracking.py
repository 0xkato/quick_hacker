"""Flow tracking operations for ToolCore."""
from __future__ import annotations

from typing import Any, Optional


class FlowTrackingMixin:
    """Mixin for flow tracking operations.

    This mixin provides methods for tracking investigation flows, including
    file analysis, function discovery, call chains, sinks, entry points, and
    triage gateways. It requires the following attributes to be set:
    - agent_id: Optional agent identifier
    """

    async def track_file_analysis(
        self,
        file_path: str,
        purpose: str = "analyzing"
    ) -> dict[str, Any]:
        """Track file analysis in flow tree.

        Args:
            file_path: Path relative to repo root
            purpose: Why analyzing this file

        Returns:
            dict with node_id and status
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None, "status": "no_agent"}

        # Update context to track current file
        flow_service.update_context(
            self.agent_id,
            current_file=file_path,
            current_function=None,  # Reset when switching files
            call_depth=0            # Reset depth
        )

        # Create file node
        node = flow_service.add_node(
            self.agent_id,
            node_type="file",
            label=file_path,
            data={
                "file_path": file_path,
                "purpose": purpose
            },
            auto_parent=True  # Parents to investigation root
        )

        return {"node_id": node.id, "status": "tracked"}

    async def track_function_discovered(
        self,
        function_name: str,
        file_path: str,
        line_number: int,
        signature: Optional[str] = None,
        reason: Optional[str] = None
    ) -> dict[str, Any]:
        """Track function discovery in flow tree.

        Args:
            function_name: Name of the function
            file_path: File containing function
            line_number: Line where defined
            signature: Full function signature
            reason: Why it's interesting

        Returns:
            dict with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Update context
        flow_service.update_context(
            self.agent_id,
            current_function=function_name,
            current_file=file_path
        )

        # Create function node
        node = flow_service.add_node(
            self.agent_id,
            node_type="function",
            label=function_name,
            data={
                "function_name": function_name,
                "file_path": file_path,
                "line_number": line_number,
                "signature": signature,
                "reason": reason
            },
            auto_parent=True  # Parents to current file
        )

        return {"node_id": node.id}

    async def track_call_chain(
        self,
        from_function: str,
        calls: list[dict[str, str]]
    ) -> dict[str, Any]:
        """Track function call chain in flow tree.

        Args:
            from_function: Function making the calls
            calls: List of calls with 'target' and optional 'file'

        Returns:
            dict with call_nodes list
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"call_nodes": []}

        flow = flow_service.get_flow(self.agent_id)
        if not flow:
            return {"call_nodes": []}

        context = flow.context
        call_node_ids = []

        for call in calls:
            target = call["target"]
            target_file = call.get("file")

            # Increment call depth
            new_depth = context.call_depth + 1

            # Respect max_call_depth
            if new_depth > context.max_call_depth:
                continue

            # Update context with new depth
            flow_service.update_context(self.agent_id, call_depth=new_depth)

            # Create call node
            node = flow_service.add_node(
                self.agent_id,
                node_type="call",
                label=f"→ {target}",
                data={
                    "target_function": target,
                    "target_file": target_file,
                    "from_function": from_function,
                    "call_depth": new_depth
                },
                auto_parent=True
            )

            call_node_ids.append(node.id)

        return {"call_nodes": call_node_ids}

    async def track_sink_identified(
        self,
        sink_type: str,
        file_path: str,
        line_number: int,
        code_snippet: Optional[str] = None
    ) -> dict[str, Any]:
        """Track dangerous sink in flow tree.

        Args:
            sink_type: Type of sink (sql, exec, etc.)
            file_path: File containing sink
            line_number: Line number
            code_snippet: Code showing sink

        Returns:
            dict with node_id and marked_dangerous flag
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None, "marked_dangerous": False}

        # Create dangerous_sink node
        node = flow_service.add_node(
            self.agent_id,
            node_type="dangerous_sink",
            label=f"⚠️ {sink_type.upper()} sink",
            data={
                "sink_type": sink_type,
                "file_path": file_path,
                "line_number": line_number,
                "code_snippet": code_snippet,
                "severity": "high"
            },
            auto_parent=True
        )

        return {"node_id": node.id, "marked_dangerous": True}

    async def track_entry_point(
        self,
        entry_type: str,
        file_path: str,
        line_number: int,
        route: Optional[str] = None,
        method: Optional[str] = None
    ) -> dict[str, Any]:
        """Track entry point in flow tree.

        Args:
            entry_type: Type of entry point
            file_path: File location
            line_number: Line number
            route: Route path if applicable
            method: HTTP method if applicable

        Returns:
            dict with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Build label
        label = route if route else f"{entry_type} entry point"
        if method:
            label = f"{method} {label}"

        # Create entry_point node
        node = flow_service.add_node(
            self.agent_id,
            node_type="entry_point",
            label=label,
            data={
                "entry_type": entry_type,
                "file_path": file_path,
                "line_number": line_number,
                "route": route,
                "method": method
            },
            auto_parent=True
        )

        return {"node_id": node.id}

    async def track_triage_gate(
        self,
        batch_id: str,
        raw_count: int,
        triaged_count: int,
        reportable_count: int,
        by_disposition: dict[str, int],
        policy_version: str,
        finding_refs: list[tuple[str, str]]
    ) -> dict[str, Any]:
        """Track triage gateway in flow tree.

        Args:
            batch_id: Unique batch identifier
            raw_count: Number of raw findings input
            triaged_count: Number of findings triaged (should equal raw_count)
            reportable_count: Number of reportable findings (VALID/BUG)
            by_disposition: Count by disposition
            policy_version: Triage policy version used
            finding_refs: List of (finding_id, disposition) tuples (capped at 50)

        Returns:
            Dictionary with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Build label
        filtered_count = raw_count - reportable_count
        label = f"🔍 Triage Gateway: {reportable_count}/{raw_count} reportable ({filtered_count} filtered)"

        # Prepare finding refs for data (limit to 50)
        finding_data = [
            {"id": fid, "disposition": disp}
            for fid, disp in finding_refs[:50]
        ]

        node = flow_service.add_node(
            self.agent_id,
            node_type="triage_gateway",
            label=label,
            data={
                "batch_id": batch_id,
                "raw_count": raw_count,
                "triaged_count": triaged_count,
                "reportable_count": reportable_count,
                "filtered_count": filtered_count,
                "by_disposition": by_disposition,
                "policy_version": policy_version,
                "finding_refs": finding_data,
                "total_findings": triaged_count
            },
            auto_parent=True
        )

        return {"node_id": node.id}
