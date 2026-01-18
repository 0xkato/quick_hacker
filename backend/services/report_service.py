"""
Report Service - Generates investigation reports.

Creates comprehensive reports on agent completion including:
- Executive summary
- Findings breakdown
- Investigation timeline
- Token usage statistics
- Flow visualization export
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, TYPE_CHECKING
import uuid

from models.observability import (
    InvestigationReport,
    FindingSummary,
    TimelineEvent,
)
from models.schemas import WSMessage, WSMessageType, Severity

if TYPE_CHECKING:
    from agents.react import ReActSecurityAgent


# Report output directory
REPORT_DIR = Path(os.environ.get("DATA_DIR", "data")) / "reports"


# Severity order for sorting
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ReportService:
    """Generates investigation reports for completed agents."""

    def __init__(self):
        self._ensure_report_dir()
        self._broadcast_callback = None

    def _ensure_report_dir(self):
        """Ensure the report directory exists."""
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def set_broadcast_callback(self, callback) -> None:
        """Set the callback for broadcasting messages via WebSocket."""
        self._broadcast_callback = callback

    def _broadcast(self, message: WSMessage) -> None:
        """Broadcast message to WebSocket clients."""
        if self._broadcast_callback:
            try:
                self._broadcast_callback(message)
            except Exception as e:
                print(f"[Report] Broadcast error: {e}")

    def generate_report(self, agent: "ReActSecurityAgent") -> InvestigationReport:
        """
        Generate a comprehensive investigation report for an agent.

        Returns the report object and saves it to disk.
        """
        from services.observability_service import observability_service
        from services.flow_service import flow_service

        report_id = str(uuid.uuid4())[:12]

        # Get observability stats
        obs_stats = observability_service.get_stats(agent.id)
        usage = observability_service.get_token_usage(agent.id)

        # Build findings summary
        findings_summary = []
        findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        findings_by_type = {}
        files_with_findings = set()

        for finding in agent.findings:
            findings_summary.append(FindingSummary(
                id=finding.id,
                severity=finding.severity.value,
                title=finding.title,
                file_path=finding.file_path,
                line_start=finding.line_start,
                vulnerability_type=finding.vulnerability_type,
                confidence=finding.confidence,
            ))
            findings_by_severity[finding.severity.value] = findings_by_severity.get(finding.severity.value, 0) + 1
            findings_by_type[finding.vulnerability_type] = findings_by_type.get(finding.vulnerability_type, 0) + 1
            files_with_findings.add(finding.file_path)

        # Sort findings by severity
        findings_summary.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), -f.confidence))

        # Build timeline
        timeline = self._build_timeline(agent, observability_service)

        # Calculate duration
        duration_seconds = None
        if agent.started_at and agent.completed_at:
            duration_seconds = int((agent.completed_at - agent.started_at).total_seconds())
        elif agent.started_at:
            duration_seconds = int((datetime.utcnow() - agent.started_at).total_seconds())

        # Handle different agent types (files_examined vs files_analyzed)
        files_examined = getattr(agent, 'files_examined', None)
        files_count = len(files_examined) if files_examined else getattr(agent, 'files_analyzed', 0)

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            agent,
            findings_by_severity,
            files_count,
            duration_seconds,
        )

        # Estimate cost (rough OpenAI GPT-4 pricing)
        estimated_cost = self._estimate_cost(usage.prompt_tokens, usage.completion_tokens)

        # Create report
        report = InvestigationReport(
            id=report_id,
            agent_id=agent.id,
            executive_summary=executive_summary,
            agent_name=agent.name,
            agent_type=agent.agent_type.value,
            repo_id=agent.repo_id,
            repo_name=agent.repo_path.split("/")[-1] if agent.repo_path else "Unknown",
            started_at=agent.started_at,
            completed_at=agent.completed_at,
            duration_seconds=duration_seconds,
            findings_summary=findings_summary,
            findings_by_severity=findings_by_severity,
            findings_by_type=findings_by_type,
            total_files=files_count,
            files_with_findings=list(files_with_findings),
            timeline=timeline,
            total_prompt_tokens=usage.prompt_tokens,
            total_completion_tokens=usage.completion_tokens,
            total_api_calls=obs_stats.get("response_count", 0),
            estimated_cost=estimated_cost,
        )

        # Save report files
        self._save_report_files(report, agent)

        # Broadcast report ready
        self._broadcast(WSMessage(
            type=WSMessageType.REPORT_READY,
            agent_id=agent.id,
            data={
                "report_id": report_id,
                "findings_count": len(findings_summary),
                "critical_count": findings_by_severity.get("critical", 0),
                "high_count": findings_by_severity.get("high", 0),
            },
        ))

        return report

    def _build_timeline(self, agent: "ReActSecurityAgent", observability_service) -> list[TimelineEvent]:
        """Build investigation timeline from agent events."""
        events = []

        # Started event
        if agent.started_at:
            events.append(TimelineEvent(
                timestamp=agent.started_at,
                event_type="started",
                description="Investigation started",
            ))

        # Tool calls from observability
        tool_details = observability_service.get_tool_details(agent.id)
        for detail in tool_details[:50]:  # Limit to first 50
            events.append(TimelineEvent(
                timestamp=datetime.fromisoformat(detail.timestamp.isoformat() if hasattr(detail.timestamp, 'isoformat') else detail.timestamp),
                event_type="tool_called",
                description=f"{detail.tool_name}: {detail.arguments_summary}",
                data={"tool_name": detail.tool_name, "success": detail.success},
            ))

        # Findings
        for finding in agent.findings:
            events.append(TimelineEvent(
                timestamp=finding.created_at,
                event_type="finding_reported",
                description=f"{finding.severity.value.upper()}: {finding.title}",
                data={"severity": finding.severity.value, "finding_id": finding.id},
            ))

        # Completed event
        if agent.completed_at:
            events.append(TimelineEvent(
                timestamp=agent.completed_at,
                event_type="completed",
                description=f"Investigation completed ({agent.status.value})",
            ))

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)

        return events

    def _generate_executive_summary(
        self,
        agent: "ReActSecurityAgent",
        findings_by_severity: dict,
        files_analyzed: int,
        duration_seconds: Optional[int],
    ) -> str:
        """Generate an executive summary of the investigation."""
        critical = findings_by_severity.get("critical", 0)
        high = findings_by_severity.get("high", 0)
        medium = findings_by_severity.get("medium", 0)
        low = findings_by_severity.get("low", 0)
        total = critical + high + medium + low

        duration_str = ""
        if duration_seconds:
            if duration_seconds < 60:
                duration_str = f" in {duration_seconds} seconds"
            else:
                duration_str = f" in {duration_seconds // 60} minutes"

        if total == 0:
            return f"Security audit completed{duration_str}. No vulnerabilities were identified in the {files_analyzed} files analyzed. The codebase appears to follow secure coding practices for the areas examined."

        severity_parts = []
        if critical > 0:
            severity_parts.append(f"{critical} critical")
        if high > 0:
            severity_parts.append(f"{high} high")
        if medium > 0:
            severity_parts.append(f"{medium} medium")
        if low > 0:
            severity_parts.append(f"{low} low")

        severity_str = ", ".join(severity_parts)

        urgency = ""
        if critical > 0:
            urgency = " Immediate remediation is recommended for critical findings."
        elif high > 0:
            urgency = " High-severity issues should be addressed promptly."

        return f"Security audit completed{duration_str}, analyzing {files_analyzed} files. Identified {total} security issues: {severity_str}.{urgency}"

    def _estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate API cost (rough GPT-4 pricing)."""
        # GPT-4 pricing: $0.03/1K prompt, $0.06/1K completion (approximate)
        prompt_cost = (prompt_tokens / 1000) * 0.03
        completion_cost = (completion_tokens / 1000) * 0.06
        return round(prompt_cost + completion_cost, 4)

    def _save_report_files(self, report: InvestigationReport, agent: "ReActSecurityAgent") -> None:
        """Save report to disk in various formats."""
        from services.flow_service import flow_service

        self._ensure_report_dir()
        base_path = REPORT_DIR / f"{agent.id}_{report.id}"

        # Save JSON report
        json_path = f"{base_path}_report.json"
        with open(json_path, 'w') as f:
            json.dump(report.model_dump(mode='json'), f, indent=2, default=str)
        report.markdown_path = json_path

        # Save markdown report
        md_path = f"{base_path}_report.md"
        markdown = self.export_markdown(report)
        with open(md_path, 'w') as f:
            f.write(markdown)
        report.markdown_path = md_path

        # Save flow JSON
        flow = flow_service.get_flow(agent.id)
        if flow:
            flow_json_path = f"{base_path}_flow.json"
            with open(flow_json_path, 'w') as f:
                json.dump(flow.to_dict(), f, indent=2)
            report.flow_json_path = flow_json_path

            # Generate simple SVG
            flow_svg_path = f"{base_path}_flow.svg"
            svg = self._generate_flow_svg(flow)
            with open(flow_svg_path, 'w') as f:
                f.write(svg)
            report.flow_svg_path = flow_svg_path

        print(f"[Report] Saved report files for agent {agent.id}")

    def export_markdown(self, report: InvestigationReport) -> str:
        """Export report as markdown."""
        lines = [
            f"# Security Audit Report: {report.repo_name}",
            "",
            f"**Agent:** {report.agent_name} ({report.agent_type})",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Executive Summary",
            "",
            report.executive_summary,
            "",
            "---",
            "",
            "## Findings Overview",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = report.findings_by_severity.get(severity, 0)
            if count > 0:
                badge = self._severity_badge(severity)
                lines.append(f"| {badge} | {count} |")

        lines.extend([
            "",
            "---",
            "",
            "## Detailed Findings",
            "",
        ])

        for finding in report.findings_summary:
            badge = self._severity_badge(finding.severity)
            lines.extend([
                f"### {badge} {finding.title}",
                "",
                f"- **File:** `{finding.file_path}:{finding.line_start}`",
                f"- **Type:** {finding.vulnerability_type}",
                f"- **Confidence:** {finding.confidence:.0%}",
                "",
            ])

        lines.extend([
            "---",
            "",
            "## Statistics",
            "",
            f"- **Duration:** {report.duration_seconds or 'N/A'} seconds",
            f"- **Files Analyzed:** {report.total_files}",
            f"- **API Calls:** {report.total_api_calls}",
            f"- **Tokens Used:** {report.total_prompt_tokens + report.total_completion_tokens:,}",
            f"- **Estimated Cost:** ${report.estimated_cost or 0:.4f}",
            "",
            "---",
            "",
            "*Report generated by quick_hack security auditor*",
        ])

        return "\n".join(lines)

    def _severity_badge(self, severity: str) -> str:
        """Get markdown badge for severity."""
        badges = {
            "critical": "![Critical](https://img.shields.io/badge/-Critical-red)",
            "high": "![High](https://img.shields.io/badge/-High-orange)",
            "medium": "![Medium](https://img.shields.io/badge/-Medium-yellow)",
            "low": "![Low](https://img.shields.io/badge/-Low-blue)",
            "info": "![Info](https://img.shields.io/badge/-Info-gray)",
        }
        return badges.get(severity, severity.upper())

    def _generate_flow_svg(self, flow) -> str:
        """Generate a simple SVG diagram of the investigation flow."""
        nodes = flow.nodes
        edges = flow.edges

        if not nodes:
            return '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100"><text x="10" y="50">No flow data</text></svg>'

        # Simple vertical layout
        node_height = 40
        node_width = 200
        spacing = 60
        padding = 20

        height = len(nodes) * (node_height + spacing) + padding * 2
        width = node_width + padding * 2

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
            '<style>',
            '  .node { fill: #2d2d2d; stroke: #569cd6; stroke-width: 2; rx: 5; }',
            '  .node-text { fill: #e0e0e0; font-family: monospace; font-size: 12px; }',
            '  .edge { stroke: #808080; stroke-width: 1; fill: none; }',
            '  .finding { fill: #5a1d1d; stroke: #f48771; }',
            '  .completed { stroke: #4ec9b0; }',
            '</style>',
        ]

        # Draw edges first (behind nodes)
        node_positions = {}
        for i, node in enumerate(nodes):
            y = padding + i * (node_height + spacing)
            node_positions[node.id] = (padding + node_width // 2, y + node_height // 2)

        for edge in edges:
            if edge.source in node_positions and edge.target in node_positions:
                x1, y1 = node_positions[edge.source]
                x2, y2 = node_positions[edge.target]
                svg_parts.append(f'<line class="edge" x1="{x1}" y1="{y1 + node_height//2}" x2="{x2}" y2="{y2 - node_height//2}"/>')

        # Draw nodes
        for i, node in enumerate(nodes):
            x = padding
            y = padding + i * (node_height + spacing)

            extra_class = ""
            if node.type == "finding":
                extra_class = " finding"
            elif node.status == "completed":
                extra_class = " completed"

            svg_parts.append(f'<rect class="node{extra_class}" x="{x}" y="{y}" width="{node_width}" height="{node_height}"/>')

            # Truncate label if too long
            label = node.label[:25] + "..." if len(node.label) > 25 else node.label
            svg_parts.append(f'<text class="node-text" x="{x + 10}" y="{y + 25}">{label}</text>')

        svg_parts.append('</svg>')
        return "\n".join(svg_parts)

    def get_report(self, agent_id: str, report_id: Optional[str] = None) -> Optional[InvestigationReport]:
        """Get a saved report."""
        self._ensure_report_dir()

        # Find report file
        pattern = f"{agent_id}_*_report.json" if not report_id else f"{agent_id}_{report_id}_report.json"
        report_files = list(REPORT_DIR.glob(pattern))

        if not report_files:
            return None

        # Get most recent
        report_file = sorted(report_files, key=lambda f: f.stat().st_mtime, reverse=True)[0]

        try:
            with open(report_file, 'r') as f:
                data = json.load(f)
            return InvestigationReport(**data)
        except Exception as e:
            print(f"[Report] Error loading report: {e}")
            return None

    def list_reports(self, agent_id: Optional[str] = None) -> list[dict]:
        """List available reports."""
        self._ensure_report_dir()

        pattern = f"{agent_id}_*_report.json" if agent_id else "*_report.json"
        reports = []

        for report_file in REPORT_DIR.glob(pattern):
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                reports.append({
                    "id": data.get("id"),
                    "agent_id": data.get("agent_id"),
                    "repo_name": data.get("repo_name"),
                    "generated_at": data.get("generated_at"),
                    "findings_count": len(data.get("findings_summary", [])),
                    "file_path": str(report_file),
                })
            except Exception:
                pass

        reports.sort(key=lambda r: r.get("generated_at", ""), reverse=True)
        return reports


# Global instance
report_service = ReportService()
