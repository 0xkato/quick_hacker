"""Campaign report generation -- produces markdown/HTML/JSON reports.

Generates comprehensive reports from campaign issues, coverage data,
steering decisions, and execution metadata.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


async def generate_campaign_report(
    campaign_id: str,
    format: str = "md",
    campaign_data: dict | None = None,
    issues: list[dict] | None = None,
    coverage: dict | None = None,
    steering_decisions: list[dict] | None = None,
    targets: list[dict] | None = None,
    lanes: list[dict] | None = None,
) -> str:
    """Generate a full campaign report.

    Args:
        campaign_id: Campaign identifier
        format: Output format (md, json, html)
        campaign_data: Campaign metadata
        issues: List of validated issues
        coverage: Coverage summary
        steering_decisions: Steering decision history
        targets: Target list
        lanes: Lane spec list
    """
    if format == "json":
        return _generate_json_report(campaign_id, campaign_data, issues, coverage, steering_decisions, targets, lanes)
    elif format == "html":
        md = _generate_markdown_report(campaign_id, campaign_data, issues, coverage, steering_decisions, targets, lanes)
        return _md_to_html(md)
    else:
        return _generate_markdown_report(campaign_id, campaign_data, issues, coverage, steering_decisions, targets, lanes)


async def generate_issue_report(
    issue_id: str,
    format: str = "md",
    issue_data: dict | None = None,
) -> str:
    """Generate a single issue report."""
    if not issue_data:
        return f"# Issue Report\n\nIssue: {issue_id}\n\nNo data available."

    if format == "json":
        return json.dumps(issue_data, indent=2, default=str)

    lines = [
        f"# Issue: {issue_data.get('title', issue_id)}",
        "",
        f"**Severity:** {issue_data.get('severity', 'unknown').upper()}",
        f"**Disposition:** {issue_data.get('disposition', 'unknown')}",
        f"**Category:** {issue_data.get('category', 'unknown')}",
        f"**CWE:** {issue_data.get('cwe_id', 'N/A')}",
        "",
        "## Description",
        issue_data.get("description", "No description available."),
        "",
    ]

    if issue_data.get("root_cause"):
        lines.extend(["## Root Cause", issue_data["root_cause"], ""])

    if issue_data.get("recommended_fix"):
        lines.extend(["## Recommended Fix", issue_data["recommended_fix"], ""])

    proof = issue_data.get("proof", {})
    if proof:
        lines.append("## Proof Checklist")
        for key, value in proof.items():
            icon = "\u2705" if value else "\u274c"
            lines.append(f"- {icon} {key.replace('_', ' ')}")
        lines.append("")

    return "\n".join(lines)


def _generate_markdown_report(
    campaign_id, campaign_data, issues, coverage, steering_decisions, targets, lanes
) -> str:
    """Generate a comprehensive markdown campaign report."""
    campaign = campaign_data or {}
    issues = issues or []
    targets = targets or []
    lanes = lanes or []
    decisions = steering_decisions or []

    lines = [
        f"# Campaign Report: {campaign_id}",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Preset:** {campaign.get('preset', 'unknown')}",
        f"**Status:** {campaign.get('status', 'unknown')}",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Targets Discovered | {len(targets)} |",
        f"| Lanes Executed | {len(lanes)} |",
        f"| Issues Found | {len(issues)} |",
        f"| Steering Decisions | {len(decisions)} |",
        "",
    ]

    # Coverage section
    if coverage:
        lines.extend([
            "## API Surface Coverage",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Operations Hit | {coverage.get('operations_hit', 0)} |",
            f"| Parameters Exercised | {coverage.get('parameters_exercised', 0)} |",
            f"| Validity Ratio | {(coverage.get('validity_ratio', 0) * 100):.1f}% |",
            f"| Sequence Depth | {coverage.get('sequence_depth', 0)} |",
            "",
        ])

    # Issues section
    if issues:
        lines.extend(["## Validated Issues", ""])

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_issues = sorted(issues, key=lambda i: severity_order.get(
            i.get("severity", "info") if isinstance(i.get("severity"), str) else "info", 4
        ))

        for i, issue in enumerate(sorted_issues, 1):
            sev = issue.get("severity", "unknown")
            title = issue.get("title", "Untitled")
            disp = issue.get("disposition", "unknown")
            lines.extend([
                f"### {i}. [{sev.upper()}] {title}",
                "",
                f"**Disposition:** {disp}",
                f"**Category:** {issue.get('category', 'N/A')}",
                f"**CWE:** {issue.get('cwe_id', 'N/A')}",
                "",
                issue.get("description", "No description."),
                "",
            ])

            if issue.get("root_cause"):
                lines.extend([f"**Root Cause:** {issue['root_cause']}", ""])
            if issue.get("recommended_fix"):
                lines.extend([f"**Fix:** {issue['recommended_fix']}", ""])

            lines.append("---")
            lines.append("")
    else:
        lines.extend(["## Issues", "", "No validated issues found.", ""])

    # Steering section
    if decisions:
        lines.extend(["## Steering Decisions", ""])
        for d in decisions:
            dtype = d.get("decision_type", "unknown") if isinstance(d, dict) else "unknown"
            rec = d.get("recommendation", "") if isinstance(d, dict) else ""
            lines.append(f"- **{dtype}**: {rec}")
        lines.append("")

    # Targets section
    if targets:
        lines.extend([
            "## Targets",
            "",
            "| Entrypoint | Kind | Language | Stateful | Priority |",
            "|-----------|------|----------|----------|----------|",
        ])
        for t in targets:
            entry = t.get("entrypoint", "?") if isinstance(t, dict) else getattr(t, "entrypoint", "?")
            kind = t.get("kind", "?") if isinstance(t, dict) else getattr(t, "kind", "?")
            lang = t.get("language", "?") if isinstance(t, dict) else getattr(t, "language", "?")
            stateful = t.get("stateful", False) if isinstance(t, dict) else getattr(t, "stateful", False)
            priority = t.get("priority_score", 0) if isinstance(t, dict) else getattr(t, "priority_score", 0)
            lines.append(f"| {entry} | {kind} | {lang} | {'Yes' if stateful else 'No'} | {priority or 0:.2f} |")
        lines.append("")

    return "\n".join(lines)


def _generate_json_report(campaign_id, campaign_data, issues, coverage, steering_decisions, targets, lanes) -> str:
    """Generate a JSON campaign report."""
    report = {
        "campaign_id": campaign_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "campaign": campaign_data or {},
        "summary": {
            "targets_count": len(targets or []),
            "lanes_count": len(lanes or []),
            "issues_count": len(issues or []),
            "steering_decisions_count": len(steering_decisions or []),
        },
        "coverage": coverage or {},
        "issues": issues or [],
        "steering_decisions": steering_decisions or [],
        "targets": targets or [],
        "lanes": lanes or [],
    }
    return json.dumps(report, indent=2, default=str)


def _md_to_html(md: str) -> str:
    """Simple markdown to HTML conversion."""
    html = md
    # Headers
    import re
    html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
    # Bold
    html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    # Lists
    html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    # Paragraphs
    html = re.sub(r'\n\n', r'</p><p>', html)
    return f"<html><body><p>{html}</p></body></html>"
