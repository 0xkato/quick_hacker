"""Report generation service for findings."""

import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class ReportFormat(str, Enum):
    """Supported report formats."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"


class ReportGenerator:
    """Generate comprehensive security reports from findings."""

    def __init__(self):
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate(
        self,
        findings: List[Dict[str, Any]],
        format: ReportFormat = ReportFormat.MARKDOWN,
        title: str = "Security Findings Report",
        include_metadata: bool = True,
        group_by: Optional[str] = None  # "severity", "disposition", "category"
    ) -> str:
        """Generate a comprehensive report from findings."""
        if format == ReportFormat.MARKDOWN:
            return self._generate_markdown(findings, title, include_metadata, group_by)
        elif format == ReportFormat.HTML:
            return self._generate_html(findings, title, include_metadata, group_by)
        elif format == ReportFormat.JSON:
            return self._generate_json(findings, include_metadata)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_markdown(
        self,
        findings: List[Dict[str, Any]],
        title: str,
        include_metadata: bool,
        group_by: Optional[str]
    ) -> str:
        """Generate Markdown report."""
        lines = []

        # Header
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**Generated:** {self.timestamp}")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append("")

        # Summary statistics
        lines.append("## Executive Summary")
        lines.append("")
        stats = self._calculate_statistics(findings)

        lines.append("### Findings by Severity")
        for severity, count in stats['by_severity'].items():
            lines.append(f"- **{severity}**: {count}")
        lines.append("")

        if stats['by_disposition']:
            lines.append("### Findings by Disposition")
            for disposition, count in stats['by_disposition'].items():
                lines.append(f"- **{disposition}**: {count}")
            lines.append("")

        if stats['by_submission']:
            lines.append("### Submission Decisions")
            for decision, count in stats['by_submission'].items():
                lines.append(f"- **{decision}**: {count}")
            lines.append("")

        lines.append("---")
        lines.append("")

        # Group findings if requested
        if group_by:
            grouped = self._group_findings(findings, group_by)
            for group_name, group_findings in grouped.items():
                lines.append(f"## {group_by.title()}: {group_name}")
                lines.append("")
                lines.append(f"*{len(group_findings)} finding(s)*")
                lines.append("")
                for finding in group_findings:
                    lines.extend(self._format_finding_markdown(finding, include_metadata))
                lines.append("---")
                lines.append("")
        else:
            # List all findings sequentially
            lines.append("## Detailed Findings")
            lines.append("")
            for i, finding in enumerate(findings, 1):
                lines.append(f"### Finding #{i}")
                lines.append("")
                lines.extend(self._format_finding_markdown(finding, include_metadata))
                lines.append("---")
                lines.append("")

        return "\n".join(lines)

    def _format_finding_markdown(
        self,
        finding: Dict[str, Any],
        include_metadata: bool
    ) -> List[str]:
        """Format a single finding as Markdown."""
        lines = []

        # Title and basic info
        lines.append(f"#### {finding.get('title', 'Untitled Finding')}")
        lines.append("")

        # Metadata badges
        badges = []
        if finding.get('severity'):
            badges.append(f"`{finding['severity']}`")
        if finding.get('disposition'):
            badges.append(f"`{finding['disposition']}`")
        if finding.get('vulnerability_type'):
            badges.append(f"`{finding['vulnerability_type']}`")
        if finding.get('cwe_id'):
            badges.append(f"`CWE-{finding['cwe_id']}`")

        if badges:
            lines.append(" ".join(badges))
            lines.append("")

        # Location
        if finding.get('file_path'):
            location = f"{finding['file_path']}"
            if finding.get('line_start'):
                location += f":{finding['line_start']}"
                if finding.get('line_end') and finding['line_end'] != finding['line_start']:
                    location += f"-{finding['line_end']}"
            lines.append(f"**Location:** `{location}`")
            lines.append("")

        # Description
        if finding.get('description'):
            lines.append("**Description:**")
            lines.append("")
            lines.append(finding['description'])
            lines.append("")

        # Code snippet
        if finding.get('code_snippet') or finding.get('vulnerable_code'):
            lines.append("**Vulnerable Code:**")
            lines.append("")
            lines.append("```")
            lines.append(finding.get('vulnerable_code') or finding.get('code_snippet', ''))
            lines.append("```")
            lines.append("")

        # Attack scenario
        if finding.get('attack_scenario'):
            lines.append("**Attack Scenario:**")
            lines.append("")
            lines.append(finding['attack_scenario'])
            lines.append("")

        # Proof of concept
        if finding.get('proof_of_concept'):
            lines.append("**Proof of Concept:**")
            lines.append("")
            lines.append("```")
            lines.append(finding['proof_of_concept'])
            lines.append("```")
            lines.append("")

        # Recommended fix
        if finding.get('recommended_fix'):
            lines.append("**Recommended Fix:**")
            lines.append("")
            lines.append(finding['recommended_fix'])
            lines.append("")

        # Submission result (protocol layer)
        if finding.get('submission_result'):
            sr = finding['submission_result']
            lines.append("**Submission Evaluation:**")
            lines.append("")
            lines.append(f"- **Decision:** {sr.get('decision', 'N/A')}")
            lines.append(f"- **Protocol:** {sr.get('protocol_id', 'N/A')}")

            if sr.get('reasons'):
                lines.append("- **Reasoning:**")
                for reason in sr['reasons']:
                    lines.append(f"  - {reason}")

            if sr.get('missing_evidence'):
                lines.append("- **Missing Evidence:**")
                for evidence in sr['missing_evidence']:
                    lines.append(f"  - {evidence}")

            lines.append("")

        # Additional metadata
        if include_metadata:
            lines.append("<details>")
            lines.append("<summary><b>Additional Metadata</b></summary>")
            lines.append("")

            if finding.get('confidence'):
                lines.append(f"- **Confidence:** {finding['confidence']:.2f}")
            if finding.get('classification_confidence'):
                lines.append(f"- **Classification Confidence:** {finding['classification_confidence']}/100")
            if finding.get('exploit_confidence'):
                lines.append(f"- **Exploit Confidence:** {finding['exploit_confidence']}/100")
            if finding.get('category'):
                lines.append(f"- **Category:** {finding['category']}")
            if finding.get('created_at'):
                lines.append(f"- **Discovered:** {finding['created_at']}")
            if finding.get('id'):
                lines.append(f"- **Finding ID:** `{finding['id']}`")

            lines.append("")
            lines.append("</details>")
            lines.append("")

        return lines

    def _generate_html(
        self,
        findings: List[Dict[str, Any]],
        title: str,
        include_metadata: bool,
        group_by: Optional[str]
    ) -> str:
        """Generate HTML report."""
        # Convert markdown to HTML with basic styling
        markdown_report = self._generate_markdown(findings, title, include_metadata, group_by)

        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            f"<title>{title}</title>",
            "<style>",
            "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1200px; margin: 40px auto; padding: 0 20px; line-height: 1.6; }",
            "h1 { border-bottom: 3px solid #333; padding-bottom: 10px; }",
            "h2 { border-bottom: 2px solid #666; padding-bottom: 8px; margin-top: 40px; }",
            "h3 { margin-top: 30px; }",
            "h4 { color: #d73a49; margin-top: 20px; }",
            "code { background: #f6f8fa; padding: 2px 6px; border-radius: 3px; font-family: 'Monaco', monospace; }",
            "pre { background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; }",
            "pre code { background: none; padding: 0; }",
            ".badge { display: inline-block; padding: 3px 8px; margin: 2px; border-radius: 3px; font-size: 12px; font-weight: bold; }",
            ".severity-critical { background: #d73a49; color: white; }",
            ".severity-high { background: #ff6b6b; color: white; }",
            ".severity-medium { background: #ff922b; color: white; }",
            ".severity-low { background: #ffd43b; color: #333; }",
            "hr { margin: 40px 0; border: none; border-top: 1px solid #e1e4e8; }",
            "details { margin: 20px 0; padding: 10px; background: #f6f8fa; border-radius: 6px; }",
            "summary { cursor: pointer; font-weight: bold; }",
            "</style>",
            "</head>",
            "<body>",
        ]

        # Simple markdown-like conversion
        for line in markdown_report.split('\n'):
            if line.startswith('# '):
                html_parts.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith('## '):
                html_parts.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith('### '):
                html_parts.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith('#### '):
                html_parts.append(f"<h4>{line[5:]}</h4>")
            elif line.startswith('- '):
                html_parts.append(f"<li>{line[2:]}</li>")
            elif line.startswith('**') and line.endswith('**'):
                html_parts.append(f"<strong>{line[2:-2]}</strong>")
            elif line == '---':
                html_parts.append("<hr>")
            elif line.strip() == '':
                html_parts.append("<br>")
            else:
                html_parts.append(f"<p>{line}</p>")

        html_parts.extend([
            "</body>",
            "</html>"
        ])

        return "\n".join(html_parts)

    def _generate_json(
        self,
        findings: List[Dict[str, Any]],
        include_metadata: bool
    ) -> str:
        """Generate JSON report."""
        report = {
            "generated_at": self.timestamp,
            "total_findings": len(findings),
            "statistics": self._calculate_statistics(findings),
            "findings": findings
        }

        return json.dumps(report, indent=2, default=str)

    def _calculate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate summary statistics."""
        stats = {
            "by_severity": {},
            "by_disposition": {},
            "by_submission": {},
            "by_category": {}
        }

        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            # Count by disposition
            if finding.get('disposition'):
                disp = finding['disposition']
                stats['by_disposition'][disp] = stats['by_disposition'].get(disp, 0) + 1

            # Count by submission decision
            if finding.get('submission_result'):
                decision = finding['submission_result'].get('decision', 'unknown')
                stats['by_submission'][decision] = stats['by_submission'].get(decision, 0) + 1

            # Count by category
            if finding.get('category'):
                cat = finding['category']
                stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1

        return stats

    def _group_findings(
        self,
        findings: List[Dict[str, Any]],
        group_by: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by specified field."""
        grouped = {}

        for finding in findings:
            if group_by == "submission" and finding.get('submission_result'):
                key = finding['submission_result'].get('decision', 'unknown')
            else:
                key = finding.get(group_by, 'unknown')

            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)

        # Sort groups by severity priority if grouping by severity
        if group_by == "severity":
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
            return dict(sorted(grouped.items(), key=lambda x: severity_order.get(x[0].lower(), 6)))

        return dict(sorted(grouped.items()))
