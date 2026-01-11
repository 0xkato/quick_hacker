"""Report generator for security scan findings.

This module generates reports from scan findings in multiple formats:
- Markdown: Human-readable report with summary tables and grouped findings
- JSON: Machine-readable format with severity and tool breakdowns
- SARIF: Static Analysis Results Interchange Format (v2.1.0) for integration with tools
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from services.security_scanners.base import (
    Severity,
    ScannerTool,
    ScanFinding,
)


# SARIF schema URL
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def generate_report(findings: list[ScanFinding], output_format: str) -> str:
    """Generate a report from scan findings.

    Args:
        findings: List of scan findings to include in the report
        output_format: Output format ('markdown', 'json', or 'sarif')

    Returns:
        Report as a string in the requested format

    Raises:
        ValueError: If output_format is not recognized
    """
    format_lower = output_format.lower()

    if format_lower == "markdown":
        return _generate_markdown(findings)
    elif format_lower == "json":
        return _generate_json(findings)
    elif format_lower == "sarif":
        return _generate_sarif(findings)
    else:
        raise ValueError(f"Unknown output format: {output_format}")


def _generate_markdown(findings: list[ScanFinding]) -> str:
    """Generate a Markdown report.

    Args:
        findings: List of scan findings

    Returns:
        Markdown-formatted report string
    """
    lines = []
    lines.append("# Security Scan Report")
    lines.append("")

    # Summary section
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Total Findings:** {len(findings)}")
    lines.append("")

    # Severity breakdown table
    severity_counts = _count_by_severity(findings)
    lines.append("### By Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for severity in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {severity.capitalize()} | {severity_counts[severity]} |")
    lines.append("")

    # Tool breakdown table
    tool_counts = _count_by_tool(findings)
    lines.append("### By Tool")
    lines.append("")
    lines.append("| Tool | Count |")
    lines.append("|------|-------|")
    for tool in ["secrets", "dependencies", "grep"]:
        lines.append(f"| {tool.capitalize()} | {tool_counts[tool]} |")
    lines.append("")

    # Findings grouped by file
    if findings:
        lines.append("## Findings by File")
        lines.append("")

        grouped = _group_by_file(findings)
        for file_path in sorted(grouped.keys()):
            file_findings = grouped[file_path]
            lines.append(f"### {file_path}")
            lines.append("")

            for finding in file_findings:
                # Finding header with severity badge
                severity_badge = f"[{finding.severity.value.upper()}]"
                lines.append(f"#### {severity_badge} {finding.title}")
                lines.append("")

                # Location info
                if finding.line_end is not None:
                    lines.append(f"**Lines:** {finding.line_start}-{finding.line_end}")
                else:
                    lines.append(f"**Line:** {finding.line_start}")
                lines.append(f"**Tool:** {finding.tool.value}")
                lines.append(f"**Confidence:** {finding.confidence:.0%}")
                lines.append("")

                # Code snippet
                lines.append("```")
                lines.append(finding.snippet)
                lines.append("```")
                lines.append("")

                # Details if present
                if finding.details:
                    lines.append("**Details:**")
                    for key, value in finding.details.items():
                        lines.append(f"- {key}: {value}")
                    lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No findings detected.")
        lines.append("")

    return "\n".join(lines)


def _generate_json(findings: list[ScanFinding]) -> str:
    """Generate a JSON report.

    Args:
        findings: List of scan findings

    Returns:
        JSON-formatted report string
    """
    report: dict[str, Any] = {
        "total": len(findings),
        "by_severity": _count_by_severity(findings),
        "by_tool": _count_by_tool(findings),
        "findings": [finding.to_dict() for finding in findings],
    }

    return json.dumps(report, indent=2)


def _generate_sarif(findings: list[ScanFinding]) -> str:
    """Generate a SARIF 2.1.0 report.

    Args:
        findings: List of scan findings

    Returns:
        SARIF-formatted JSON string
    """
    # Build results list
    results = []
    for finding in findings:
        result: dict[str, Any] = {
            "ruleId": f"{finding.tool.value}/{finding.title.lower().replace(' ', '_')}",
            "message": {
                "text": finding.title,
            },
            "level": _severity_to_sarif_level(finding.severity),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        },
                        "region": {
                            "startLine": finding.line_start,
                        },
                    },
                },
            ],
        }

        # Add endLine if present
        if finding.line_end is not None:
            result["locations"][0]["physicalLocation"]["region"]["endLine"] = finding.line_end

        # Add snippet as context region
        if finding.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.snippet,
            }

        # Add properties for additional details
        if finding.details or finding.confidence < 1.0:
            result["properties"] = {}
            if finding.confidence < 1.0:
                result["properties"]["confidence"] = finding.confidence
            if finding.details:
                result["properties"]["details"] = finding.details

        results.append(result)

    # Build SARIF structure
    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "security-scanners",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/quick_hack/security-scanner",
                    },
                },
                "results": results,
            },
        ],
    }

    return json.dumps(sarif, indent=2)


def _count_by_severity(findings: list[ScanFinding]) -> dict[str, int]:
    """Count findings by severity level.

    Args:
        findings: List of scan findings

    Returns:
        Dictionary mapping severity names to counts
    """
    counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity_key = finding.severity.value
        counts[severity_key] = counts.get(severity_key, 0) + 1

    return counts


def _count_by_tool(findings: list[ScanFinding]) -> dict[str, int]:
    """Count findings by scanner tool.

    Args:
        findings: List of scan findings

    Returns:
        Dictionary mapping tool names to counts
    """
    counts: dict[str, int] = {
        "secrets": 0,
        "dependencies": 0,
        "grep": 0,
    }

    for finding in findings:
        tool_key = finding.tool.value
        counts[tool_key] = counts.get(tool_key, 0) + 1

    return counts


def _group_by_file(findings: list[ScanFinding]) -> dict[str, list[ScanFinding]]:
    """Group findings by file path.

    Args:
        findings: List of scan findings

    Returns:
        Dictionary mapping file paths to lists of findings
    """
    grouped: dict[str, list[ScanFinding]] = defaultdict(list)

    for finding in findings:
        grouped[finding.file_path].append(finding)

    return dict(grouped)


def _severity_to_sarif_level(severity: Severity) -> str:
    """Map severity to SARIF level.

    SARIF levels:
    - error: A serious problem
    - warning: A problem
    - note: An opportunity for improvement

    Args:
        severity: Severity enum value

    Returns:
        SARIF level string ('error', 'warning', or 'note')
    """
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    else:  # LOW, INFO
        return "note"
