"""Simple report generation - just get all findings in one place."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from datetime import datetime

from database.connection import get_db

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/agents/{agent_id}/report")
async def get_agent_report(
    agent_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get all findings for an agent in one comprehensive Markdown report.
    No filters, no options - just everything in one place.
    """
    # Get all findings
    query = text("""
        SELECT * FROM findings
        WHERE agent_id = :agent_id
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            created_at DESC
    """)

    result = await db.execute(query, {"agent_id": agent_id})
    rows = result.fetchall()

    if not rows:
        raise HTTPException(status_code=404, detail="No findings found for this project")

    # Generate report
    report_lines = []

    # Header
    report_lines.append(f"# Security Findings Report")
    report_lines.append(f"")
    report_lines.append(f"**Project:** {agent_id}")
    report_lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report_lines.append(f"**Total Findings:** {len(rows)}")
    report_lines.append(f"")

    # Quick stats
    severities = {}
    for row in rows:
        sev = row.severity
        severities[sev] = severities.get(sev, 0) + 1

    report_lines.append("## Summary")
    report_lines.append("")
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity in severities:
            report_lines.append(f"- **{severity.upper()}**: {severities[severity]}")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")

    # All findings
    report_lines.append("## Findings")
    report_lines.append("")

    for i, row in enumerate(rows, 1):
        finding = dict(row._mapping)

        # Title
        report_lines.append(f"### {i}. {finding.get('title', 'Untitled')}")
        report_lines.append("")

        # Basic info
        badges = []
        if finding.get('severity'):
            badges.append(f"`{finding['severity'].upper()}`")
        if finding.get('vulnerability_type'):
            badges.append(f"`{finding['vulnerability_type']}`")
        if finding.get('cwe_id'):
            badges.append(f"`CWE-{finding['cwe_id']}`")

        if badges:
            report_lines.append(" ".join(badges))
            report_lines.append("")

        # Location
        if finding.get('file_path'):
            location = finding['file_path']
            if finding.get('line_start'):
                location += f":{finding['line_start']}"
                if finding.get('line_end') and finding['line_end'] != finding['line_start']:
                    location += f"-{finding['line_end']}"
            report_lines.append(f"**Location:** `{location}`")
            report_lines.append("")

        # Description
        if finding.get('description'):
            report_lines.append("**Description:**")
            report_lines.append("")
            report_lines.append(finding['description'])
            report_lines.append("")

        # Code
        if finding.get('vulnerable_code') or finding.get('code_snippet'):
            report_lines.append("**Vulnerable Code:**")
            report_lines.append("")
            report_lines.append("```")
            report_lines.append(finding.get('vulnerable_code') or finding.get('code_snippet', ''))
            report_lines.append("```")
            report_lines.append("")

        # Attack scenario
        if finding.get('attack_scenario'):
            report_lines.append("**Attack Scenario:**")
            report_lines.append("")
            report_lines.append(finding['attack_scenario'])
            report_lines.append("")

        # PoC
        if finding.get('proof_of_concept'):
            report_lines.append("**Proof of Concept:**")
            report_lines.append("")
            report_lines.append("```")
            report_lines.append(finding['proof_of_concept'])
            report_lines.append("```")
            report_lines.append("")

        # Fix
        if finding.get('recommended_fix'):
            report_lines.append("**Recommended Fix:**")
            report_lines.append("")
            report_lines.append(finding['recommended_fix'])
            report_lines.append("")

        report_lines.append("---")
        report_lines.append("")

    report_content = "\n".join(report_lines)

    # Return as downloadable markdown file
    return Response(
        content=report_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="security-report-{agent_id}.md"'
        }
    )
