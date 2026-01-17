"""Report generation API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select
from typing import Optional, List
import io

from database.connection import get_db
from database.models import Finding
from services.report_generator import ReportGenerator, ReportFormat

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/findings/export")
async def export_findings_report(
    agent_id: str = Query(..., description="Agent/project ID to generate report for"),
    format: ReportFormat = Query(ReportFormat.MARKDOWN, description="Report format (markdown, html, json)"),
    title: Optional[str] = Query(None, description="Custom report title"),
    include_metadata: bool = Query(True, description="Include detailed metadata"),
    group_by: Optional[str] = Query(None, description="Group by: severity, disposition, category, submission"),
    min_severity: Optional[str] = Query(None, description="Minimum severity to include"),
    disposition_filter: Optional[str] = Query(None, description="Filter by disposition"),
    submission_decision: Optional[str] = Query(None, description="Filter by submission decision"),
    db: AsyncSession = Depends(get_db)
):
    """
    Generate and export a comprehensive report of all findings.

    Supports multiple formats:
    - **markdown**: Markdown document (default)
    - **html**: Standalone HTML page
    - **json**: Structured JSON data

    Can filter and group findings by various criteria.
    """
    # Build query
    query_parts = ["SELECT * FROM findings WHERE agent_id = :agent_id"]
    params = {"agent_id": agent_id}

    # Apply filters
    if min_severity:
        severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        min_order = severity_order.get(min_severity.lower(), 999)
        severity_filter = [s for s, o in severity_order.items() if o >= min_order]
        query_parts.append(f"AND severity IN ({','.join([':sev_' + str(i) for i in range(len(severity_filter))])})")
        for i, sev in enumerate(severity_filter):
            params[f"sev_{i}"] = sev

    if disposition_filter:
        query_parts.append("AND disposition = :disposition")
        params["disposition"] = disposition_filter

    if submission_decision:
        query_parts.append("AND submission_result->>'decision' = :submission_decision")
        params["submission_decision"] = submission_decision

    query_parts.append("ORDER BY created_at DESC")

    query_text = " ".join(query_parts)

    # Execute query
    result = await db.execute(text(query_text), params)
    rows = result.fetchall()

    if not rows:
        raise HTTPException(status_code=404, detail="No findings found matching criteria")

    # Convert to dicts
    findings = []
    for row in rows:
        finding_dict = dict(row._mapping)

        # Parse JSON fields
        if finding_dict.get('submission_result') and isinstance(finding_dict['submission_result'], str):
            import json
            finding_dict['submission_result'] = json.loads(finding_dict['submission_result'])
        if finding_dict.get('proof_checklist') and isinstance(finding_dict['proof_checklist'], str):
            import json
            finding_dict['proof_checklist'] = json.loads(finding_dict['proof_checklist'])
        if finding_dict.get('metadata_') and isinstance(finding_dict['metadata_'], str):
            import json
            finding_dict['metadata'] = json.loads(finding_dict['metadata_'])

        findings.append(finding_dict)

    # Generate report
    generator = ReportGenerator()

    if not title:
        title = f"Security Findings Report - {agent_id}"

    report_content = generator.generate(
        findings=findings,
        format=format,
        title=title,
        include_metadata=include_metadata,
        group_by=group_by
    )

    # Determine content type and filename
    content_types = {
        ReportFormat.MARKDOWN: "text/markdown",
        ReportFormat.HTML: "text/html",
        ReportFormat.JSON: "application/json"
    }

    extensions = {
        ReportFormat.MARKDOWN: "md",
        ReportFormat.HTML: "html",
        ReportFormat.JSON: "json"
    }

    content_type = content_types.get(format, "text/plain")
    extension = extensions.get(format, "txt")
    filename = f"security-report-{agent_id}.{extension}"

    # Return as downloadable file
    return Response(
        content=report_content,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@router.get("/findings/preview")
async def preview_findings_report(
    agent_id: str = Query(..., description="Agent/project ID"),
    format: ReportFormat = Query(ReportFormat.MARKDOWN, description="Report format"),
    limit: int = Query(5, description="Number of findings to preview", ge=1, le=20),
    db: AsyncSession = Depends(get_db)
):
    """
    Preview a report with limited findings (useful for testing formatting).
    Returns the report content directly without download headers.
    """
    # Get limited findings
    query = text("""
        SELECT * FROM findings
        WHERE agent_id = :agent_id
        ORDER BY created_at DESC
        LIMIT :limit
    """)

    result = await db.execute(query, {"agent_id": agent_id, "limit": limit})
    rows = result.fetchall()

    if not rows:
        raise HTTPException(status_code=404, detail="No findings found")

    # Convert to dicts
    findings = []
    for row in rows:
        finding_dict = dict(row._mapping)
        if finding_dict.get('submission_result') and isinstance(finding_dict['submission_result'], str):
            import json
            finding_dict['submission_result'] = json.loads(finding_dict['submission_result'])
        findings.append(finding_dict)

    # Generate report
    generator = ReportGenerator()
    report_content = generator.generate(
        findings=findings,
        format=format,
        title=f"Security Findings Report Preview - {agent_id}",
        include_metadata=True,
        group_by=None
    )

    content_types = {
        ReportFormat.MARKDOWN: "text/markdown",
        ReportFormat.HTML: "text/html",
        ReportFormat.JSON: "application/json"
    }

    return Response(
        content=report_content,
        media_type=content_types.get(format, "text/plain")
    )


@router.get("/findings/stats")
async def get_findings_statistics(
    agent_id: str = Query(..., description="Agent/project ID"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get summary statistics for findings (useful for report generation UI).
    """
    # Get all findings for agent
    query = text("SELECT * FROM findings WHERE agent_id = :agent_id")
    result = await db.execute(query, {"agent_id": agent_id})
    rows = result.fetchall()

    if not rows:
        return {
            "total": 0,
            "by_severity": {},
            "by_disposition": {},
            "by_submission": {}
        }

    # Calculate stats
    findings = []
    for row in rows:
        finding_dict = dict(row._mapping)
        if finding_dict.get('submission_result') and isinstance(finding_dict['submission_result'], str):
            import json
            finding_dict['submission_result'] = json.loads(finding_dict['submission_result'])
        findings.append(finding_dict)

    generator = ReportGenerator()
    stats = generator._calculate_statistics(findings)
    stats['total'] = len(findings)

    return stats
