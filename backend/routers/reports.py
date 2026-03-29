"""Report generation API endpoints."""

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from typing import Optional

from database.connection import get_db
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
        severity_filter = [s for s, o in severity_order.items() if o <= min_order]
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

    # Execute query with timeout
    try:
        result = await asyncio.wait_for(db.execute(text(query_text), params), timeout=30.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Database query timed out")
    rows = result.fetchall()

    if not rows:
        raise HTTPException(status_code=404, detail="No findings found matching criteria")

    # Convert to dicts
    findings = []
    for row in rows:
        finding_dict = dict(row._mapping)

        # Parse JSON fields
        if finding_dict.get('submission_result') and isinstance(finding_dict['submission_result'], str):
            finding_dict['submission_result'] = json.loads(finding_dict['submission_result'])
        if finding_dict.get('proof_checklist') and isinstance(finding_dict['proof_checklist'], str):
            finding_dict['proof_checklist'] = json.loads(finding_dict['proof_checklist'])
        if finding_dict.get('metadata_') and isinstance(finding_dict['metadata_'], str):
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

    try:
        result = await asyncio.wait_for(db.execute(query, {"agent_id": agent_id, "limit": limit}), timeout=30.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Database query timed out")
    rows = result.fetchall()

    if not rows:
        raise HTTPException(status_code=404, detail="No findings found")

    # Convert to dicts
    findings = []
    for row in rows:
        finding_dict = dict(row._mapping)
        if finding_dict.get('submission_result') and isinstance(finding_dict['submission_result'], str):
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


@router.get("/campaigns/export")
async def export_campaign_report(
    campaign_id: str = Query(..., description="Campaign ID to generate report for"),
    format: str = Query("md", description="Report format (md, json, html)"),
):
    """Export a comprehensive campaign report."""
    from issues.reporting import generate_campaign_report
    from services.campaign_service import campaign_service
    from services.target_service import target_service
    from services.issue_service import issue_service
    from services.coverage_service import coverage_service
    from services.steering_service import steering_service
    from services.lane_service import lane_service

    campaign = await campaign_service.get_campaign(campaign_id)
    targets = await target_service.list_targets(campaign_id)
    issues_list = await issue_service.list_issues(campaign_id)
    coverage = await coverage_service.get_campaign_coverage_summary(campaign_id)
    steering = await steering_service.list_decisions(campaign_id)
    lanes = await lane_service.list_lane_specs(campaign_id=campaign_id)

    # Convert to dicts for the report generator
    campaign_dict = campaign.model_dump() if hasattr(campaign, 'model_dump') else campaign.__dict__ if campaign else {}
    target_dicts = [t.model_dump() if hasattr(t, 'model_dump') else t for t in targets] if targets else []
    issue_dicts = [i.model_dump() if hasattr(i, 'model_dump') else i for i in issues_list] if issues_list else []
    lane_dicts = [l.model_dump() if hasattr(l, 'model_dump') else l for l in lanes] if lanes else []

    report = await generate_campaign_report(
        campaign_id=campaign_id,
        format=format,
        campaign_data=campaign_dict,
        issues=issue_dicts,
        coverage=coverage,
        steering_decisions=steering,
        targets=target_dicts,
        lanes=lane_dicts,
    )

    content_type = "application/json" if format == "json" else "text/html" if format == "html" else "text/markdown"
    return Response(content=report, media_type=content_type)


@router.get("/issues/export")
async def export_issues_report(
    campaign_id: str = Query(..., description="Campaign ID to export issues for"),
    issue_id: Optional[str] = Query(None, description="Single issue ID to export"),
    format: str = Query("md", description="Report format (md, json, html)"),
):
    """Export an issues report -- single issue or all issues for a campaign."""
    from issues.reporting import generate_campaign_report, generate_issue_report
    from services.issue_service import issue_service

    if issue_id:
        # Single issue export
        issues_list = await issue_service.list_issues(campaign_id)
        issue_data = None
        for iss in (issues_list or []):
            iss_dict = iss.model_dump() if hasattr(iss, 'model_dump') else iss
            iss_id = iss_dict.get("issue_id") or iss_dict.get("id")
            if str(iss_id) == str(issue_id):
                issue_data = iss_dict
                break

        report = await generate_issue_report(
            issue_id=issue_id,
            format=format,
            issue_data=issue_data,
        )
    else:
        # All issues for campaign
        issues_list = await issue_service.list_issues(campaign_id)
        issue_dicts = [i.model_dump() if hasattr(i, 'model_dump') else i for i in issues_list] if issues_list else []

        report = await generate_campaign_report(
            campaign_id=campaign_id,
            format=format,
            issues=issue_dicts,
        )

    content_type = "application/json" if format == "json" else "text/html" if format == "html" else "text/markdown"
    return Response(content=report, media_type=content_type)


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
    try:
        result = await asyncio.wait_for(db.execute(query, {"agent_id": agent_id}), timeout=30.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Database query timed out")
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
            finding_dict['submission_result'] = json.loads(finding_dict['submission_result'])
        findings.append(finding_dict)

    generator = ReportGenerator()
    stats = generator._calculate_statistics(findings)
    stats['total'] = len(findings)

    return stats
