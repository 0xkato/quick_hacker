"""Findings API endpoints with protocol-aware filtering."""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select, func
import json

from models.schemas import Finding
from database import get_db
from database.models import Finding as DBFinding

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
async def list_findings(
    project_id: str = Query(..., description="Project ID to filter findings"),
    disposition: Optional[str] = Query(None, description="Filter by disposition"),
    submission_decision: Optional[str] = Query(None, description="Filter by submission decision (submit/needs_more_info/do_not_submit)"),
    quest_completed: Optional[bool] = Query(None, description="Filter by evidence quest completion status"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of findings to return"),
    offset: int = Query(0, ge=0, description="Number of findings to skip"),
    db: AsyncSession = Depends(get_db)
):
    """
    List findings with optional filters.

    Supports filtering by:
    - project_id: Required - filter by project
    - disposition: Filter by triage disposition
    - submission_decision: Filter by submission result decision
    - quest_completed: Filter by evidence quest completion status
    """
    # Build query using SQLAlchemy text for raw SQL with parameters
    query_parts = ["SELECT * FROM findings WHERE repo_id = :project_id"]
    params = {"project_id": project_id}

    if disposition:
        query_parts.append("AND disposition = :disposition")
        params["disposition"] = disposition

    if submission_decision:
        # Use PostgreSQL JSON extraction operator ->>
        query_parts.append("AND submission_result->>'decision' = :submission_decision")
        params["submission_decision"] = submission_decision

    if quest_completed is not None:
        query_parts.append("AND evidence_quest_completed = :quest_completed")
        params["quest_completed"] = quest_completed

    query_parts.append("ORDER BY created_at DESC LIMIT :limit OFFSET :offset")
    params["limit"] = limit
    params["offset"] = offset

    query = " ".join(query_parts)

    # Execute query
    result = await db.execute(text(query), params)
    rows = result.fetchall()

    # Parse findings
    findings = []
    for row in rows:
        finding_dict = dict(zip([col for col in result.keys()], row))

        # Parse JSON fields
        if finding_dict.get("submission_result"):
            try:
                if isinstance(finding_dict["submission_result"], str):
                    finding_dict["submission_result"] = json.loads(finding_dict["submission_result"])
            except (json.JSONDecodeError, TypeError):
                finding_dict["submission_result"] = None

        if finding_dict.get("proof_checklist"):
            try:
                if isinstance(finding_dict["proof_checklist"], str):
                    finding_dict["proof_checklist"] = json.loads(finding_dict["proof_checklist"])
            except (json.JSONDecodeError, TypeError):
                finding_dict["proof_checklist"] = None

        if finding_dict.get("metadata"):
            try:
                if isinstance(finding_dict["metadata"], str):
                    finding_dict["metadata"] = json.loads(finding_dict["metadata"])
            except (json.JSONDecodeError, TypeError):
                finding_dict["metadata"] = {}

        if finding_dict.get("source_trace"):
            try:
                if isinstance(finding_dict["source_trace"], str):
                    finding_dict["source_trace"] = json.loads(finding_dict["source_trace"])
            except (json.JSONDecodeError, TypeError):
                finding_dict["source_trace"] = None

        if finding_dict.get("reasoning"):
            try:
                if isinstance(finding_dict["reasoning"], str):
                    finding_dict["reasoning"] = json.loads(finding_dict["reasoning"])
            except (json.JSONDecodeError, TypeError):
                finding_dict["reasoning"] = None

        findings.append(finding_dict)

    # Get total count with same filters
    count_parts = ["SELECT COUNT(*) FROM findings WHERE repo_id = :project_id"]
    count_params = {"project_id": project_id}

    if disposition:
        count_parts.append("AND disposition = :disposition")
        count_params["disposition"] = disposition

    if submission_decision:
        count_parts.append("AND submission_result->>'decision' = :submission_decision")
        count_params["submission_decision"] = submission_decision

    if quest_completed is not None:
        count_parts.append("AND evidence_quest_completed = :quest_completed")
        count_params["quest_completed"] = quest_completed

    count_query = " ".join(count_parts)
    count_result = await db.execute(text(count_query), count_params)
    total = count_result.scalar()

    return {
        "findings": findings,
        "total": total,
        "limit": limit,
        "offset": offset
    }
