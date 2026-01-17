"""Protocol policy and submission management routes."""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import json

from models.schemas import ProtocolPolicy, Finding, SubmissionResult
from services.protocol_policies import ProtocolPolicyLoader
from database import get_db


router = APIRouter(prefix="/api", tags=["protocol"])


@router.get("/protocol-policies")
async def get_policies(db: AsyncSession = Depends(get_db)):
    """Get all available protocol policies."""
    # Get all policies from database
    result = await db.execute(
        text("SELECT id, display_name, config FROM protocol_policies ORDER BY is_default DESC, display_name")
    )
    rows = result.fetchall()

    policies = []
    for row in rows:
        config = json.loads(row[2])
        policies.append(config)

    return {"policies": policies}


@router.get("/protocol-policies/{policy_id}")
async def get_policy(policy_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific protocol policy."""
    # Query the policy from database
    result = await db.execute(
        text("SELECT config FROM protocol_policies WHERE id = :policy_id"),
        {"policy_id": policy_id}
    )
    row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Protocol not found: {policy_id}")

    config = json.loads(row[0])
    return config


@router.patch("/projects/{project_id}")
async def update_project_protocol(
    project_id: str,
    update: dict,
    db: AsyncSession = Depends(get_db)
):
    """Update project's protocol policy."""
    if "protocol_id" not in update:
        raise HTTPException(status_code=400, detail="protocol_id required")

    protocol_id = update["protocol_id"]

    # Verify protocol exists
    result = await db.execute(
        text("SELECT id FROM protocol_policies WHERE id = :protocol_id"),
        {"protocol_id": protocol_id}
    )
    row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail=f"Protocol not found: {protocol_id}")

    # Update project
    await db.execute(
        text("UPDATE projects SET protocol_id = :protocol_id WHERE id = :project_id"),
        {"protocol_id": protocol_id, "project_id": project_id}
    )
    await db.commit()

    return {"success": True, "protocol_id": protocol_id}


@router.post("/findings/{finding_id}/quests")
async def trigger_evidence_quest(
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Manually trigger evidence quest for a finding."""
    # Get finding
    result = await db.execute(
        text("SELECT * FROM findings WHERE id = :finding_id"),
        {"finding_id": finding_id}
    )
    row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    # TODO: Get evidence and trigger quest
    # For now, return placeholder
    return {
        "message": "Quest triggering not yet fully implemented",
        "finding_id": finding_id,
        "status": "pending"
    }


@router.get("/findings/{finding_id}/quests")
async def get_finding_quests(
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get all quests for a finding."""
    result = await db.execute(
        text("""
            SELECT id, quest_type, status, started_at, completed_at, success
            FROM evidence_quests
            WHERE finding_id = :finding_id
            ORDER BY created_at DESC
        """),
        {"finding_id": finding_id}
    )

    rows = result.fetchall()

    quests = []
    for row in rows:
        quests.append({
            "id": row[0],
            "quest_type": row[1],
            "status": row[2],
            "started_at": row[3],
            "completed_at": row[4],
            "success": bool(row[5]) if row[5] is not None else None
        })

    return {"quests": quests}


@router.get("/quests/{quest_id}")
async def get_quest_details(
    quest_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get detailed quest information."""
    result = await db.execute(
        text("""
            SELECT id, finding_id, category, quest_type, status,
                   missing_items, evidence_found, new_checklist_items,
                   started_at, completed_at, success, error_message
            FROM evidence_quests
            WHERE id = :quest_id
        """),
        {"quest_id": quest_id}
    )

    row = result.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Quest not found")

    return {
        "id": row[0],
        "finding_id": row[1],
        "category": row[2],
        "quest_type": row[3],
        "status": row[4],
        "missing_items": json.loads(row[5]) if row[5] else [],
        "evidence_found": json.loads(row[6]) if row[6] else {},
        "new_checklist_items": json.loads(row[7]) if row[7] else {},
        "started_at": row[8],
        "completed_at": row[9],
        "success": bool(row[10]) if row[10] is not None else None,
        "error_message": row[11]
    }
