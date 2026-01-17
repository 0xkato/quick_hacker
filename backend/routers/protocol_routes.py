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
