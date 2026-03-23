"""Issue service -- CRUD operations for issues and regression tests.

Provides create, read, and list operations for confirmed issues
promoted from artifacts after proof gating.
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select

from database.campaign_models import (
    Artifact as DBArtifact,
    ExecutionBundle as DBExecBundle,
    Issue as DBIssue,
    RegressionTest as DBRegressionTest,
    RunLane as DBRunLane,
)
from database.connection import get_session
from models.campaign_enums import IssueDisposition, IssueSeverity
from models.campaign_schemas import IssueResponse, ProofChecklist


def _short_id() -> str:
    """Generate an 8-character hex ID from a UUID4."""
    return uuid.uuid4().hex[:8]


def _db_to_response(row: DBIssue) -> IssueResponse:
    """Map a SQLAlchemy Issue row to an IssueResponse."""
    return IssueResponse(
        id=row.id,
        artifact_id=row.artifact_id,
        severity=IssueSeverity(row.severity),
        title=row.title,
        description=row.description,
        category=row.category,
        cwe_id=row.cwe_id,
        disposition=(
            IssueDisposition(row.disposition)
            if row.disposition is not None
            else None
        ),
        proof=(
            ProofChecklist(**row.proof) if row.proof is not None else None
        ),
        root_cause=row.root_cause,
        recommended_fix=row.recommended_fix,
        regression_test_id=row.regression_test_id,
        created_at=row.created_at,
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class IssueService:
    """Thin service layer around the issues and regression_tests tables."""

    async def create_issue(
        self,
        artifact_id: str,
        severity: str,
        title: str,
        description: str | None = None,
        category: str | None = None,
        cwe_id: str | None = None,
        disposition: str | None = None,
        proof: dict | None = None,
        root_cause: str | None = None,
        recommended_fix: str | None = None,
    ) -> IssueResponse:
        """Persist a new issue and return its response representation."""
        issue_id = _short_id()

        db_issue = DBIssue(
            id=issue_id,
            artifact_id=artifact_id,
            severity=severity,
            title=title,
            description=description,
            category=category,
            cwe_id=cwe_id,
            disposition=disposition,
            proof=proof,
            root_cause=root_cause,
            recommended_fix=recommended_fix,
        )

        async with get_session() as session:
            session.add(db_issue)
            await session.flush()
            await session.refresh(db_issue)
            return _db_to_response(db_issue)

    async def get_issue(
        self, issue_id: str
    ) -> Optional[IssueResponse]:
        """Return a single issue by ID, or None if not found."""
        async with get_session() as session:
            row = await session.get(DBIssue, issue_id)
            if row is None:
                return None
            return _db_to_response(row)

    async def list_issues(
        self, campaign_id: str
    ) -> list[IssueResponse]:
        """List all issues for a campaign.

        Joins through the artifact -> run_lane -> execution_bundle chain
        to ensure issues are scoped to the correct campaign.
        """
        async with get_session() as session:
            stmt = (
                select(DBIssue)
                .join(DBArtifact, DBIssue.artifact_id == DBArtifact.id)
                .join(DBRunLane, DBArtifact.run_lane_id == DBRunLane.id)
                .join(DBExecBundle, DBRunLane.execution_bundle_id == DBExecBundle.id)
                .where(DBExecBundle.campaign_id == campaign_id)
                .order_by(DBIssue.created_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [_db_to_response(r) for r in rows]

    async def get_regression_test_for_issue(
        self, issue_id: str
    ) -> Optional[dict]:
        """Return the regression test for an issue, or None if not found."""
        async with get_session() as session:
            stmt = (
                select(DBRegressionTest)
                .where(DBRegressionTest.issue_id == issue_id)
                .limit(1)
            )
            result = await session.execute(stmt)
            row = result.scalars().first()
            if row is None:
                return None
            return {
                "id": row.id,
                "issue_id": row.issue_id,
                "file_ref": row.file_ref,
                "created_at": (
                    row.created_at.isoformat()
                    if row.created_at
                    else None
                ),
            }

    async def create_regression_test(
        self,
        issue_id: str,
        file_ref: str,
    ) -> dict:
        """Create a regression test record for an issue."""
        test_id = _short_id()

        db_test = DBRegressionTest(
            id=test_id,
            issue_id=issue_id,
            file_ref=file_ref,
        )

        async with get_session() as session:
            session.add(db_test)
            await session.flush()
            await session.refresh(db_test)
            return {
                "id": db_test.id,
                "issue_id": db_test.issue_id,
                "file_ref": db_test.file_ref,
                "created_at": (
                    db_test.created_at.isoformat()
                    if db_test.created_at
                    else None
                ),
            }


# Module-level singleton
issue_service = IssueService()
