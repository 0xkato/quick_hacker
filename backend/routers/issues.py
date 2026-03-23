"""Issue endpoints -- get issue details and revalidate."""

from fastapi import APIRouter, HTTPException, Depends
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import IssueResponse
from services.issue_service import issue_service

router = APIRouter()


@router.get("/{issue_id}", response_model=IssueResponse)
async def get_issue(
    issue_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get a single issue by ID."""
    issue = await issue_service.get_issue(issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    return issue


@router.post("/{issue_id}/revalidate")
async def revalidate_issue(
    issue_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Enqueue issue revalidation (stub for v1)."""
    issue = await issue_service.get_issue(issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    return {"status": "revalidation_queued"}


@router.get("/{issue_id}/regression-test")
async def get_issue_regression_test(
    issue_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get the regression test for an issue."""
    issue = await issue_service.get_issue(issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    test = await issue_service.get_regression_test_for_issue(issue_id)
    if not test:
        return {"regression_test": None}
    return test
