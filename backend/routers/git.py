"""Git operations API router."""

from fastapi import APIRouter, HTTPException

from models.schemas import RepoCloneRequest, RepoInfo, APIResponse
from services import git_service


router = APIRouter()


@router.post("/clone", response_model=RepoInfo)
async def clone_repository(request: RepoCloneRequest):
    """Clone a git repository."""
    try:
        repo = await git_service.clone_repo(request.url, request.branch)
        return repo
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clone: {str(e)}")


@router.get("/repos", response_model=list[RepoInfo])
async def list_repositories():
    """List all cloned repositories."""
    return await git_service.list_repos()


@router.get("/repos/{repo_id}", response_model=RepoInfo)
async def get_repository(repo_id: str):
    """Get repository by ID."""
    repo = await git_service.get_repo(repo_id)
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo


@router.delete("/repos/{repo_id}", response_model=APIResponse)
async def delete_repository(repo_id: str):
    """Delete a cloned repository."""
    success = await git_service.delete_repo(repo_id)
    if not success:
        raise HTTPException(status_code=404, detail="Repository not found")
    return APIResponse(success=True, message="Repository deleted")


@router.post("/repos/{repo_id}/refresh", response_model=RepoInfo)
async def refresh_repository(repo_id: str):
    """Pull latest changes for a repository."""
    try:
        repo = await git_service.refresh_repo(repo_id)
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        return repo
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
