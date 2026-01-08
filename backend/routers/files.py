"""File operations API router."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from models.schemas import FileNode, FileContent
from services import git_service, file_service
from services.project_service import project_service


router = APIRouter()


async def get_repo_path(id: str) -> str:
    """Get repository path from project ID or repo ID."""
    # First try as project ID
    project_path = project_service.get_project_repo_path(id)
    if project_path:
        return project_path

    # Fall back to repo ID for backwards compatibility
    repo = await git_service.get_repo(id)
    if repo:
        return repo.path

    raise HTTPException(status_code=404, detail="Project or repository not found")


@router.get("/{repo_id}/tree", response_model=FileNode)
async def get_file_tree(repo_id: str, max_depth: int = Query(10, le=20)):
    """Get file tree for a repository."""
    repo_path = await get_repo_path(repo_id)

    try:
        tree = await file_service.get_file_tree(repo_path, max_depth)
        return tree
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get file tree: {str(e)}")


@router.get("/{repo_id}/content")
async def get_file_content(repo_id: str, path: str = Query(..., description="File path relative to repo root")):
    """Get content of a specific file."""
    repo_path = await get_repo_path(repo_id)

    try:
        content = await file_service.read_file(repo_path, path)
        return content
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{repo_id}/files")
async def list_files_by_extension(
    repo_id: str,
    extensions: str = Query(..., description="Comma-separated file extensions (e.g., 'py,js,ts')"),
    max_files: int = Query(500, le=1000),
):
    """List files with specific extensions."""
    repo_path = await get_repo_path(repo_id)
    ext_list = [e.strip() for e in extensions.split(",")]

    try:
        files_list = await file_service.get_files_by_extension(repo_path, ext_list, max_files)
        return {"files": files_list, "count": len(files_list)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")


@router.get("/{repo_id}/search")
async def search_in_files(
    repo_id: str,
    pattern: str = Query(..., description="Search pattern (regex supported)"),
    max_results: int = Query(100, le=500),
):
    """Search for pattern in repository files."""
    repo_path = await get_repo_path(repo_id)

    try:
        results = await file_service.search_files(repo_path, pattern, max_results)
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")
