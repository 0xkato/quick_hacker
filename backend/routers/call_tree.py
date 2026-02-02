"""Call tree router - API endpoints for static call-tree visualization."""

from fastapi import APIRouter, HTTPException, Query

from cass.tools.call_tree import CallTreeBuilder
from services import git_service
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


@router.get("/calltree/{repo_id}/routes")
async def list_fastapi_routes(repo_id: str):
    """List FastAPI HTTP routes in the target repository."""
    repo_path = await get_repo_path(repo_id)
    builder = CallTreeBuilder(repo_path)
    return builder.list_fastapi_routes()


@router.get("/calltree/{repo_id}/tree")
async def get_call_tree(
    repo_id: str,
    route_id: str = Query(..., description="Route ID from /calltree/{repo_id}/routes"),
    max_depth: int = Query(4, ge=1, le=20),
    max_nodes: int = Query(250, ge=10, le=2000),
    include_external: bool = Query(True),
):
    """Build a static call tree for a selected FastAPI route."""
    repo_path = await get_repo_path(repo_id)
    builder = CallTreeBuilder(repo_path)
    route = next((r for r in builder.list_fastapi_routes() if r.get("id") == route_id), None)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")

    result = builder.build_call_tree(
        route,
        max_depth=max_depth,
        max_nodes=max_nodes,
        include_external=include_external,
    )

    # Post-build validation: truncate if node count exceeds max_nodes
    nodes = result.get("nodes", [])
    if len(nodes) > max_nodes:
        result["nodes"] = nodes[:max_nodes]
        result["warning"] = f"Result truncated: {len(nodes)} nodes exceeded limit of {max_nodes}"

    return result
