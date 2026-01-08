"""Project management API endpoints."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from services.project_service import project_service, Project


router = APIRouter(prefix="/projects", tags=["projects"])


class CreateProjectRequest(BaseModel):
    name: str
    description: str = ""


class UpdateProjectRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class CloneIntoProjectRequest(BaseModel):
    url: str
    branch: Optional[str] = None
    force: bool = False  # Force clone even if in another project


class ProjectStatus(BaseModel):
    in_project: bool
    current_project: Optional[Project] = None


@router.get("", response_model=list[Project])
async def list_projects():
    """List all projects."""
    return await project_service.list_projects()


@router.post("", response_model=Project)
async def create_project(request: CreateProjectRequest):
    """Create a new empty project."""
    return await project_service.create_project(
        name=request.name,
        description=request.description
    )


@router.get("/status", response_model=ProjectStatus)
async def get_project_status():
    """Get current project status."""
    current = await project_service.get_current_project()
    return ProjectStatus(
        in_project=current is not None,
        current_project=current
    )


@router.get("/{project_id}", response_model=Project)
async def get_project(project_id: str):
    """Get a specific project."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.put("/{project_id}", response_model=Project)
async def update_project(project_id: str, request: UpdateProjectRequest):
    """Update project metadata."""
    project = await project_service.update_project(
        project_id=project_id,
        name=request.name,
        description=request.description
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}")
async def delete_project(project_id: str):
    """Delete a project."""
    success = await project_service.delete_project(project_id)
    if not success:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"status": "deleted", "id": project_id}


@router.post("/{project_id}/enter", response_model=Project)
async def enter_project(project_id: str):
    """Enter/select a project as the current workspace."""
    project = await project_service.enter_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.post("/exit")
async def exit_project():
    """Exit the current project."""
    success = await project_service.exit_project()
    return {"status": "exited" if success else "not_in_project"}


@router.post("/{project_id}/clone", response_model=Project)
async def clone_into_project(project_id: str, request: CloneIntoProjectRequest):
    """Clone a repository into a project."""
    # Check if already in a project
    current = await project_service.get_current_project()
    if current and current.id != project_id and not request.force:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "already_in_project",
                "message": f"Currently in project '{current.name}'. Exit first or use force=true.",
                "current_project": current.model_dump(mode='json')
            }
        )

    try:
        project = await project_service.clone_into_project(
            project_id=project_id,
            url=request.url,
            branch=request.branch
        )
        # Auto-enter the project after cloning
        await project_service.enter_project(project_id)
        return project
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{project_id}/refresh", response_model=Project)
async def refresh_project(project_id: str):
    """Pull latest changes for a project's repository."""
    try:
        project = await project_service.refresh_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found or not cloned")
        return project
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Quick clone endpoint - creates project and clones in one step
class QuickCloneRequest(BaseModel):
    url: str
    branch: Optional[str] = None
    project_name: Optional[str] = None
    force: bool = False


@router.post("/quick-clone", response_model=Project)
async def quick_clone(request: QuickCloneRequest):
    """Create a project and clone a repository in one step."""
    # Check if already in a project
    current = await project_service.get_current_project()
    if current and not request.force:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "already_in_project",
                "message": f"Currently in project '{current.name}'. Exit first or use force=true.",
                "current_project": current.model_dump(mode='json')
            }
        )

    # Extract repo name for project name if not provided
    repo_name = request.url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    project_name = request.project_name or repo_name

    try:
        # Create project
        project = await project_service.create_project(name=project_name)

        # Clone into it
        project = await project_service.clone_into_project(
            project_id=project.id,
            url=request.url,
            branch=request.branch
        )

        # Auto-enter
        await project_service.enter_project(project.id)

        return project

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
