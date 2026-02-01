"""Project management API endpoints."""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Literal, Any
from datetime import datetime

from services.project_service import project_service, Project
from services.sink_signal_service import sink_signal_service
from models.sink_signals import SinkSignal, SinkSignalStatus
from models.threat_model_profile import ThreatModelProfile, ThreatModelPreset, compute_profile_hash, preset_to_profile
from models.validation_profile import ValidationProfile
from services.validation.presets import VALIDATION_PRESETS, get_preset


router = APIRouter(prefix="/projects", tags=["projects"])


class CreateProjectRequest(BaseModel):
    name: str
    description: str = ""


class UpdateProjectRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    threat_model: Optional[Literal["A", "AB", "ABC"]] = None


class CloneIntoProjectRequest(BaseModel):
    url: str
    branch: Optional[str] = None
    force: bool = False  # Force clone even if in another project


class ProjectStatus(BaseModel):
    in_project: bool
    current_project: Optional[Project] = None


class UpdateSinkSignalStatusRequest(BaseModel):
    status: SinkSignalStatus


class ApplyPresetRequest(BaseModel):
    preset: str


class ThreatModelProfileResponse(BaseModel):
    threat_model_preset: ThreatModelPreset
    profile_source: Literal["preset", "custom", "migrated"]
    profile_review_status: Literal["unreviewed", "reviewed"]
    profile_reviewed_at: Optional[datetime] = None
    profile_mapping_version: int
    input_channel_semantics_version: int
    prompt_threat_model_block_version: int
    threat_model_profile: dict[str, Any]
    profile_hash: str


class ThreatModelProfileUpdateRequest(BaseModel):
    action: Literal["reset_to_preset", "save_custom", "mark_reviewed"]
    expected_profile_hash: Optional[str] = None
    preset: Optional[ThreatModelPreset] = None
    profile: Optional[ThreatModelProfile] = None


def _get_profile_hash(project: Project) -> str:
    if project.threat_model_preset is None:
        raise ValueError("Project missing threat_model_preset")
    if project.profile_source is None:
        raise ValueError("Project missing profile_source")
    if project.threat_model_profile is None:
        raise ValueError("Project missing threat_model_profile")

    profile = ThreatModelProfile(**project.threat_model_profile)
    return compute_profile_hash(
        threat_model_preset=project.threat_model_preset,
        profile_source=project.profile_source,
        profile_mapping_version=project.profile_mapping_version,
        input_channel_semantics_version=project.input_channel_semantics_version,
        prompt_threat_model_block_version=project.prompt_threat_model_block_version,
        threat_model_profile=profile,
    )


def _profile_response(project: Project) -> ThreatModelProfileResponse:
    profile_hash = _get_profile_hash(project)
    return ThreatModelProfileResponse(
        threat_model_preset=project.threat_model_preset or project.threat_model,
        profile_source=project.profile_source or "migrated",
        profile_review_status=project.profile_review_status or "unreviewed",
        profile_reviewed_at=project.profile_reviewed_at,
        profile_mapping_version=project.profile_mapping_version,
        input_channel_semantics_version=project.input_channel_semantics_version,
        prompt_threat_model_block_version=project.prompt_threat_model_block_version,
        threat_model_profile=project.threat_model_profile or {},
        profile_hash=profile_hash,
    )


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


@router.get("/validation-presets")
async def list_validation_presets() -> dict[str, dict]:
    """List available validation presets."""
    return {name: profile.model_dump() for name, profile in VALIDATION_PRESETS.items()}


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
        description=request.description,
        threat_model=request.threat_model,
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.get("/{project_id}/threat-model-profile", response_model=ThreatModelProfileResponse)
async def get_threat_model_profile(project_id: str):
    """Get the canonical ThreatModelProfile for this project (includes profile_hash)."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return _profile_response(project)


@router.put("/{project_id}/threat-model-profile", response_model=ThreatModelProfileResponse)
async def update_threat_model_profile(project_id: str, request: ThreatModelProfileUpdateRequest):
    """Update the project's ThreatModelProfile (optimistic concurrency enforced by expected_profile_hash)."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    current = _profile_response(project)

    if not request.expected_profile_hash:
        return JSONResponse(
            status_code=400,
            content={"error_code": "MISSING_EXPECTED_PROFILE_HASH", "retryable": True},
        )

    if request.expected_profile_hash != current.profile_hash:
        return JSONResponse(
            status_code=409,
            content={
                "error_code": "PROFILE_HASH_MISMATCH",
                "retryable": True,
                "current_profile": current.model_dump(mode="json"),
                "current_profile_hash": current.profile_hash,
            },
        )

    if request.action == "mark_reviewed":
        project.profile_review_status = "reviewed"
        project.profile_reviewed_at = datetime.utcnow()
        await project_service._save_projects()
        return _profile_response(project)

    if request.action == "reset_to_preset":
        if not request.preset:
            raise HTTPException(status_code=400, detail="preset is required for reset_to_preset")
        project.threat_model = request.preset
        project.threat_model_preset = request.preset
        project.threat_model_profile = preset_to_profile(request.preset).model_dump(mode="json")
        project.profile_source = "preset"
        project.profile_review_status = "unreviewed"
        project.profile_reviewed_at = None
        await project_service._save_projects()
        return _profile_response(project)

    if request.action == "save_custom":
        if not request.preset:
            raise HTTPException(status_code=400, detail="preset is required for save_custom")
        if not request.profile:
            raise HTTPException(status_code=400, detail="profile is required for save_custom")
        project.threat_model = request.preset
        project.threat_model_preset = request.preset
        project.threat_model_profile = request.profile.model_dump(mode="json")
        project.profile_source = "custom"
        project.profile_review_status = "reviewed"
        project.profile_reviewed_at = datetime.utcnow()
        await project_service._save_projects()
        return _profile_response(project)

    raise HTTPException(status_code=400, detail={"error": "unknown_action", "action": request.action})


@router.get("/{project_id}/validation-profile")
async def get_validation_profile(project_id: str) -> dict:
    """Get validation profile for project."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project.get_validation_profile().model_dump()


@router.put("/{project_id}/validation-profile")
async def update_validation_profile(
    project_id: str,
    profile: ValidationProfile,
) -> dict:
    """Replace validation profile for project."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.validation_profile = profile.model_dump()
    await project_service._save_projects()
    return profile.model_dump()


@router.post("/{project_id}/validation-profile/apply-preset")
async def apply_validation_preset(
    project_id: str,
    request: ApplyPresetRequest,
) -> dict:
    """Apply a preset validation profile."""
    preset = get_preset(request.preset)
    if preset is None:
        raise HTTPException(status_code=404, detail=f"Unknown preset: {request.preset}")

    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project.validation_profile = preset.model_dump()
    await project_service._save_projects()
    return preset.model_dump()


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


@router.get("/{project_id}/sink-signals", response_model=list[SinkSignal])
async def list_sink_signals(
    project_id: str,
    status: Optional[SinkSignalStatus] = Query(None, description="Filter by signal status"),
    limit: Optional[int] = Query(200, ge=1, le=2000, description="Maximum signals to return"),
):
    """List persistent sink signals (investigation leads) for a project."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return await sink_signal_service.list_signals(project_id=project_id, status=status, limit=limit)


@router.put("/{project_id}/sink-signals/{fingerprint}/status", response_model=SinkSignal)
async def update_sink_signal_status(
    project_id: str,
    fingerprint: str,
    request: UpdateSinkSignalStatusRequest,
):
    """Update a sink signal's lifecycle status (no downgrades)."""
    project = await project_service.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        return await sink_signal_service.set_status(
            project_id=project_id,
            fingerprint=fingerprint,
            status=request.status,
        )
    except ValueError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail="Signal not found")
        raise HTTPException(status_code=400, detail=msg)


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
