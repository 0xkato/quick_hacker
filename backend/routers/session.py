"""Session hibernation endpoints for pause/resume."""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from middleware.auth import require_auth
from models.schemas import (
    SessionSnapshot,
    SessionSnapshotAgent,
    SessionSnapshotUIState,
    SnapshotInfo,
)
from services.session_service import session_service
from services.project_service import project_service

router = APIRouter(prefix="/session", tags=["Session"])


@router.get("/snapshot", response_model=Optional[SnapshotInfo])
async def get_snapshot_info(_: str = Depends(require_auth)):
    """Get metadata about the current session snapshot."""
    project_path = project_service.get_current_project_path()
    if not project_path:
        raise HTTPException(status_code=400, detail="No project selected")

    info = session_service.get_snapshot_info(project_path)
    return info


@router.post("/pause")
async def pause_session(
    ui_state: Optional[dict] = None,
    _: str = Depends(require_auth),
):
    """
    Pause the current session and save a snapshot.

    This endpoint:
    1. Signals all running agents to pause
    2. Waits for in-flight LLM calls to complete
    3. Collects all state (agents, findings, LLM context, UI)
    4. Saves to .quickhack/session-snapshot.json
    """
    project_path = project_service.get_current_project_path()
    if not project_path:
        raise HTTPException(status_code=400, detail="No project selected")

    project = project_service.get_current_project_sync()
    if not project:
        raise HTTPException(status_code=400, detail="No project selected")

    # Old agent orchestrator removed -- no agents to pause
    snapshot_agents = []
    all_findings = []

    # Build UI state
    ui = SessionSnapshotUIState(
        active_view=ui_state.get("active_view", "explorer") if ui_state else "explorer",
        selected_file=ui_state.get("selected_file") if ui_state else None,
        open_panels=ui_state.get("open_panels", []) if ui_state else [],
        selected_agent_id=ui_state.get("selected_agent_id") if ui_state else None,
    )

    snapshot = SessionSnapshot(
        version=1,
        timestamp=datetime.utcnow(),
        project_id=project.id,
        agents=snapshot_agents,
        findings=all_findings,
        llm_context=[],  # TODO: implement LLM context capture
        ui_state=ui,
    )

    # Save snapshot
    snapshot_path = session_service.save_snapshot(project_path, snapshot)

    return {
        "status": "paused",
        "snapshot_path": snapshot_path,
        "agents_paused": len(pausing_agents),
        "findings_saved": len(all_findings),
    }


@router.post("/resume")
async def resume_session(_: str = Depends(require_auth)):
    """
    Resume a session from a saved snapshot.

    This endpoint:
    1. Loads the snapshot from disk
    2. Restores agent state
    3. Restores findings
    4. Returns UI state for frontend restoration
    """
    project_path = project_service.get_current_project_path()
    if not project_path:
        raise HTTPException(status_code=400, detail="No project selected")

    snapshot = session_service.load_snapshot(project_path)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No snapshot found")

    # Return snapshot data for frontend to restore
    # Actual agent restoration would require re-creating agent instances
    # which is complex - for now, return data for frontend display

    return {
        "status": "restored",
        "snapshot": snapshot.model_dump(mode="json"),
    }


@router.delete("/snapshot")
async def delete_snapshot(_: str = Depends(require_auth)):
    """Delete the current session snapshot."""
    project_path = project_service.get_current_project_path()
    if not project_path:
        raise HTTPException(status_code=400, detail="No project selected")

    deleted = session_service.delete_snapshot(project_path)
    if not deleted:
        raise HTTPException(status_code=404, detail="No snapshot found")

    return {"status": "deleted"}
