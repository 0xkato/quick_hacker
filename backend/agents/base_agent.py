"""Base agent class for security auditing."""

import asyncio
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Callable, Optional

from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    FindingCreate,
    WSMessage,
    WSMessageType,
)
from providers import BaseProvider, get_provider
from services.attack_surface_service import attack_surface_service
from services.flow_service import flow_service
from services.project_service import project_service


class BaseAgent(ABC):
    """Abstract base class for security auditing agents."""

    agent_type: AgentType = AgentType.CUSTOM

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
    ):
        self.id = str(uuid.uuid4())[:12]
        self.repo_id = request.repo_id
        self.repo_path = repo_path
        self.provider_config = request.provider_config
        self.scan_tier = request.scan_tier
        self.time_budget_seconds = request.time_budget_seconds
        self.custom_prompt = request.custom_prompt
        self.target_files = request.target_files
        self.focus_areas = request.focus_areas
        self.on_message = on_message

        # State
        self.status = AgentStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.files_analyzed = 0
        self.findings: list[Finding] = []
        self.error_message: Optional[str] = None

        # Cancellation
        self._cancelled = False
        self._task: Optional[asyncio.Task] = None

        # Pause support
        self._pause_requested = False
        self.processed_files: list[str] = []
        self.pending_files: list[str] = []
        self.current_file: Optional[str] = None

        # Provider (lazy init)
        self._provider: Optional[BaseProvider] = None

        # Name
        self.name = request.name or f"{self.agent_type.value}_{self.id}"

    @property
    def provider(self) -> BaseProvider:
        """Lazy initialize provider."""
        if self._provider is None:
            self._provider = get_provider(self.provider_config)
        return self._provider

    def to_schema(self) -> Agent:
        """Convert to Agent schema."""
        return Agent(
            id=self.id,
            repo_id=self.repo_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
            provider_config=self.provider_config,
            scan_tier=self.scan_tier,
            time_budget_seconds=self.time_budget_seconds,
            custom_prompt=self.custom_prompt,
            target_files=self.target_files,
            focus_areas=self.focus_areas,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            files_analyzed=self.files_analyzed,
            findings_count=len(self.findings),
            error_message=self.error_message,
        )

    async def emit(self, msg_type: WSMessageType, data: dict):
        """Emit a WebSocket message."""
        if self.on_message:
            msg = WSMessage(
                type=msg_type,
                agent_id=self.id,
                data=data,
            )
            await asyncio.to_thread(self.on_message, msg)

    async def emit_log(self, message: str):
        """Emit a log message."""
        await self.emit(WSMessageType.LOG, {"message": message})

    async def emit_progress(self, current: int, total: int, file: str = ""):
        """Emit progress update."""
        await self.emit(
            WSMessageType.PROGRESS,
            {"current": current, "total": total, "file": file},
        )

    async def emit_flow_update(self) -> None:
        """Emit a flow update (if a flow exists) for the investigation diagram."""
        flow = flow_service.get_flow(self.id)
        if flow:
            await self.emit(WSMessageType.PROGRESS, {"type": "flow_update", "flow": flow.to_dict()})

    async def emit_finding(self, finding: Finding):
        """Emit a new finding."""
        await self.emit(WSMessageType.FINDING, finding.model_dump())

    async def emit_status(self, status: AgentStatus):
        """Emit status change."""
        self.status = status
        await self.emit(
            WSMessageType.AGENT_STATUS,
            {"status": status.value},
        )

    async def _build_attack_surface_tree(self) -> None:
        """Build an initial attack-surface tree (best-effort)."""
        threat_model = "AB"
        try:
            project = await project_service.get_project(self.repo_id)
            if project and getattr(project, "threat_model", None):
                threat_model = project.threat_model
        except Exception:
            threat_model = "AB"

        scan_node = flow_service.add_node(
            self.id,
            "scan",
            f"Attack Surface Scan ({threat_model})",
            {"threat_model": threat_model},
        )
        flow_service.update_node_status(self.id, scan_node.id, "running")
        await self.emit_flow_update()

        provider = None
        try:
            provider = self.provider
        except Exception:
            provider = None

        try:
            triaged = []
            if provider is None:
                flow_service.update_node_data(
                    self.id,
                    scan_node.id,
                    {"skipped": True, "reason": "no_provider_configured"},
                )
                flow_service.update_node_status(self.id, scan_node.id, "completed")
                await self.emit_flow_update()
                return

            candidates = attack_surface_service.scan_candidates(repo_path=self.repo_path)
            triaged = await attack_surface_service.triage(
                agent_id=self.id,
                repo_path=self.repo_path,
                threat_model=threat_model,  # type: ignore[arg-type]
                provider=provider,
                candidates=candidates,
            )

            flow_service.update_node_data(
                self.id,
                scan_node.id,
                {
                    "candidates_found": len(candidates),
                    "investigate_count": len(triaged),
                },
            )
            flow_service.update_node_status(self.id, scan_node.id, "completed")

            for item in triaged[:20]:
                c = item.candidate
                node_type = "entry_point" if c.kind == "entry_point" else "dangerous_sink"
                exposure = item.exposure if item.exposure != "unknown" else ""
                label = f"[{exposure}] {c.label}" if exposure else c.label

                flow_service.add_node(
                    self.id,
                    node_type,  # type: ignore[arg-type]
                    label,
                    data={
                        "attack_surface_candidate_id": c.id,
                        "kind": c.kind,
                        "file_path": c.file_path,
                        "line_number": c.line_number,
                        "metadata": c.metadata,
                        "threat_model": threat_model,
                        "exposure": item.exposure,
                    },
                    parent_id=scan_node.id,
                    edge_label="candidate",
                    llm_reasoning=item.reasoning,
                    code_context=c.code_context,
                    confidence_score=item.confidence_score,
                    set_current=False,
                )

            await self.emit_flow_update()
        except Exception as e:
            flow_service.update_node_data(self.id, scan_node.id, {"error": str(e)})
            flow_service.update_node_status(self.id, scan_node.id, "failed")
            await self.emit_flow_update()

    def add_finding(self, finding_create: FindingCreate) -> Finding:
        """Add a finding."""
        finding = Finding(
            id=str(uuid.uuid4())[:12],
            agent_id=self.id,
            repo_id=self.repo_id,
            created_at=datetime.utcnow(),
            **finding_create.model_dump(),
        )
        self.findings.append(finding)
        return finding

    async def run(self) -> list[Finding]:
        """Run the agent."""
        try:
            self.started_at = datetime.utcnow()
            await self.emit_status(AgentStatus.RUNNING)
            await self.emit_log(f"Starting {self.agent_type.value} agent...")

            # Initialize investigation flow (used by the Flow diagram UI)
            flow_service.initialize_flow(self.id)
            start_node = flow_service.add_node(
                self.id,
                "user_input",
                f"Start {self.agent_type.value}",
                {"agent_type": self.agent_type.value},
            )
            flow_service.update_node_status(self.id, start_node.id, "completed")
            await self.emit_flow_update()

            # Best-effort initial scan + triage (safe to no-op on failure).
            await self._build_attack_surface_tree()

            # Run the actual analysis
            await self.analyze()

            if self._cancelled:
                await self.emit_status(AgentStatus.CANCELLED)
                await self.emit_log("Agent cancelled")
            else:
                self.completed_at = datetime.utcnow()
                await self.emit_status(AgentStatus.COMPLETED)
                await self.emit_log(
                    f"Analysis complete. Found {len(self.findings)} potential issues."
                )
                flow_service.add_node(
                    self.id,
                    "analysis",
                    "Audit Complete",
                    {"findings_count": len(self.findings)},
                )
                await self.emit_flow_update()

        except Exception as e:
            self.error_message = str(e)
            await self.emit_status(AgentStatus.FAILED)
            await self.emit(WSMessageType.ERROR, {"error": str(e)})
            raise

        return self.findings

    def cancel(self):
        """Cancel the agent."""
        self._cancelled = True
        if self._task:
            self._task.cancel()

    def pause(self):
        """Pause the agent (sets flag, analysis must check)."""
        self.status = AgentStatus.PAUSED

    def resume(self):
        """Resume the agent."""
        if self.status == AgentStatus.PAUSED:
            self.status = AgentStatus.RUNNING

    def request_pause(self):
        """Request the agent to pause at the next safe point."""
        self._pause_requested = True

    def is_pausable(self) -> bool:
        """Check if agent can be paused."""
        return self.status == AgentStatus.RUNNING

    def get_pause_state(self) -> dict:
        """Get current state for snapshot."""
        return {
            "processed_files": getattr(self, "processed_files", []),
            "pending_files": getattr(self, "pending_files", []),
            "current_file": getattr(self, "current_file", None),
        }

    @abstractmethod
    async def analyze(self):
        """Perform the actual analysis. Must be implemented by subclasses."""
        pass

    def get_state_snapshot(self):
        """
        Create a state snapshot for persistence.
        Allows agents to be restored after restart.
        """
        from models.observability import AgentStateSnapshot
        from services.observability_service import observability_service

        repo_path = str(self.repo_path)

        files_analyzed: int
        if isinstance(self.files_analyzed, (list, tuple, set)):
            files_analyzed = len(self.files_analyzed)
        else:
            try:
                files_analyzed = int(self.files_analyzed or 0)
            except Exception:
                files_analyzed = 0

        provider_config: dict[str, object] = {}
        if self.provider_config:
            provider_value = (
                self.provider_config.provider.value
                if hasattr(self.provider_config.provider, "value")
                else str(self.provider_config.provider)
            )
            provider_config = {
                "provider": provider_value,
                "model": self.provider_config.model,
            }
            session_id = getattr(self, "_codex_session_id", None)
            if isinstance(session_id, str) and session_id:
                provider_config["session_id"] = session_id

        return AgentStateSnapshot(
            id=str(uuid.uuid4())[:12],
            agent_id=self.id,
            repo_id=self.repo_id,
            repo_path=repo_path,
            agent_type=self.agent_type.value if hasattr(self.agent_type, 'value') else str(self.agent_type),
            provider_config=provider_config,
            custom_prompt=self.custom_prompt,
            status=self.status.value if hasattr(self.status, 'value') else str(self.status),
            files_analyzed=files_analyzed,
            total_files=0,
            current_file=None,
            findings=[f.model_dump(mode='json') for f in self.findings],
            conversation_history=[],  # BaseAgent doesn't track conversation
            llm_interactions=[i.model_dump(mode="json", exclude_none=True) for i in observability_service.get_interactions(self.id)],
            tool_details=[d.model_dump(mode="json", exclude_none=True) for d in observability_service.get_tool_details(self.id)],
            flow_nodes=[],
            flow_edges=[],
            current_flow_node_id=None,
            investigation_context={
                "focus_areas": self.focus_areas,
                "target_files": self.target_files,
            },
            total_prompt_tokens=0,
            total_completion_tokens=0,
            total_api_calls=0,
            last_error=self.error_message,
        )
