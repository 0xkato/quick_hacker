"""Agent orchestrator for managing multiple concurrent agents."""

import asyncio
from datetime import datetime
from typing import Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from middleware.auth import AuthContext, get_user_api_key_for_provider
from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    WSMessage,
    ProviderConfig,
)
from agents.base_agent import BaseAgent
from agents.quick_audit_agent import QuickAuditAgent
from agents.react_agent import ReActSecurityAgent
from agents.deep_audit_agent import DeepAuditAgent
from agents.ultrathink_agent import UltrathinkAgent
from services import git_service
from services.project_service import project_service
from services.settings_service import settings_service
from services.persistence_service import persistence_service
from services.report_service import report_service


# Agent type to class mapping
AGENT_CLASSES = {
    AgentType.DEEP_SCAN: ReActSecurityAgent,      # ReAct for thorough investigation
    AgentType.QUICK_AUDIT: QuickAuditAgent,       # Pattern matching
    AgentType.CUSTOM: ReActSecurityAgent,         # ReAct for custom investigation
    AgentType.STRICT_ANALYSIS: ReActSecurityAgent,# ReAct for strict mode
    AgentType.ULTRA_STRICT: ReActSecurityAgent,   # ReAct for ultra strict
    AgentType.DEEP_AUDIT: DeepAuditAgent,         # 3-layer architecture
    AgentType.ULTRATHINK: UltrathinkAgent,        # Maximum cognitive depth
}


class AgentOrchestrator:
    """
    Manages multiple security auditing agents.

    Features:
    - Concurrent agent execution
    - Agent lifecycle management (create, run, pause, cancel)
    - Real-time updates via WebSocket callbacks
    - Rate limiting and resource management
    """

    def __init__(self):
        self._agents: dict[str, BaseAgent] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._findings: dict[str, list[Finding]] = {}  # agent_id -> findings
        self._message_callbacks: list[Callable[[WSMessage], None]] = []
        self._lock = asyncio.Lock()

    def add_message_callback(self, callback: Callable[[WSMessage], None]):
        """Add a callback for agent messages (WebSocket broadcast)."""
        self._message_callbacks.append(callback)

    def remove_message_callback(self, callback: Callable[[WSMessage], None]):
        """Remove a message callback."""
        if callback in self._message_callbacks:
            self._message_callbacks.remove(callback)

    def _broadcast_message(self, message: WSMessage):
        """Broadcast message to all registered callbacks."""
        for callback in self._message_callbacks:
            try:
                callback(message)
            except Exception as e:
                print(f"Callback error: {e}")

    async def create_agent(
        self,
        request: AgentCreateRequest,
        auth_context: AuthContext,
        db: AsyncSession
    ) -> Agent:
        """Create a new agent instance."""
        # Get repo path - try project ID first, then fall back to repo ID
        repo_path = project_service.get_project_repo_path(request.repo_id)
        if not repo_path:
            # Fall back to git service for backwards compatibility
            repo = await git_service.get_repo(request.repo_id)
            if not repo:
                raise ValueError(f"Project or repository not found: {request.repo_id}")
            repo_path = repo.path

        # Check concurrent agent limit
        running_count = sum(
            1 for a in self._agents.values()
            if a.status in [AgentStatus.RUNNING, AgentStatus.PENDING]
        )
        if running_count >= settings.max_concurrent_agents:
            raise ValueError(
                f"Maximum concurrent agents ({settings.max_concurrent_agents}) reached"
            )

        # Resolve API keys for all configs
        configs_to_resolve = []
        if request.provider_config:
            configs_to_resolve.append(("provider_config", request.provider_config))
        if request.scanner_config:
            configs_to_resolve.append(("scanner_config", request.scanner_config))
        if request.analyzer_config:
            configs_to_resolve.append(("analyzer_config", request.analyzer_config))

        for config_name, config in configs_to_resolve:
            if config and not config.api_key:
                provider_name = (
                    config.provider.value
                    if hasattr(config.provider, 'value')
                    else str(config.provider)
                )

                api_key = await get_user_api_key_for_provider(
                    provider_name,
                    auth_context,
                    db
                )

                if not api_key and provider_name != "ollama":
                    raise ValueError(
                        f"No {provider_name.capitalize()} API key found for {config_name}. "
                        f"Please add your API key in Settings."
                    )

                if api_key:
                    # Create new config with resolved key
                    resolved_config = ProviderConfig(
                        provider=config.provider,
                        model=config.model,
                        api_key=api_key,
                        base_url=config.base_url,
                        temperature=config.temperature,
                        max_tokens=config.max_tokens,
                    )
                    setattr(request, config_name, resolved_config)
                    print(f"[Orchestrator] Resolved API key for {config_name}")

        # Create agent instance
        agent_class = AGENT_CLASSES.get(request.agent_type)
        if not agent_class:
            raise ValueError(f"Unknown agent type: {request.agent_type}")

        # Use focused agent if focus areas provided with custom type
        if request.agent_type == AgentType.CUSTOM and request.focus_areas:
            agent_class = FocusedAgent

        agent = agent_class(
            request=request,
            repo_path=repo_path,
            on_message=self._broadcast_message,
        )

        async with self._lock:
            self._agents[agent.id] = agent
            self._findings[agent.id] = []

        return agent.to_schema()

    async def start_agent(self, agent_id: str) -> Agent:
        """Start an agent's analysis."""
        agent = self._agents.get(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")

        if agent.status not in [AgentStatus.PENDING, AgentStatus.PAUSED]:
            raise ValueError(f"Agent cannot be started (status: {agent.status})")

        print(f"[Orchestrator] Starting agent {agent_id} (type: {type(agent).__name__})")

        # Create task for agent execution
        task = asyncio.create_task(self._run_agent(agent))
        self._tasks[agent_id] = task

        print(f"[Orchestrator] Task created for agent {agent_id}")
        return agent.to_schema()

    async def _run_agent(self, agent: BaseAgent):
        """Run agent and handle completion."""
        print(f"[Orchestrator] _run_agent started for {agent.id}")
        try:
            findings = await agent.run()
            print(f"[Orchestrator] Agent {agent.id} completed with {len(findings)} findings")
            self._findings[agent.id] = findings

            # Save state on successful completion (for persistence)
            if hasattr(agent, 'get_state_snapshot'):
                try:
                    snapshot = agent.get_state_snapshot()
                    persistence_service.save_agent_state(snapshot)
                    print(f"[Orchestrator] Saved state for completed agent {agent.id}")
                except Exception as e:
                    print(f"[Orchestrator] Failed to save state on completion: {e}")

            # Generate report on successful completion (for ReAct agents)
            if hasattr(agent, 'get_state_snapshot'):
                try:
                    report_service.generate_report(agent)
                except Exception as e:
                    print(f"[Orchestrator] Failed to generate report: {e}")
        except asyncio.CancelledError:
            print(f"[Orchestrator] Agent {agent.id} cancelled")
            agent.status = AgentStatus.CANCELLED
            # Save state on cancellation
            if hasattr(agent, 'get_state_snapshot'):
                try:
                    snapshot = agent.get_state_snapshot()
                    persistence_service.save_agent_state(snapshot)
                except Exception as e:
                    print(f"[Orchestrator] Failed to save state on cancel: {e}")
        except Exception as e:
            print(f"[Orchestrator] Agent {agent.id} FAILED with error: {e}")
            import traceback
            traceback.print_exc()
            agent.status = AgentStatus.FAILED
            agent.error_message = str(e)
            # Save state on failure for debugging/resume
            if hasattr(agent, 'get_state_snapshot'):
                try:
                    snapshot = agent.get_state_snapshot()
                    persistence_service.save_agent_state(snapshot)
                except Exception as save_err:
                    print(f"[Orchestrator] Failed to save state on failure: {save_err}")
        finally:
            print(f"[Orchestrator] _run_agent cleanup for {agent.id}")
            # Cleanup task reference
            if agent.id in self._tasks:
                del self._tasks[agent.id]

    async def pause_agent(self, agent_id: str) -> Agent:
        """Pause a running agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")

        if agent.status != AgentStatus.RUNNING:
            raise ValueError("Only running agents can be paused")

        agent.pause()

        # Auto-save state on pause (for ReAct agents)
        if hasattr(agent, 'get_state_snapshot'):
            try:
                snapshot = agent.get_state_snapshot()
                persistence_service.save_agent_state(snapshot)
            except Exception as e:
                print(f"[Orchestrator] Failed to save state on pause: {e}")

        return agent.to_schema()

    async def resume_agent(self, agent_id: str) -> Agent:
        """Resume a paused agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")

        if agent.status != AgentStatus.PAUSED:
            raise ValueError("Only paused agents can be resumed")

        agent.resume()
        return agent.to_schema()

    async def cancel_agent(self, agent_id: str) -> Agent:
        """Cancel an agent (in-memory or persisted)."""
        agent = self._agents.get(agent_id)

        # If not in memory, check persisted state
        if not agent:
            snapshot = persistence_service.load_agent_state(agent_id)
            if snapshot:
                # Update persisted state to cancelled
                snapshot.status = AgentStatus.CANCELLED.value
                persistence_service.save_agent_state(snapshot)
                # Return a schema representation
                return Agent(
                    id=snapshot.agent_id,
                    repo_id=snapshot.repo_id,
                    name=f"Cancelled: {snapshot.agent_type}",
                    agent_type=snapshot.agent_type,
                    status=AgentStatus.CANCELLED,
                    provider_config=ProviderConfig(
                        provider=snapshot.provider_config.get("provider", "openai") if snapshot.provider_config else "openai",
                        model=snapshot.provider_config.get("model", "unknown") if snapshot.provider_config else "unknown",
                    ),
                    created_at=snapshot.created_at,
                    files_analyzed=snapshot.files_analyzed,
                    findings_count=len(snapshot.findings) if snapshot.findings else 0,
                )
            raise ValueError(f"Agent not found: {agent_id}")

        if agent.status in [AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.CANCELLED]:
            raise ValueError(f"Agent already finished (status: {agent.status})")

        # Auto-save state before cancelling (for ReAct agents)
        if hasattr(agent, 'get_state_snapshot'):
            try:
                snapshot = agent.get_state_snapshot()
                persistence_service.save_agent_state(snapshot)
            except Exception as e:
                print(f"[Orchestrator] Failed to save state on cancel: {e}")

        agent.cancel()

        # Cancel the task if running
        task = self._tasks.get(agent_id)
        if task and not task.done():
            task.cancel()

        return agent.to_schema()

    async def get_agent(self, agent_id: str) -> Optional[Agent]:
        """Get agent by ID."""
        agent = self._agents.get(agent_id)
        return agent.to_schema() if agent else None

    async def list_agents(
        self,
        repo_id: Optional[str] = None,
        status: Optional[AgentStatus] = None,
    ) -> list[Agent]:
        """List agents with optional filtering."""
        agents = []
        for agent in self._agents.values():
            if repo_id and agent.repo_id != repo_id:
                continue
            if status and agent.status != status:
                continue
            agents.append(agent.to_schema())

        # Sort by creation time (newest first)
        agents.sort(key=lambda a: a.created_at, reverse=True)
        return agents

    async def get_findings(
        self,
        agent_id: Optional[str] = None,
        repo_id: Optional[str] = None,
    ) -> list[Finding]:
        """Get findings with optional filtering."""
        findings = []

        if agent_id:
            agent = self._agents.get(agent_id)
            if agent:
                findings.extend(agent.findings)
        elif repo_id:
            for agent in self._agents.values():
                if agent.repo_id == repo_id:
                    findings.extend(agent.findings)
        else:
            for agent in self._agents.values():
                findings.extend(agent.findings)

        # Sort by severity and creation time
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (severity_order.get(f.severity.value, 5), f.created_at))

        return findings

    async def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent and its findings."""
        agent = self._agents.get(agent_id)
        if not agent:
            return False

        # Cancel if still running
        if agent.status in [AgentStatus.RUNNING, AgentStatus.PENDING]:
            await self.cancel_agent(agent_id)

        async with self._lock:
            del self._agents[agent_id]
            if agent_id in self._findings:
                del self._findings[agent_id]
            if agent_id in self._tasks:
                del self._tasks[agent_id]

        return True

    async def get_stats(self) -> dict:
        """Get orchestrator statistics."""
        status_counts = {}
        for agent in self._agents.values():
            status = agent.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

        total_findings = sum(len(a.findings) for a in self._agents.values())

        return {
            "total_agents": len(self._agents),
            "status_counts": status_counts,
            "total_findings": total_findings,
            "max_concurrent": settings.max_concurrent_agents,
        }


# Global orchestrator instance
orchestrator = AgentOrchestrator()
