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
from providers.claude_sdk_provider import ClaudeSDKProvider
from services.claude_sdk_orchestrator import ClaudeSDKOrchestrator
from services.tool_core import ToolCore
from services import git_service
from services.project_service import project_service
from services.settings_service import settings_service
from services.persistence_service import persistence_service
from services.report_service import report_service
from services.scan_tier_service import resolve_scan_budget


# Agent type to class mapping
AGENT_CLASSES = {
    AgentType.QUICK_AUDIT: QuickAuditAgent,       # Pattern matching
    AgentType.CUSTOM: ReActSecurityAgent,         # ReAct for custom investigation
    AgentType.STRICT_ANALYSIS: ReActSecurityAgent,# ReAct for strict mode
    AgentType.ULTRA_STRICT: ReActSecurityAgent,   # ReAct for ultra strict
    AgentType.DEEP_AUDIT: ReActSecurityAgent,     # ReAct w/ deeper profile
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

        # Resolve/validate scan tier → time budget (time-tiered audits).
        # Custom agents may omit scan tiers entirely.
        if request.agent_type != AgentType.CUSTOM:
            resolved = resolve_scan_budget(
                scan_tier=request.scan_tier,
                time_budget_seconds=request.time_budget_seconds,
            )
            request.scan_tier = resolved.scan_tier
            request.time_budget_seconds = resolved.time_budget_seconds
        else:
            # Only normalize custom agent timing if an explicit time override is provided.
            if request.time_budget_seconds is not None:
                resolved = resolve_scan_budget(
                    scan_tier=request.scan_tier,
                    time_budget_seconds=request.time_budget_seconds,
                )
                request.scan_tier = resolved.scan_tier
                request.time_budget_seconds = resolved.time_budget_seconds

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
            # Check if this agent should use Claude SDK provider
            config = getattr(agent.request, 'provider_config', None)
            if config and hasattr(config, 'provider'):
                provider_name = (
                    config.provider.value
                    if hasattr(config.provider, 'value')
                    else str(config.provider)
                )
                if provider_name.lower() == "claude_sdk":
                    findings = await self._run_sdk_agent(agent)
                else:
                    findings = await agent.run()
            else:
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

    async def _run_sdk_agent(self, agent: BaseAgent) -> list[Finding]:
        """Run an agent using the Claude SDK provider.

        Creates ToolCore with limits factory, ClaudeSDKProvider, and
        ClaudeSDKOrchestrator to run the security audit.

        Args:
            agent: The agent to run with SDK provider

        Returns:
            List of Finding objects from the audit
        """
        print(f"[Orchestrator] Running SDK agent {agent.id}")

        config = agent.request.provider_config
        scan_tier = getattr(agent.request, 'scan_tier', 'quick') or 'quick'

        # Create ClaudeSDKOrchestrator first to get make_fresh_limits
        # We need a temporary orchestrator to get the limits factory
        sdk_orchestrator = ClaudeSDKOrchestrator(
            scan_tier=scan_tier,
            on_ws_event=lambda event: self._broadcast_message(
                WSMessage(type=event.get("type", "sdk_event"), data=event)
            ),
            provider=None,  # Will be set after provider is created
            tool_core=None,  # Will be set after tool_core is created
        )

        # Create ToolCore with limits factory from orchestrator
        tool_core = ToolCore(
            repo_path=agent.repo_path,
            project_id=agent.repo_id,
            get_scan_limits=sdk_orchestrator.make_fresh_limits,
        )

        # Create ClaudeSDKProvider
        provider_config = {
            "model": config.model if config else "claude-sonnet-4-20250514",
            "api_key": config.api_key if config else None,
            "max_tokens": config.max_tokens if config else 8192,
        }

        provider = ClaudeSDKProvider(
            repo_path=agent.repo_path,
            project_id=agent.repo_id,
            tool_core=tool_core,
            config=provider_config,
        )

        # Store provider reference on agent for cancellation
        agent._sdk_provider = provider

        # Update orchestrator with actual provider and tool_core
        sdk_orchestrator.provider = provider
        sdk_orchestrator.tool_core = tool_core

        # Store SDK orchestrator reference on agent for cancellation
        agent._sdk_orchestrator = sdk_orchestrator

        try:
            # Build initial prompt for the audit
            initial_prompt = self._build_initial_audit_prompt(agent)

            # Run the audit
            result = await sdk_orchestrator.run_audit(initial_prompt)

            # Convert findings from dict to Finding objects
            findings: list[Finding] = []
            for finding_data in result.get("findings", []):
                try:
                    finding = Finding(
                        id=f"{agent.id}-{len(findings)}",
                        agent_id=agent.id,
                        title=finding_data.get("title", "Untitled Finding"),
                        description=finding_data.get("description", ""),
                        severity=finding_data.get("severity", "medium"),
                        file_path=finding_data.get("file_path", ""),
                        line_start=finding_data.get("line_start"),
                        line_end=finding_data.get("line_end"),
                        vulnerable_code=finding_data.get("vulnerable_code", ""),
                        recommendation=finding_data.get("recommended_fix", ""),
                    )
                    findings.append(finding)
                except Exception as e:
                    print(f"[Orchestrator] Failed to convert finding: {e}")

            # Update agent findings
            agent.findings = findings
            agent.status = AgentStatus.COMPLETED

            return findings

        finally:
            # Clean up provider
            await provider.close()

    def _build_initial_audit_prompt(self, agent: BaseAgent) -> str:
        """Build the initial prompt for a security audit.

        Args:
            agent: The agent with audit configuration

        Returns:
            Initial prompt string for the audit
        """
        prompt_parts = [
            f"Perform a security audit of the repository at {agent.repo_path}.",
            "Focus on identifying vulnerabilities, security misconfigurations, and potential attack vectors.",
        ]

        # Add custom prompt if provided
        if hasattr(agent.request, 'custom_prompt') and agent.request.custom_prompt:
            prompt_parts.append(f"Additional instructions: {agent.request.custom_prompt}")

        # Add focus areas if provided
        if hasattr(agent.request, 'focus_areas') and agent.request.focus_areas:
            focus_str = ", ".join(agent.request.focus_areas)
            prompt_parts.append(f"Focus particularly on: {focus_str}")

        # Add target files if provided
        if hasattr(agent.request, 'target_files') and agent.request.target_files:
            files_str = ", ".join(agent.request.target_files)
            prompt_parts.append(f"Prioritize analyzing these files: {files_str}")

        return " ".join(prompt_parts)

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

        # For SDK agents, call interrupt on the provider
        if hasattr(agent, '_sdk_provider') and agent._sdk_provider is not None:
            try:
                agent._sdk_provider.interrupt()
                print(f"[Orchestrator] Interrupted SDK provider for agent {agent_id}")
            except Exception as e:
                print(f"[Orchestrator] Failed to interrupt SDK provider: {e}")

        # For SDK agents with orchestrator, call cancel on the orchestrator
        if hasattr(agent, '_sdk_orchestrator') and agent._sdk_orchestrator is not None:
            try:
                agent._sdk_orchestrator.cancel()
                print(f"[Orchestrator] Cancelled SDK orchestrator for agent {agent_id}")
            except Exception as e:
                print(f"[Orchestrator] Failed to cancel SDK orchestrator: {e}")

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
