"""Agent lifecycle management."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from middleware.auth import AuthContext, get_user_api_key_for_provider
from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    ProviderConfig,
    Finding,
)
from agents.base_agent import BaseAgent
from agents.quick_audit_agent import QuickAuditAgent
from agents.react_agent import ReActSecurityAgent
from agents.deep_audit import DeepAuditSupervisor
from providers.claude_sdk_provider import SDK_AVAILABLE
from services.tool_cache import ToolCache
from services import git_service
from services.project_service import project_service
from services.scan_tier_service import resolve_scan_budget
from services.persistence_service import persistence_service


# Agent type to class mapping
AGENT_CLASSES = {
    AgentType.QUICK_AUDIT: QuickAuditAgent,          # Pattern matching
    AgentType.CUSTOM: ReActSecurityAgent,            # ReAct for custom investigation
    AgentType.STRICT_ANALYSIS: DeepAuditSupervisor,  # Deep Agents architecture
    AgentType.ULTRA_STRICT: DeepAuditSupervisor,     # Deep Agents architecture
    AgentType.DEEP_AUDIT: DeepAuditSupervisor,       # Deep Agents architecture
}


class AgentLifecycleManager:
    """Manages agent lifecycle: create, run, pause, resume, cancel."""

    def __init__(self, shared_cache: Optional[ToolCache] = None, broadcast_callback=None):
        """
        Initialize lifecycle manager.
        
        Args:
            shared_cache: Shared tool cache for all agents
            broadcast_callback: Callback for broadcasting messages
        """
        self.running_agents: dict[str, BaseAgent] = {}
        self._shared_cache = shared_cache
        self._broadcast_callback = broadcast_callback

    @staticmethod
    def _is_masked_credential(value: str | None) -> bool:
        """Heuristic to detect masked credentials coming back from the UI/settings export."""
        if not value:
            return False
        candidate = value.strip()
        return candidate == "****" or "..." in candidate

    async def create_agent(
        self,
        request: AgentCreateRequest,
        auth_context: AuthContext,
        db: AsyncSession,
        on_message = None,
    ) -> BaseAgent:
        """
        Create agent instance with provider, tools, budgets.

        Args:
            request: Agent configuration
            auth_context: Authentication context
            db: Database session
            on_message: WebSocket message callback

        Returns:
            Initialized agent instance
        """
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
            1 for a in self.running_agents.values()
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

        # Check if using Claude SDK
        use_claude_sdk = getattr(request, 'use_claude_sdk', False)

        # Resolve API keys for all configs (including SDK - provider will set env var)
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

                normalized_provider = (provider_name or "").strip().lower()
                if not api_key and normalized_provider not in ("ollama", "codex_cli"):
                    # Claude SDK mode can authenticate via Claude Code subscription token
                    # (`claude setup-token`) instead of an Anthropic API key.
                    if (
                        use_claude_sdk
                        and normalized_provider == "anthropic"
                        and config_name == "provider_config"
                    ):
                        print(
                            "[LifecycleManager] Claude SDK mode: no Anthropic API key configured; "
                            "relying on Claude Code auth (setup-token) or ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN env var."
                        )
                        continue
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
                    print(f"[LifecycleManager] Resolved API key for {config_name}")

        if use_claude_sdk:
            if SDK_AVAILABLE:
                print("[LifecycleManager] Using Claude SDK mode (SDK available)")
            else:
                print("[LifecycleManager] WARNING: Claude SDK mode requested but SDK not installed")
                print("[LifecycleManager] Agent will fail when started. Install with: pip install claude-agent-sdk")

        # Use shared cache (all agents share the same cache instance)
        cache = self._shared_cache

        # Create agent instance
        agent_class = AGENT_CLASSES.get(request.agent_type)
        if not agent_class:
            raise ValueError(f"Unknown agent type: {request.agent_type}")

        # Pass cache to agent constructor if it accepts it
        agent_kwargs = {
            "request": request,
            "repo_path": repo_path,
            "on_message": on_message or self._broadcast_callback,
        }

        # ReActSecurityAgent accepts cache parameter
        if agent_class == ReActSecurityAgent:
            agent_kwargs["cache"] = cache

        agent = agent_class(**agent_kwargs)

        # Store cache on agent for potential reuse
        agent._tool_cache = cache

        # Store in running agents
        self.running_agents[agent.id] = agent

        return agent

    async def pause_agent(self, agent_id: str) -> Agent:
        """
        Pause running agent, save state.

        Args:
            agent_id: Agent to pause

        Returns:
            Updated agent schema
        """
        agent = self.running_agents.get(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")

        if agent.status != AgentStatus.RUNNING:
            raise ValueError("Only running agents can be paused")

        agent.pause()

        # If this agent is backed by a long-running subprocess (e.g. codex_cli),
        # interrupt it immediately so pause takes effect mid-turn.
        provider = getattr(agent, "_codex_provider", None)
        if provider is not None:
            try:
                if hasattr(provider, "set_cancelled"):
                    provider.set_cancelled(True)
                interrupt = getattr(provider, "interrupt", None)
                if interrupt is not None:
                    await interrupt()
            except Exception:
                pass

        # Auto-save state on pause (for ReAct agents)
        if hasattr(agent, 'get_state_snapshot'):
            try:
                snapshot = agent.get_state_snapshot()
                persistence_service.save_agent_state(snapshot)
            except Exception as e:
                print(f"[LifecycleManager] Failed to save state on pause: {e}")

        return agent.to_schema()

    async def resume_agent(self, agent_id: str) -> Agent:
        """
        Resume paused agent from saved state.

        Args:
            agent_id: Agent to resume

        Returns:
            Updated agent schema
        """
        agent = self.running_agents.get(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")

        if agent.status != AgentStatus.PAUSED:
            raise ValueError("Only paused agents can be resumed")

        agent.resume()
        return agent.to_schema()

    async def cancel_agent(self, agent_id: str) -> Agent:
        """
        Cancel running agent, cleanup resources.

        Args:
            agent_id: Agent to cancel

        Returns:
            Updated agent schema
        """
        agent = self.running_agents.get(agent_id)

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
                print(f"[LifecycleManager] Failed to save state on cancel: {e}")

        # For Codex CLI agents, call interrupt on the provider
        if hasattr(agent, '_codex_provider') and agent._codex_provider is not None:
            try:
                await agent._codex_provider.interrupt()
                print(f"[LifecycleManager] Interrupted Codex provider for agent {agent_id}")
            except Exception as e:
                print(f"[LifecycleManager] Failed to interrupt Codex provider: {e}")

        # For SDK agents, call interrupt on the provider
        if hasattr(agent, '_sdk_provider') and agent._sdk_provider is not None:
            try:
                await agent._sdk_provider.interrupt()
                print(f"[LifecycleManager] Interrupted SDK provider for agent {agent_id}")
            except Exception as e:
                print(f"[LifecycleManager] Failed to interrupt SDK provider: {e}")

        # For SDK agents with orchestrator, call cancel on the orchestrator
        if hasattr(agent, '_sdk_orchestrator') and agent._sdk_orchestrator is not None:
            try:
                agent._sdk_orchestrator.cancel()
                print(f"[LifecycleManager] Cancelled SDK orchestrator for agent {agent_id}")
            except Exception as e:
                print(f"[LifecycleManager] Failed to cancel SDK orchestrator: {e}")

        agent.cancel()
        return agent.to_schema()

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID."""
        return self.running_agents.get(agent_id)

    def remove_agent(self, agent_id: str) -> bool:
        """Remove agent from running agents."""
        if agent_id in self.running_agents:
            del self.running_agents[agent_id]
            return True
        return False
