"""Agent orchestrator for managing multiple concurrent agents."""

import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

from config import settings
from middleware.auth import AuthContext, get_user_api_key_for_provider
from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    WSMessage,
    WSMessageType,
    ProviderConfig,
)
from agents.base_agent import BaseAgent
from agents.quick_audit_agent import QuickAuditAgent
from agents.react_agent import ReActSecurityAgent
from agents.deep_audit import DeepAuditSupervisor
from providers.claude_sdk_provider import ClaudeSDKProvider
from providers.codex_cli_provider import CodexCLIProvider
from services.claude_sdk_orchestrator import ClaudeSDKOrchestrator
from services.tool_core import ToolCore
from services.tool_cache import ToolCache
from services import git_service
from services.project_service import project_service
from services.settings_service import settings_service
from services.persistence_service import persistence_service
from services.report_service import report_service
from services.scan_tier_service import resolve_scan_budget
from services.flow_service import flow_service
from services.observability_service import observability_service
from services.finding_triage_service import triage_service
from services.threat_model_prompt_block import build_threat_model_prompt_block
from prompting_loader import load_prompt, render_prompt


def _codex_text_signals_handoff_to_analyzer(text: str) -> bool:
    """Return True if Codex output indicates the scanner phase is complete."""
    if not text:
        return False
    normalized = str(text).strip().lower().replace("_", " ")
    return any(
        phrase in normalized
        for phrase in (
            "scanning complete",
            "scan complete",
        )
    )


def _codex_text_signals_done(text: str) -> bool:
    """Return True if Codex output indicates the overall audit is complete."""
    if not text:
        return False
    normalized = str(text).strip().lower().replace("_", " ")
    return any(
        phrase in normalized
        for phrase in (
            "audit complete",
            "analysis complete",
            "investigation complete",
            "no more findings",
        )
    )


# Agent type to class mapping
AGENT_CLASSES = {
    AgentType.QUICK_AUDIT: QuickAuditAgent,          # Pattern matching
    AgentType.CUSTOM: ReActSecurityAgent,            # ReAct for custom investigation
    AgentType.STRICT_ANALYSIS: DeepAuditSupervisor,  # Deep Agents architecture
    AgentType.ULTRA_STRICT: DeepAuditSupervisor,     # Deep Agents architecture
    AgentType.DEEP_AUDIT: DeepAuditSupervisor,       # Deep Agents architecture
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

        # Shared cache for all agents (created once, reused across all agents)
        self._shared_cache: Optional[ToolCache] = None
        if settings.tool_cache_enabled:
            try:
                self._shared_cache = ToolCache(
                    max_size=settings.tool_cache_max_size,
                    ttl_seconds=settings.tool_cache_ttl_seconds,
                )
                logger.info(
                    "Initialized shared tool cache: max_size=%d, ttl=%ds",
                    settings.tool_cache_max_size,
                    settings.tool_cache_ttl_seconds
                )
            except ValueError as e:
                logger.error("Failed to initialize shared cache: %s", e)
                self._shared_cache = None

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
                            "[Orchestrator] Claude SDK mode: no Anthropic API key configured; "
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
                    print(f"[Orchestrator] Resolved API key for {config_name}")

        if use_claude_sdk:
            print("[Orchestrator] Using Claude SDK mode")

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
            "on_message": self._broadcast_message,
        }

        # ReActSecurityAgent accepts cache parameter
        if agent_class == ReActSecurityAgent:
            agent_kwargs["cache"] = cache

        agent = agent_class(**agent_kwargs)

        # Store cache on agent for potential reuse in _run_sdk_agent
        agent._tool_cache = cache

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
            use_sdk = False
            use_codex = False

            if config and hasattr(config, 'provider'):
                provider_name = (
                    config.provider.value
                    if hasattr(config.provider, 'value')
                    else str(config.provider)
                )

                if provider_name.lower() == "codex_cli":
                    use_codex = True
                # Use SDK if:
                # Use SDK if:
                # 1. Provider is explicitly set to "claude_sdk", OR
                # 2. Provider is "anthropic" and use_claude_sdk flag is True
                if provider_name.lower() == "claude_sdk":
                    use_sdk = True
                elif provider_name.lower() == "anthropic":
                    use_claude_sdk = getattr(agent.request, 'use_claude_sdk', False)
                    use_sdk = use_claude_sdk

            if use_codex:
                findings = await self._run_codex_cli_agent(agent)
            elif use_sdk:
                findings = await self._run_sdk_agent(agent)
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

        # Update agent status to RUNNING
        agent.status = AgentStatus.RUNNING
        agent.started_at = datetime.utcnow()
        self._broadcast_message(WSMessage(
            type=WSMessageType.AGENT_STATUS,
            agent_id=agent.id,
            data={"status": "running"}
        ))

        config = agent.request.provider_config
        scan_tier = getattr(agent.request, 'scan_tier', 'quick') or 'quick'

        # Re-resolve credentials at run-time for SDK mode.
        #
        # This covers cases where:
        # - An agent was created before the user saved credentials in Settings, or
        # - The UI supplied a masked credential (e.g. `sk-a...wxyz`) which is not usable.
        sdk_api_key: str | None = None
        if config is not None:
            sdk_api_key = getattr(config, "api_key", None)
        sdk_api_key = (sdk_api_key or "").strip() or None

        if sdk_api_key is None or self._is_masked_credential(sdk_api_key):
            try:
                provider_name = "anthropic"
                if config is not None and hasattr(config, "provider"):
                    raw_provider = config.provider.value if hasattr(config.provider, "value") else str(config.provider)
                    normalized_provider = (raw_provider or "").strip().lower()
                    provider_name = "anthropic" if normalized_provider in ("anthropic", "claude_sdk") else normalized_provider

                if provider_name == "anthropic":
                    app_settings = await settings_service.get_settings()
                    provider_settings = app_settings.providers.get("anthropic")
                    candidate = (provider_settings.api_key or "").strip() if provider_settings else ""
                    if candidate:
                        sdk_api_key = candidate
                        print("[Orchestrator] Loaded Anthropic credential from Settings for Claude SDK run")
            except Exception:
                # Best-effort only: fall back to env vars / Claude Code login state.
                pass

        # === Initialize Flow and Observability Services ===
        # Initialize investigation flow for visualization
        flow_service.initialize_flow(agent.id)
        start_node = flow_service.add_node(
            agent.id, "user_input", "Start Investigation",
            {"agent_type": agent.request.agent_type.value if hasattr(agent.request, 'agent_type') else "sdk_audit"}
        )
        flow_service.update_node_status(agent.id, start_node.id, "completed")

        # Broadcast initial flow
        flow = flow_service.get_flow(agent.id)
        if flow:
            self._broadcast_message(WSMessage(
                type=WSMessageType.PROGRESS,
                agent_id=agent.id,
                data={"type": "flow_update", "flow": flow.to_dict()}
            ))

        # Set broadcast callback for observability service
        observability_service.set_broadcast_callback(self._broadcast_message)

        # Create ClaudeSDKOrchestrator first to get make_fresh_limits
        # We need a temporary orchestrator to get the limits factory
        agent_id = agent.id  # Capture for lambda closure

        # Track state for tool call correlation
        current_tool_calls: list[dict] = []
        current_request_id: str | None = None
        current_tool_node_id: str | None = None
        session_policy_template: str | None = None
        # Track findings as they're reported (for real-time broadcast)
        sdk_findings: list[Finding] = []
        finding_counter = [0]  # Use list to allow mutation in nested function

        def on_sdk_event(event: dict) -> None:
            """Broadcast SDK events as WebSocket messages with flow + observability integration."""
            nonlocal current_tool_calls, current_request_id, current_tool_node_id, sdk_findings, session_policy_template

            event_type_str = event.get("type", "sdk_event")
            if event_type_str == "finding":
                print(f"[Orchestrator DEBUG] Received 'finding' event from SDK orchestrator. Keys: {list(event.keys())}")

            # Map SDK event types to WSMessageType
            SDK_TO_WS_MAP = {
                # LLM request (prompt sent to Claude) -> blue in UI
                "llm_request": WSMessageType.LLM_REQUEST,
                # Text/thinking from Claude -> LLM response
                "agent_text": WSMessageType.LLM_RESPONSE,
                "agent_thinking": WSMessageType.LLM_RESPONSE,
                # Tool events -> Tool detail
                "tool_call": WSMessageType.TOOL_DETAIL,
                "tool_result": WSMessageType.TOOL_DETAIL,
                # System/session events -> Progress
                "system": WSMessageType.PROGRESS,
                "session_started": WSMessageType.PROGRESS,
                "turn_complete": WSMessageType.PROGRESS,
                "phase_change": WSMessageType.PROGRESS,
                # Findings
                "finding": WSMessageType.FINDING,
                # Errors stay as errors
                "error": WSMessageType.ERROR,
            }

            ws_type = SDK_TO_WS_MAP.get(event_type_str)
            if ws_type is None:
                try:
                    ws_type = WSMessageType(event_type_str)
                except ValueError:
                    ws_type = WSMessageType.LOG

            # Transform event data to match frontend expectations
            import uuid as uuid_mod
            from datetime import datetime as dt
            import json
            ws_data = dict(event)
            timestamp = dt.utcnow().isoformat()

            if event_type_str == "llm_request":
                prompt = event.get("prompt", "")
                turn = event.get("turn", 0)
                phase = event.get("phase", "scanner")

                requested_policy_template = (
                    "agents/claude_sdk_orchestrator_analyzer_policy.md"
                    if phase == "analyzer"
                    else "agents/claude_sdk_orchestrator_scanner_policy.md"
                )

                # Claude SDK system prompt is fixed at session start; track the policy template used
                # for that initial session so observability reflects what the model actually sees.
                if session_policy_template is None:
                    session_policy_template = requested_policy_template

                policy_text = load_prompt(session_policy_template)
                system_prompt = render_prompt(
                    "agents/claude_sdk_provider_system_prompt.md",
                    repo_path=agent.repo_path,
                    audit_policy=policy_text,
                )

                prompt_template = (
                    "agents/agent_orchestrator_initial_prompt.md" if turn == 1 else "(unknown)"
                )

                meta_lines = [
                    f"turn: {turn}",
                    f"phase: {phase}",
                    f"prompt_template: {prompt_template}",
                    "system_template: agents/claude_sdk_provider_system_prompt.md",
                    f"session_policy_template: {session_policy_template}",
                ]
                if requested_policy_template != session_policy_template:
                    meta_lines.append(f"requested_policy_template: {requested_policy_template}")
                    meta_lines.append("note: SDK system prompt is fixed at session start; policy does not change mid-session.")
                meta = "\n".join(meta_lines)

                current_request_id = observability_service.log_llm_request(
                    agent_id=agent_id,
                    messages=[
                        {"role": "meta", "content": meta},
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    tools_available=None,  # SDK manages tools internally
                    model="claude-sdk",
                    provider="claude_sdk",
                )

                return

            elif event_type_str == "agent_text":
                text = event.get("text", "")

                # Log to observability service
                if current_request_id and text:
                    observability_service.log_llm_response(
                        agent_id=agent_id,
                        request_id=current_request_id,
                        content=text,
                        tool_calls=current_tool_calls if current_tool_calls else None,
                        model="claude-sdk",
                        provider="claude_sdk",
                    )
                    current_tool_calls = []  # Reset for next response
                return

            elif event_type_str == "agent_thinking":
                # Don't emit raw SDK thinking blocks to the UI as LLM interactions; they don't match
                # the LLMInteraction schema and are not user-facing by default.
                return

            elif event_type_str == "tool_call":
                tool_id = event.get("id", "") or str(uuid_mod.uuid4())
                tool_name = event.get("name", "")
                tool_args = event.get("args", {})

                # Track for correlation with results
                current_tool_calls.append({
                    "id": tool_id,
                    "name": tool_name,
                    "args": tool_args,
                })

                # === Add Flow Node for Tool Call ===
                # Determine node type based on tool
                node_type = "tool_call"
                if tool_name in ("read_file", "list_directory"):
                    node_type = "code_read"
                elif tool_name in ("search_code", "grep_semantic"):
                    node_type = "search"
                elif tool_name in ("scan_repo_for_secrets", "dependency_audit"):
                    node_type = "scan"
                elif tool_name == "report_finding":
                    node_type = "finding"
                elif tool_name == "upsert_sink_signal":
                    kind = tool_args.get("kind", "")
                    node_type = "entry_point" if kind == "entry_point" else "dangerous_sink"

                # Create node label
                args_preview = str(tool_args)[:50]
                label = f"{tool_name}: {args_preview}..."

                # Add flow node
                tool_node = flow_service.add_node(
                    agent_id, node_type, label,
                    {"tool": tool_name, "args": tool_args}
                )
                flow_service.update_node_status(agent_id, tool_node.id, "running")
                current_tool_node_id = tool_node.id

                # Broadcast flow update
                flow = flow_service.get_flow(agent_id)
                if flow:
                    self._broadcast_message(WSMessage(
                        type=WSMessageType.PROGRESS,
                        agent_id=agent_id,
                        data={"type": "flow_update", "flow": flow.to_dict()}
                    ))
                return

            elif event_type_str == "tool_result":
                tool_use_id = event.get("tool_use_id", "") or str(uuid_mod.uuid4())
                result = event.get("result", "")
                is_error = event.get("is_error", False)

                # Find the corresponding tool_call
                tool_name = "unknown"
                tool_args = {}
                for tc in current_tool_calls:
                    if tc.get("id") == tool_use_id:
                        tool_name = tc.get("name", "unknown")
                        tool_args = tc.get("args", {})
                        break

                print(f"[Orchestrator DEBUG] tool_result: tool_use_id={tool_use_id}, tool_name={tool_name}, is_error={is_error}")

                # Log to observability service
                observability_service.log_tool_execution(
                    agent_id=agent_id,
                    tool_name=tool_name,
                    tool_call_id=tool_use_id,
                    arguments=tool_args,
                    result=result,
                    success=not is_error,
                    duration_ms=0,  # SDK doesn't provide timing
                    error_message=str(result) if is_error else None,
                )

                # === Update Flow Node Status ===
                if current_tool_node_id:
                    status = "failed" if is_error else "completed"
                    flow_service.update_node_status(agent_id, current_tool_node_id, status)

                    # === Add finding/signal nodes if applicable ===
                    # Tool names from MCP have the prefix "mcp__quickhack__"
                    if tool_name.endswith("report_finding") and not is_error:
                        try:
                            # Debug: Log the raw result for diagnosis
                            print(f"[Orchestrator] report_finding result type: {type(result)}")
                            if isinstance(result, dict):
                                print(f"[Orchestrator] result keys: {list(result.keys())}")
                            elif isinstance(result, str):
                                print(f"[Orchestrator] result preview: {result[:200]}")

                            # Strategy 0: Check if result is a list (MCP tool response format)
                            finding_data = None
                            if isinstance(result, list):
                                print("[Orchestrator] Result is list, extracting text (Strategy 0)")
                                for item in result:
                                    if isinstance(item, dict) and item.get("type") == "text":
                                        text = item.get("text", "")
                                        if text.strip().startswith("{"):
                                            try:
                                                parsed = json.loads(text)
                                                if isinstance(parsed, dict) and "finding" in parsed:
                                                    finding_data = parsed
                                                    print("[Orchestrator] Extracted finding from list text")
                                                    break
                                            except json.JSONDecodeError as jde:
                                                print(f"[Orchestrator] JSON parse failed: {jde}")
                            # Strategy 1: Check if result is a dict with top-level "finding" key
                            # (This is what our improved MCP tool returns)
                            elif isinstance(result, dict) and "finding" in result:
                                print("[Orchestrator] Found 'finding' at top level (Strategy 1)")
                                finding_data = result
                            # Strategy 2: Check if result is SDK response format with content array
                            elif isinstance(result, dict) and "content" in result:
                                print("[Orchestrator] Trying to extract from SDK content format (Strategy 2)")
                                content = result.get("content", [])
                                if isinstance(content, list):
                                    for item in content:
                                        if isinstance(item, dict) and item.get("type") == "text":
                                            text = item.get("text", "")
                                            if text.strip().startswith("{"):
                                                try:
                                                    parsed = json.loads(text)
                                                    if isinstance(parsed, dict) and "finding" in parsed:
                                                        finding_data = parsed
                                                        print("[Orchestrator] Extracted finding from content text")
                                                        break
                                                except json.JSONDecodeError as jde:
                                                    print(f"[Orchestrator] JSON parse failed: {jde}")
                            # Strategy 3: Try parsing result as JSON string
                            elif isinstance(result, str):
                                print("[Orchestrator] Trying to parse result as JSON string (Strategy 3)")
                                try:
                                    parsed = json.loads(result)
                                    if isinstance(parsed, dict) and "finding" in parsed:
                                        finding_data = parsed
                                        print("[Orchestrator] Parsed finding from JSON string")
                                except json.JSONDecodeError as jde:
                                    print(f"[Orchestrator] JSON parse failed: {jde}")
                            # Strategy 4: If result is already a dict, try using it directly
                            elif isinstance(result, dict):
                                print("[Orchestrator] Using result dict directly (Strategy 4)")
                                finding_data = result

                            # Extract the finding
                            if isinstance(finding_data, dict) and "finding" in finding_data:
                                raw_finding = finding_data["finding"]
                                severity_str = raw_finding.get("severity", "medium")
                                title = raw_finding.get("title", "Finding")

                                print(f"[Orchestrator] Successfully extracted finding: {title} ({severity_str})")

                                # Add finding node to flow
                                finding_node = flow_service.add_node(
                                    agent_id, "finding", f"{severity_str.upper()}: {title}",
                                    {"severity": severity_str, "finding": raw_finding}
                                )
                                flow_service.update_node_status(agent_id, finding_node.id, "completed")

                                # === Create Finding object and broadcast to Findings panel ===
                                finding_counter[0] += 1
                                try:
                                    # Map severity string to Severity enum
                                    from models.schemas import Severity
                                    severity_map = {
                                        "critical": Severity.CRITICAL,
                                        "high": Severity.HIGH,
                                        "medium": Severity.MEDIUM,
                                        "low": Severity.LOW,
                                        "info": Severity.INFO,
                                    }
                                    severity_enum = severity_map.get(severity_str.lower(), Severity.MEDIUM)

                                    # Convert source_trace to list if it's a string
                                    source_trace = raw_finding.get("source_trace")
                                    if isinstance(source_trace, str):
                                        source_trace = [source_trace] if source_trace else None
                                    elif source_trace is None:
                                        source_trace = None
                                    # else it's already a list or will be validated by Pydantic

                                    finding_obj = Finding(
                                        id=f"{agent_id}-finding-{finding_counter[0]}",
                                        agent_id=agent_id,
                                        repo_id=agent.repo_id,
                                        severity=severity_enum,
                                        title=title,
                                        description=raw_finding.get("description", ""),
                                        file_path=raw_finding.get("file_path", ""),
                                        line_start=raw_finding.get("line_start", 1),
                                        line_end=raw_finding.get("line_end"),
                                        code_snippet=raw_finding.get("vulnerable_code", ""),
                                        vulnerable_code=raw_finding.get("vulnerable_code", ""),
                                        vulnerability_type=raw_finding.get("vulnerability_type", "Unknown"),
                                        cwe_id=raw_finding.get("cwe_id"),
                                        attack_scenario=raw_finding.get("attack_scenario"),
                                        proof_of_concept=raw_finding.get("proof_of_concept"),
                                        recommended_fix=raw_finding.get("recommended_fix"),
                                        confidence=raw_finding.get("confidence", 0.5),
                                        source_trace=source_trace,
                                        created_at=datetime.utcnow(),
                                        metadata={"source": "sdk_audit"},
                                    )
                                    sdk_findings.append(finding_obj)

                                    # Broadcast finding to frontend
                                    self._broadcast_message(WSMessage(
                                        type=WSMessageType.FINDING,
                                        agent_id=agent_id,
                                        data=finding_obj.model_dump(mode='json'),
                                    ))
                                    print(f"[Orchestrator] ✓ Successfully broadcast finding to UI: {title} ({severity_str})")
                                except Exception as finding_err:
                                    print(f"[Orchestrator] ✗ Failed to create/broadcast finding: {finding_err}")
                                    import traceback
                                    traceback.print_exc()
                            else:
                                print(f"[Orchestrator] ✗ Could not extract finding from result. finding_data type: {type(finding_data)}, has 'finding': {isinstance(finding_data, dict) and 'finding' in finding_data if finding_data else False}")
                        except Exception as e:
                            print(f"[Orchestrator] ✗ Failed to process finding: {e}")
                            import traceback
                            traceback.print_exc()

                    elif tool_name.endswith("upsert_sink_signal") and not is_error:
                        try:
                            signal_data = json.loads(result) if isinstance(result, str) else result
                            if isinstance(signal_data, dict) and "signal" in signal_data:
                                signal = signal_data["signal"]
                                kind = signal.get("kind", "sink")
                                label = signal.get("label", "Signal")
                                node_type = "entry_point" if kind == "entry_point" else "dangerous_sink"
                                signal_node = flow_service.add_node(
                                    agent_id, node_type, label,
                                    {"signal": signal}
                                )
                                flow_service.update_node_status(agent_id, signal_node.id, "completed")
                        except Exception as e:
                            print(f"[Orchestrator] Failed to add signal node: {e}")

                    current_tool_node_id = None

                    # Broadcast flow update
                    flow = flow_service.get_flow(agent_id)
                    if flow:
                        self._broadcast_message(WSMessage(
                            type=WSMessageType.PROGRESS,
                            agent_id=agent_id,
                            data={"type": "flow_update", "flow": flow.to_dict()}
                        ))
                return

            # Handle "finding" events from SDK orchestrator
            elif event_type_str == "finding":
                try:
                    raw_finding = event
                    # Remove the 'type' key to get just the finding data
                    raw_finding_data = {k: v for k, v in raw_finding.items() if k != 'type'}

                    severity_str = raw_finding_data.get("severity", "medium")
                    title = raw_finding_data.get("title", "Finding")

                    print(f"[Orchestrator] Processing 'finding' event: {title} ({severity_str})")

                    # Map severity string to Severity enum
                    from models.schemas import Severity
                    severity_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                        "info": Severity.INFO,
                    }
                    severity_enum = severity_map.get(severity_str.lower(), Severity.MEDIUM)

                    # Convert source_trace to list if it's a string
                    source_trace = raw_finding_data.get("source_trace")
                    if isinstance(source_trace, str):
                        source_trace = [source_trace] if source_trace else None
                    elif source_trace is None:
                        source_trace = None

                    finding_counter[0] += 1
                    finding_obj = Finding(
                        id=f"{agent_id}-finding-{finding_counter[0]}",
                        agent_id=agent_id,
                        repo_id=agent.repo_id,
                        severity=severity_enum,
                        title=title,
                        description=raw_finding_data.get("description", ""),
                        file_path=raw_finding_data.get("file_path", ""),
                        line_start=raw_finding_data.get("line_start", 1),
                        line_end=raw_finding_data.get("line_end"),
                        code_snippet=raw_finding_data.get("vulnerable_code", ""),
                        vulnerable_code=raw_finding_data.get("vulnerable_code", ""),
                        vulnerability_type=raw_finding_data.get("vulnerability_type", "Unknown"),
                        cwe_id=raw_finding_data.get("cwe_id"),
                        attack_scenario=raw_finding_data.get("attack_scenario"),
                        proof_of_concept=raw_finding_data.get("proof_of_concept"),
                        recommended_fix=raw_finding_data.get("recommended_fix"),
                        confidence=raw_finding_data.get("confidence", 0.5),
                        source_trace=source_trace,
                        created_at=datetime.utcnow(),
                        metadata={"source": "sdk_audit"},
                    )
                    sdk_findings.append(finding_obj)

                    # Broadcast finding to frontend
                    self._broadcast_message(WSMessage(
                        type=WSMessageType.FINDING,
                        agent_id=agent_id,
                        data=finding_obj.model_dump(mode='json'),
                    ))
                    print(f"[Orchestrator] ✓ Successfully broadcast finding from event: {title} ({severity_str})")
                except Exception as e:
                    print(f"[Orchestrator] ✗ Failed to process finding event: {e}")
                    import traceback
                    traceback.print_exc()
                return

            self._broadcast_message(
                WSMessage(type=ws_type, agent_id=agent_id, data=ws_data)
            )

        sdk_orchestrator = ClaudeSDKOrchestrator(
            scan_tier=scan_tier,
            on_ws_event=on_sdk_event,
            provider=None,  # Will be set after provider is created
            tool_core=None,  # Will be set after tool_core is created
        )

        # Reuse cache from agent if it was already created, otherwise create new
        cache = getattr(agent, '_tool_cache', None)

        # Create ToolCore with limits factory from orchestrator
        tool_core = ToolCore(
            repo_path=agent.repo_path,
            project_id=agent.repo_id,
            agent_id=agent_id,
            get_scan_limits=sdk_orchestrator.make_fresh_limits,
            cache=cache,
        )

        # Create ClaudeSDKProvider
        provider_config = {
            "model": config.model if config else "claude-sonnet-4-20250514",
            "api_key": sdk_api_key,
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
                    finding_payload = dict(finding_data) if isinstance(finding_data, dict) else {}
                    finding_payload.setdefault("metadata", {})
                    finding = Finding(
                        id=f"{agent.id}-{len(findings)}",
                        agent_id=agent.id,
                        repo_id=agent.repo_id,
                        created_at=datetime.utcnow(),
                        **finding_payload,
                    )
                    findings.append(finding)
                except Exception as e:
                    print(f"[Orchestrator] Failed to convert finding: {e}")

            # Use sdk_findings (broadcast in real-time) if available, else use result findings
            raw_findings = sdk_findings if sdk_findings else findings
            print(f"[Orchestrator] Raw findings: {len(raw_findings)}")

            # === Triage findings ===
            triaged_findings = raw_findings
            reportable_count = len(raw_findings)

            # Check both config setting AND schema availability
            from database.schema_checker import is_triage_available
            triage_ready = settings.triage_enabled and is_triage_available()

            if triage_ready and raw_findings:
                try:
                    print(f"[Orchestrator] Running triage on {len(raw_findings)} findings...")
                    from models.schemas import BudgetConfig

                    budgets = BudgetConfig(
                        batch_ms=settings.triage_batch_budget_ms,
                        per_finding_ms=settings.triage_per_finding_budget_ms,
                        max_evidence_bytes=settings.triage_max_evidence_bytes,
                        max_snippet_lines=settings.triage_max_snippet_lines
                    )

                    # Run triage in worker thread (evidence gathering + classification)
                    triage_result = await asyncio.to_thread(
                        triage_service.triage_findings,
                        repo_root=agent.repo_path,
                        findings=raw_findings,
                        policy_version=settings.triage_policy_version,
                        budgets=budgets
                    )

                    # Assert no findings dropped
                    assert triage_result.triaged_count == len(raw_findings), \
                        f"Triage dropped findings: {len(raw_findings)} input vs {triage_result.triaged_count} output"

                    print(f"[Orchestrator] Triage complete: {triage_result.metrics.reportable_count}/{triage_result.metrics.triaged_count} reportable")
                    print(f"[Orchestrator] By disposition: {triage_result.metrics.by_disposition}")

                    # Use triaged findings
                    triaged_findings = triage_result.triaged_findings
                    reportable_count = triage_result.metrics.reportable_count

                    # Track triage gateway in flow (back on main thread)
                    if hasattr(agent, '_tool_core') and agent._tool_core:
                        try:
                            finding_refs = [
                                (f.id, f.disposition.value if f.disposition else "unknown")
                                for f in triaged_findings[:50]
                            ]
                            await agent._tool_core.track_triage_gate(
                                batch_id=triage_result.batch_id,
                                raw_count=triage_result.metrics.raw_count,
                                triaged_count=triage_result.metrics.triaged_count,
                                reportable_count=triage_result.metrics.reportable_count,
                                by_disposition=triage_result.metrics.by_disposition,
                                policy_version=settings.triage_policy_version,
                                finding_refs=finding_refs
                            )
                            print(f"[Orchestrator] Tracked triage gateway node in flow")
                        except Exception as flow_err:
                            print(f"[Orchestrator] Failed to track triage gateway: {flow_err}")

                except Exception as triage_err:
                    print(f"[Orchestrator] Triage failed, using raw findings: {triage_err}")
                    import traceback
                    traceback.print_exc()
                    # Fallback to raw findings on error
                    triaged_findings = raw_findings
                    reportable_count = len(raw_findings)

            agent.findings = triaged_findings
            print(f"[Orchestrator] Total findings: {len(triaged_findings)} ({reportable_count} reportable)")

            # === Add completion node to flow ===
            completion_status = "completed" if result.get("success", True) else "failed"
            flow_service.add_node(
                agent.id, "analysis", f"Audit {completion_status.title()}",
                {
                    "findings_count": reportable_count,  # Show reportable count
                    "total_findings": len(triaged_findings),  # Total including filtered
                    "elapsed_s": result.get("elapsed_s", 0)
                }
            )

            # Broadcast final flow update
            flow = flow_service.get_flow(agent.id)
            if flow:
                self._broadcast_message(WSMessage(
                    type=WSMessageType.PROGRESS,
                    agent_id=agent.id,
                    data={"type": "flow_update", "flow": flow.to_dict()}
                ))

            # === Generate report on successful completion ===
            if result.get("success", True):
                try:
                    report_service.generate_report(agent)
                    print(f"[Orchestrator] Generated report for SDK agent {agent.id}")

                    # Broadcast REPORT_READY so frontend knows report is available
                    self._broadcast_message(WSMessage(
                        type=WSMessageType.REPORT_READY,
                        agent_id=agent.id,
                        data={
                            "agent_id": agent.id,
                            "repo_id": agent.repo_id,
                            "findings_count": reportable_count,
                            "total_findings": len(triaged_findings),
                            "severity_summary": {
                                "critical": sum(1 for f in triaged_findings if f.severity.value == "critical"),
                                "high": sum(1 for f in triaged_findings if f.severity.value == "high"),
                                "medium": sum(1 for f in triaged_findings if f.severity.value == "medium"),
                                "low": sum(1 for f in triaged_findings if f.severity.value == "low"),
                                "info": sum(1 for f in triaged_findings if f.severity.value == "info"),
                            },
                            "message": f"Security audit complete. Found {reportable_count} reportable findings ({len(triaged_findings)} total).",
                        }
                    ))
                    print(f"[Orchestrator] Broadcast REPORT_READY for SDK agent {agent.id}")
                except Exception as e:
                    print(f"[Orchestrator] Failed to generate report: {e}")

            # If the SDK run failed, propagate an error so the agent is marked FAILED.
            if not result.get("success", True):
                raise RuntimeError(result.get("error_message") or "Claude SDK audit failed")

            agent.status = AgentStatus.COMPLETED

            return findings

        finally:
            # Clean up provider
            await provider.close()

    async def _run_codex_cli_agent(self, agent: BaseAgent) -> list[Finding]:
        """Run an agent using the local Codex CLI provider (codex exec/resume).

        This implements a budget-governed multi-turn loop and streams events to
        the existing WebSocket/observability pipeline.
        """
        print(f"[Orchestrator] Running Codex CLI agent {agent.id}")

        # Update agent status to RUNNING
        agent.status = AgentStatus.RUNNING
        agent.started_at = datetime.utcnow()
        self._broadcast_message(
            WSMessage(type=WSMessageType.AGENT_STATUS, agent_id=agent.id, data={"status": "running"})
        )

        config = agent.request.provider_config
        if config is None:
            raise ValueError("codex_cli provider requires provider_config")

        # Resolve scan budget + time floor rules.
        scan_budget = resolve_scan_budget(
            scan_tier=getattr(agent.request, "scan_tier", None),
            time_budget_seconds=getattr(agent.request, "time_budget_seconds", None),
        )
        budget_s = float(scan_budget.time_budget_seconds)
        from services.claude_sdk_orchestrator import SCAN_TIER_FLOORS

        time_floor_s = float(SCAN_TIER_FLOORS.get(scan_budget.scan_tier, 0))
        time_floor_s = min(time_floor_s, budget_s)

        start_time = time.monotonic()
        phase = "scanner"
        turn_count = 0
        consecutive_no_tool_turns = 0

        def elapsed_s() -> float:
            return time.monotonic() - start_time

        def remaining_s() -> float:
            return max(0.0, budget_s - elapsed_s())

        def time_floor_satisfied() -> bool:
            return elapsed_s() >= time_floor_s

        codex_path = (getattr(config, "codex_path", None) or "").strip() or "codex"

        provider = CodexCLIProvider(
            repo_path=str(agent.repo_path),
            project_id=str(agent.repo_id),
            agent_id=str(agent.id),
            model=str(config.model),
            codex_path=codex_path,
        )
        agent._codex_provider = provider

        # Resume session if the agent already has one (pause/resume or persisted state reload).
        resume_session_id = getattr(agent, "_codex_session_id", None)
        await provider.start_session(resume_session_id=resume_session_id)

        # Threat model prompt block (authoritative JSON + summary). If the project record
        # isn't available (e.g., some tests), fall back to AB preset-derived profile.
        threat_model_block = ""
        threat_model_profile_for_gating: dict | None = None
        try:
            from models.threat_model_profile import ThreatModelProfile, preset_to_profile

            project = None
            try:
                project = await project_service.get_project(str(agent.repo_id))
            except Exception:
                project = None

            if project and project.threat_model_profile:
                threat_model_profile_for_gating = project.threat_model_profile
                threat_model_block = build_threat_model_prompt_block(
                    threat_model_preset=(project.threat_model_preset or project.threat_model),
                    profile_source=(project.profile_source or "migrated"),
                    profile_review_status=(project.profile_review_status or "unreviewed"),
                    profile_mapping_version=project.profile_mapping_version,
                    input_channel_semantics_version=project.input_channel_semantics_version,
                    prompt_threat_model_block_version=project.prompt_threat_model_block_version,
                    threat_model_profile=ThreatModelProfile(**project.threat_model_profile),
                )
            else:
                fallback_profile = preset_to_profile("AB")
                threat_model_profile_for_gating = fallback_profile.model_dump(mode="json")
                threat_model_block = build_threat_model_prompt_block(
                    threat_model_preset="AB",
                    profile_source="migrated",
                    profile_review_status="unreviewed",
                    profile_mapping_version=1,
                    input_channel_semantics_version=1,
                    prompt_threat_model_block_version=1,
                    threat_model_profile=fallback_profile,
                )
        except Exception:
            threat_model_block = ""
            threat_model_profile_for_gating = None

        # Set broadcast callback for observability service.
        observability_service.set_broadcast_callback(self._broadcast_message)

        # Track state for tool call correlation and finding extraction.
        current_tool_calls: list[dict] = []
        current_request_id: str | None = None
        current_tool_node_id: str | None = None
        codex_findings: list[Finding] = []
        finding_counter = [0]
        last_triaged_count = 0
        files_read: list[str] = []

        import json as json_mod
        import uuid as uuid_mod

        def normalize_tool_name(tool_name: str) -> str:
            if tool_name.startswith("mcp__"):
                # mcp__quickhack__read_file -> read_file
                parts = tool_name.split("__", 2)
                if len(parts) == 3:
                    return parts[2]
            return tool_name

        def on_codex_event(event: dict) -> None:
            nonlocal current_request_id, current_tool_node_id, consecutive_no_tool_turns
            event_type_str = event.get("type", "codex_event")

            if event_type_str == "session_started":
                session_id = event.get("session_id")
                if isinstance(session_id, str) and session_id:
                    agent._codex_session_id = session_id
                self._broadcast_message(
                    WSMessage(
                        type=WSMessageType.PROGRESS,
                        agent_id=agent.id,
                        data={"type": "session_started", "session_id": session_id},
                    )
                )
                return

            if event_type_str == "llm_request":
                prompt = event.get("prompt", "")
                turn = event.get("turn", 0)
                phase_name = event.get("phase", phase)

                meta_lines = [
                    f"turn: {turn}",
                    f"phase: {phase_name}",
                    f"budget_s: {budget_s:.0f}",
                    f"remaining_s: {remaining_s():.0f}",
                    f"time_floor_s: {time_floor_s:.0f}",
                ]
                meta = "\n".join(meta_lines)

                current_request_id = observability_service.log_llm_request(
                    agent_id=agent.id,
                    messages=[
                        {"role": "meta", "content": meta},
                        {"role": "user", "content": prompt},
                    ],
                    tools_available=[
                        "read_file",
                        "list_directory",
                        "grep_semantic",
                        "scan_repo_for_secrets",
                        "dependency_audit",
                        "analyze_ast",
                        "trace_dataflow",
                        "track_file_analysis",
                        "track_function_discovered",
                        "track_call_chain",
                        "track_sink_identified",
                        "track_entry_point",
                        "upsert_sink_signal",
                        "report_finding",
                        "promote_finding",
                    ],
                    model=str(config.model),
                    provider="codex_cli",
                )
                return

            if event_type_str == "agent_text":
                text = event.get("text", "")
                if current_request_id and isinstance(text, str) and text:
                    observability_service.log_llm_response(
                        agent_id=agent.id,
                        request_id=current_request_id,
                        content=text,
                        tool_calls=current_tool_calls if current_tool_calls else None,
                        model=str(config.model),
                        provider="codex_cli",
                    )
                    current_tool_calls.clear()
                return

            if event_type_str == "tool_call":
                tool_id = event.get("id", "") or event.get("tool_use_id", "")
                tool_id = tool_id or str(uuid_mod.uuid4())
                tool_name = str(event.get("name") or "")
                tool_args = event.get("args", {}) if isinstance(event.get("args"), dict) else {}

                current_tool_calls.append({"id": tool_id, "name": tool_name, "args": tool_args})

                normalized_name = normalize_tool_name(tool_name)
                node_type = "tool_call"
                if normalized_name in ("read_file", "list_directory"):
                    node_type = "code_read"
                    if normalized_name == "read_file":
                        path = tool_args.get("path")
                        if isinstance(path, str) and path:
                            files_read.append(path)
                elif normalized_name in ("search_code", "grep_semantic"):
                    node_type = "search"
                elif normalized_name in ("scan_repo_for_secrets", "dependency_audit"):
                    node_type = "scan"
                elif normalized_name in ("report_finding", "promote_finding"):
                    node_type = "finding"
                elif normalized_name == "upsert_sink_signal":
                    kind = tool_args.get("kind", "")
                    node_type = "entry_point" if kind == "entry_point" else "dangerous_sink"
                elif normalized_name.startswith("track_"):
                    node_type = "flow"

                args_preview = str(tool_args)[:50]
                label = f"{normalized_name}: {args_preview}..."

                tool_node = flow_service.add_node(agent.id, node_type, label, {"tool": normalized_name, "args": tool_args})
                flow_service.update_node_status(agent.id, tool_node.id, "running")
                current_tool_node_id = tool_node.id

                flow = flow_service.get_flow(agent.id)
                if flow:
                    self._broadcast_message(
                        WSMessage(
                            type=WSMessageType.PROGRESS,
                            agent_id=agent.id,
                            data={"type": "flow_update", "flow": flow.to_dict()},
                        )
                    )
                return

            if event_type_str == "tool_result":
                tool_use_id = event.get("tool_use_id", "") or str(uuid_mod.uuid4())
                result = event.get("result", "")
                is_error = bool(event.get("is_error", False))

                tool_name = "unknown"
                tool_args: dict = {}
                for tc in current_tool_calls:
                    if tc.get("id") == tool_use_id:
                        tool_name = tc.get("name", "unknown")
                        tool_args = tc.get("args", {})
                        break

                normalized_name = normalize_tool_name(tool_name)

                observability_service.log_tool_execution(
                    agent_id=agent.id,
                    tool_name=normalized_name,
                    tool_call_id=tool_use_id,
                    arguments=tool_args,
                    result=result,
                    success=not is_error,
                    duration_ms=0,
                    error_message=str(result) if is_error else None,
                )

                if current_tool_node_id:
                    status = "failed" if is_error else "completed"
                    flow_service.update_node_status(agent.id, current_tool_node_id, status)

                if normalized_name in ("report_finding", "promote_finding") and not is_error:
                    finding_data = None
                    # Strategy 1: direct dict with finding.
                    if isinstance(result, dict) and "finding" in result:
                        finding_data = result
                    # Strategy 2: MCP-style dict with content array.
                    elif isinstance(result, dict) and "content" in result:
                        content = result.get("content", [])
                        if isinstance(content, list):
                            for item in content:
                                if isinstance(item, dict) and item.get("type") == "text":
                                    text = item.get("text", "")
                                    if isinstance(text, str) and text.strip().startswith("{"):
                                        try:
                                            parsed = json_mod.loads(text)
                                            if isinstance(parsed, dict) and "finding" in parsed:
                                                finding_data = parsed
                                                break
                                        except json_mod.JSONDecodeError:
                                            continue
                    # Strategy 3: JSON string.
                    elif isinstance(result, str):
                        try:
                            parsed = json_mod.loads(result)
                            if isinstance(parsed, dict) and "finding" in parsed:
                                finding_data = parsed
                        except json_mod.JSONDecodeError:
                            finding_data = None

                    if isinstance(finding_data, dict) and isinstance(finding_data.get("finding"), dict):
                        raw_finding = finding_data["finding"]
                        try:
                            from models.schemas import Severity

                            severity_str = str(raw_finding.get("severity", "medium"))
                            severity_enum = Severity(severity_str) if severity_str in Severity._value2member_map_ else Severity.MEDIUM

                            finding_counter[0] += 1
                            metadata_from_tool = raw_finding.get("metadata") if isinstance(raw_finding.get("metadata"), dict) else {}
                            merged_metadata = dict(metadata_from_tool)
                            merged_metadata["source"] = "codex_cli"
                            finding_obj = Finding(
                                id=f"{agent.id}-finding-{finding_counter[0]}",
                                agent_id=agent.id,
                                repo_id=agent.repo_id,
                                severity=severity_enum,
                                title=str(raw_finding.get("title", "Finding")),
                                description=str(raw_finding.get("description", "")),
                                file_path=str(raw_finding.get("file_path", "")),
                                line_start=int(raw_finding.get("line_start", 1) or 1),
                                line_end=raw_finding.get("line_end"),
                                code_snippet=raw_finding.get("vulnerable_code", ""),
                                vulnerable_code=raw_finding.get("vulnerable_code", ""),
                                vulnerability_type=str(raw_finding.get("vulnerability_type", "Unknown")),
                                cwe_id=raw_finding.get("cwe_id"),
                                attack_scenario=raw_finding.get("attack_scenario"),
                                proof_of_concept=raw_finding.get("proof_of_concept"),
                                recommended_fix=raw_finding.get("recommended_fix"),
                                confidence=float(raw_finding.get("confidence", 0.5) or 0.5),
                                source_trace=raw_finding.get("source_trace"),
                                created_at=datetime.utcnow(),
                                metadata=merged_metadata,
                            )
                            codex_findings.append(finding_obj)
                            agent.findings = codex_findings

                            self._broadcast_message(
                                WSMessage(
                                    type=WSMessageType.FINDING,
                                    agent_id=agent.id,
                                    data=finding_obj.model_dump(mode="json"),
                                )
                            )
                        except Exception as e:
                            print(f"[Orchestrator] Failed to create/broadcast codex finding: {e}")

                current_tool_node_id = None
                flow = flow_service.get_flow(agent.id)
                if flow:
                    self._broadcast_message(
                        WSMessage(type=WSMessageType.PROGRESS, agent_id=agent.id, data={"type": "flow_update", "flow": flow.to_dict()})
                    )
                return

            if event_type_str == "turn_complete":
                self._broadcast_message(
                    WSMessage(
                        type=WSMessageType.PROGRESS,
                        agent_id=agent.id,
                        data={
                            "type": "turn_complete",
                            "turn": turn_count,
                            "phase": phase,
                            "remaining_s": remaining_s(),
                            "session_id": event.get("session_id") or getattr(agent, "_codex_session_id", None),
                        },
                    )
                )
                return

            if event_type_str == "error":
                self._broadcast_message(
                    WSMessage(type=WSMessageType.ERROR, agent_id=agent.id, data={"error": event.get("message", "Unknown error")})
                )
                return

        def build_turn_prompt(*, base: str, phase_name: str, floor_remaining_s: float) -> str:
            base_system = load_prompt("base/base_prompt.md")
            repo_info = f"Repository root: {agent.repo_path}"
            try:
                entries = sorted(Path(agent.repo_path).iterdir())
                top = []
                for entry in entries[:25]:
                    suffix = "/" if entry.is_dir() else ""
                    top.append(entry.name + suffix)
                if top:
                    repo_info += "\nTop-level entries: " + ", ".join(top)
            except Exception:
                pass

            if phase_name == "analyzer":
                scanner_context_parts = []
                if files_read:
                    scanner_context_parts.append("Files read (sample):")
                    for p in files_read[:20]:
                        scanner_context_parts.append(f"- {p}")
                if codex_findings:
                    scanner_context_parts.append(f"\nFindings reported so far: {len(codex_findings)}")
                scanner_context = "\n".join(scanner_context_parts) if scanner_context_parts else "UNKNOWN (single-model mode)"
                phase_system = render_prompt("agents/analyzer_system_prompt.md", scanner_context=scanner_context)
            else:
                phase_system = render_prompt("agents/scanner_system_prompt.md", repo_info=repo_info)

            profile_text = ""
            try:
                if agent.agent_type == AgentType.DEEP_AUDIT:
                    profile_text = load_prompt("agents/profile_deep_audit_mode.md")
                elif agent.agent_type == AgentType.ULTRA_STRICT:
                    profile_text = load_prompt("agents/profile_ultra_strict_mode.md")
                elif agent.agent_type == AgentType.STRICT_ANALYSIS:
                    profile_text = load_prompt("agents/profile_strict_mode.md")
            except Exception:
                profile_text = ""
            tool_list = "\n".join(
                [
                    "- read_file",
                    "- list_directory",
                    "- grep_semantic",
                    "- scan_repo_for_secrets",
                    "- dependency_audit",
                    "- analyze_ast",
                    "- trace_dataflow",
                    "- track_file_analysis",
                    "- track_function_discovered",
                    "- track_call_chain",
                    "- track_sink_identified",
                    "- track_entry_point",
                    "- upsert_sink_signal",
                    "- report_finding",
                    "- promote_finding",
                ]
            )
            guardrails = "\n".join(
                [
                    "CRITICAL GUARDRAILS:",
                    "- No web requests, no web search, no fetching dependencies.",
                    "- Do NOT attempt to run shell commands; use only the MCP tools above.",
                    "- Only claim vulnerabilities with concrete evidence from tool outputs.",
                    "- Use upsert_sink_signal for leads; use report_finding only for confirmed issues.",
                ]
            )
            floor_note = ""
            if floor_remaining_s > 0:
                floor_note = f"\nMinimum scan time remaining: {floor_remaining_s:.0f}s. Keep working."

            return "\n\n".join(
                [
                    f"[Phase: {phase_name}]",
                    "Base system:\n" + base_system,
                    ("Threat model:\n" + threat_model_block) if threat_model_block else "",
                    "Phase system:\n" + phase_system,
                    ("Audit profile:\n" + profile_text) if profile_text else "",
                    "Available tools:\n" + tool_list,
                    guardrails + floor_note,
                    base,
                ]
            )

        # Initialize flow root (best-effort).
        flow_service.initialize_flow(agent.id)
        flow_service.add_node(agent.id, "user_input", "Start codex_cli audit", {"provider": "codex_cli"})

        initial_prompt = self._build_initial_audit_prompt(agent)
        current_prompt = initial_prompt
        last_turn_had_tools = False

        try:
            while remaining_s() > 0 and not getattr(agent, "_cancelled", False):
                # Pause handling: interrupt Codex and wait for resume.
                if agent.status == AgentStatus.PAUSED:
                    try:
                        provider.set_cancelled(True)
                        await provider.interrupt()
                    except Exception:
                        pass
                    # Persist state snapshot while paused (best-effort).
                    if hasattr(agent, "get_state_snapshot"):
                        try:
                            snapshot = agent.get_state_snapshot()
                            persistence_service.save_agent_state(snapshot)
                        except Exception:
                            pass
                    while agent.status == AgentStatus.PAUSED and not getattr(agent, "_cancelled", False):
                        await asyncio.sleep(0.2)
                    provider.set_cancelled(False)
                    continue

                turn_count += 1

                # Determine per-turn tool runtime budget (25% of remaining time, capped).
                turn_limits_s = max(5.0, min(60.0, remaining_s() * 0.25))
                provider.write_turn_limits(max_runtime_s=turn_limits_s)
                provider.set_cancelled(False)

                floor_remaining = max(0.0, time_floor_s - elapsed_s())
                prompt_for_turn = build_turn_prompt(base=current_prompt, phase_name=phase, floor_remaining_s=floor_remaining)

                on_codex_event({"type": "llm_request", "prompt": prompt_for_turn, "turn": turn_count, "phase": phase})

                # Collect per-turn stats for steering.
                turn_text_parts: list[str] = []
                turn_tool_calls: list[dict] = []

                def collecting_event(ev: dict) -> None:
                    # Capture tool call density for steering heuristics.
                    if ev.get("type") == "tool_call":
                        turn_tool_calls.append(ev)
                    if ev.get("type") == "agent_text":
                        text = ev.get("text")
                        if isinstance(text, str) and text:
                            turn_text_parts.append(text)
                    on_codex_event(ev)

                await provider.run_turn(prompt=prompt_for_turn, on_event=collecting_event)

                last_turn_had_tools = len(turn_tool_calls) > 0
                if last_turn_had_tools:
                    consecutive_no_tool_turns = 0
                else:
                    consecutive_no_tool_turns += 1

                turn_text = "\n".join(turn_text_parts)

                # After each turn, triage any newly reported findings (strict evidence-based).
                if settings.triage_enabled and len(codex_findings) > last_triaged_count:
                    new_findings = codex_findings[last_triaged_count:]
                    try:
                        from models.schemas import BudgetConfig

                        # Bound triage work to a small slice of remaining time to avoid overruns.
                        remaining_ms = int(remaining_s() * 1000)
                        batch_ms = int(
                            min(
                                settings.triage_batch_budget_ms,
                                max(250, remaining_ms * 0.05),
                            )
                        )
                        budgets = BudgetConfig(
                            batch_ms=batch_ms,
                            per_finding_ms=min(settings.triage_per_finding_budget_ms, batch_ms),
                            max_evidence_bytes=settings.triage_max_evidence_bytes,
                            max_snippet_lines=settings.triage_max_snippet_lines,
                        )

                        triage_result = await asyncio.to_thread(
                            triage_service.triage_findings,
                            repo_root=str(agent.repo_path),
                            findings=new_findings,
                            policy_version=settings.triage_policy_version,
                            budgets=budgets,
                            threat_model_profile=threat_model_profile_for_gating,
                        )

                        codex_findings[last_triaged_count:] = triage_result.triaged_findings
                        agent.findings = codex_findings
                        last_triaged_count = len(codex_findings)

                        self._broadcast_message(
                            WSMessage(
                                type=WSMessageType.PROGRESS,
                                agent_id=agent.id,
                                data={
                                    "type": "triage_complete",
                                    "raw_count": triage_result.metrics.raw_count,
                                    "triaged_count": triage_result.metrics.triaged_count,
                                    "reportable_count": triage_result.metrics.reportable_count,
                                    "by_disposition": triage_result.metrics.by_disposition,
                                },
                            )
                        )
                    except Exception as triage_err:
                        # Best-effort: keep raw findings if triage fails.
                        print(f"[Orchestrator] Codex triage failed: {triage_err}")
                        last_triaged_count = len(codex_findings)

                # Persist state after each turn for crash resilience (best-effort).
                if hasattr(agent, "get_state_snapshot"):
                    try:
                        snapshot = agent.get_state_snapshot()
                        persistence_service.save_agent_state(snapshot)
                    except Exception:
                        pass

                # If scanner phase is explicitly complete, hand off even if no findings were reported.
                if phase == "scanner" and _codex_text_signals_handoff_to_analyzer(turn_text):
                    phase = "analyzer"
                    self._broadcast_message(
                        WSMessage(type=WSMessageType.PROGRESS, agent_id=agent.id, data={"type": "phase_change", "phase": phase})
                    )
                    current_prompt = render_prompt(
                        "agents/claude_sdk_orchestrator_analyzer_prompt.md",
                        finding_count=str(len(codex_findings)),
                    )
                    continue

                # Detect completion signal.
                if _codex_text_signals_done(turn_text):
                    if time_floor_satisfied() or time_floor_s <= 0:
                        break
                    current_prompt = render_prompt(
                        "agents/claude_sdk_orchestrator_steering_prompt_before_floor.md",
                        floor_remaining_s=f"{max(0.0, time_floor_s - elapsed_s()):.0f}",
                    )
                    continue

                # Transition to analyzer if we have findings or we're deep into the budget.
                if phase == "scanner" and (len(codex_findings) > 0 or elapsed_s() > budget_s * 0.5):
                    phase = "analyzer"
                    self._broadcast_message(
                        WSMessage(type=WSMessageType.PROGRESS, agent_id=agent.id, data={"type": "phase_change", "phase": phase})
                    )
                    current_prompt = render_prompt(
                        "agents/claude_sdk_orchestrator_analyzer_prompt.md",
                        finding_count=str(len(codex_findings)),
                    )
                    continue

                if consecutive_no_tool_turns >= 3:
                    current_prompt = (
                        "You have not used tools recently. Use MCP tools to gather evidence and expand coverage."
                    )
                    continue

                current_prompt = render_prompt(
                    "agents/claude_sdk_orchestrator_continue_prompt.md",
                    remaining_mins=f"{remaining_s() / 60:.1f}",
                )

            raw_findings = codex_findings

            # === Triage findings (best-effort, same gating as SDK path) ===
            triaged_findings = raw_findings
            reportable_count = len(raw_findings)

            from database.schema_checker import is_triage_available

            triage_ready = settings.triage_enabled and is_triage_available()
            if triage_ready and raw_findings:
                try:
                    from models.schemas import BudgetConfig

                    budgets = BudgetConfig(
                        batch_ms=settings.triage_batch_budget_ms,
                        per_finding_ms=settings.triage_per_finding_budget_ms,
                        max_evidence_bytes=settings.triage_max_evidence_bytes,
                        max_snippet_lines=settings.triage_max_snippet_lines,
                    )
                    triage_result = await asyncio.to_thread(
                        triage_service.triage_findings,
                        repo_root=str(agent.repo_path),
                        findings=raw_findings,
                        policy_version=settings.triage_policy_version,
                        budgets=budgets,
                    )
                    triaged_findings = triage_result.triaged_findings
                    reportable_count = triage_result.metrics.reportable_count
                except Exception as triage_err:
                    print(f"[Orchestrator] Codex triage failed, using raw findings: {triage_err}")

            agent.findings = triaged_findings

            agent.completed_at = datetime.utcnow()
            agent.status = AgentStatus.COMPLETED

            # Best-effort report generation.
            try:
                report_service.generate_report(agent)
                self._broadcast_message(
                    WSMessage(
                        type=WSMessageType.REPORT_READY,
                        agent_id=agent.id,
                        data={
                            "agent_id": agent.id,
                            "repo_id": agent.repo_id,
                            "findings_count": reportable_count,
                            "total_findings": len(triaged_findings),
                            "message": f"Security audit complete. Found {reportable_count} reportable findings ({len(triaged_findings)} total).",
                        },
                    )
                )
            except Exception:
                pass

            return triaged_findings
        except asyncio.CancelledError:
            try:
                provider.set_cancelled(True)
                await provider.interrupt()
            except Exception:
                pass
            agent.status = AgentStatus.CANCELLED
            raise

    def _build_initial_audit_prompt(self, agent: BaseAgent) -> str:
        """Build the initial prompt for a security audit.

        Args:
            agent: The agent with audit configuration

        Returns:
            Initial prompt string for the audit
        """
        custom_instructions = ""
        if hasattr(agent.request, "custom_prompt") and agent.request.custom_prompt:
            custom_instructions = f" Additional instructions: {agent.request.custom_prompt}"

        focus_areas = ""
        if hasattr(agent.request, "focus_areas") and agent.request.focus_areas:
            focus_str = ", ".join(agent.request.focus_areas)
            focus_areas = f" Focus particularly on: {focus_str}"

        target_files = ""
        if hasattr(agent.request, "target_files") and agent.request.target_files:
            files_str = ", ".join(agent.request.target_files)
            target_files = f" Prioritize analyzing these files: {files_str}"

        return render_prompt(
            "agents/agent_orchestrator_initial_prompt.md",
            repo_path=agent.repo_path,
            custom_instructions=custom_instructions,
            focus_areas=focus_areas,
            target_files=target_files,
        )

    def evaluate_with_critic(
        self,
        agent_id: str,
        finding: Finding,
        evidence: 'EvidenceResult',
        checklist: 'ProofChecklist',
        preliminary_disposition: 'Disposition',
        pass_number: int,
        remaining_tool_calls: int,
        hypothesis_span_id: str
    ) -> 'CriticDecision':
        """
        Evaluate finding with critic loop and emit observability events.

        Args:
            agent_id: ID of the agent performing evaluation
            finding: Finding being evaluated
            evidence: Evidence gathered so far
            checklist: Proof checklist with current status
            preliminary_disposition: Preliminary disposition assessment
            pass_number: Current pass number (1, 2, 3, ...)
            remaining_tool_calls: Tool calls remaining in budget
            hypothesis_span_id: Parent span ID for hierarchy

        Returns:
            CriticDecision with decision, gaps, and recommendations
        """
        from services.critic_loop import CriticLoop, CriticInput

        # Generate critic span ID
        critic_span_id = f"critic_{hypothesis_span_id}_{pass_number}"

        # Emit critic_started event
        observability_service.log_critic_started(
            agent_id=agent_id,
            span_id=critic_span_id,
            parent_span_id=hypothesis_span_id,
            pass_number=pass_number
        )

        # Create critic input
        critic_input = CriticInput(
            finding=finding,
            evidence=evidence,
            checklist=checklist,
            preliminary_disposition=preliminary_disposition,
            pass_number=pass_number,
            remaining_tool_calls=remaining_tool_calls,
            hypothesis_span_id=hypothesis_span_id
        )

        # Evaluate with critic loop
        critic = CriticLoop()
        decision = critic.evaluate(critic_input)

        # Emit critic_decision event
        observability_service.log_critic_decision(
            agent_id=agent_id,
            span_id=critic_span_id,
            decision=decision.decision,
            reasoning=decision.reasoning
        )

        # Emit critic_output event with details
        observability_service.log_critic_output(
            agent_id=agent_id,
            span_id=critic_span_id,
            blocking_gaps=decision.blocking_gaps,
            recommended_tool_calls=decision.recommended_tool_calls,
            disposition_hint=decision.disposition_hint
        )

        # Emit critic_completed event
        observability_service.log_critic_completed(
            agent_id=agent_id,
            span_id=critic_span_id
        )

        return decision

    async def pause_agent(self, agent_id: str) -> Agent:
        """Pause a running agent."""
        agent = self._agents.get(agent_id)
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

        # For Codex CLI agents, call interrupt on the provider
        if hasattr(agent, '_codex_provider') and agent._codex_provider is not None:
            try:
                await agent._codex_provider.interrupt()
                print(f"[Orchestrator] Interrupted Codex provider for agent {agent_id}")
            except Exception as e:
                print(f"[Orchestrator] Failed to interrupt Codex provider: {e}")

        # For SDK agents, call interrupt on the provider
        if hasattr(agent, '_sdk_provider') and agent._sdk_provider is not None:
            try:
                await agent._sdk_provider.interrupt()
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

    async def get_cache_metrics(self) -> dict[str, int]:
        """Get metrics from shared cache used by all agents.

        Returns:
            Dictionary with total_hits, total_misses, total_size, cache_count
        """
        # All agents share the same cache, so just return its metrics
        if self._shared_cache is None:
            return {
                "total_hits": 0,
                "total_misses": 0,
                "total_size": 0,
                "cache_count": 0,
            }

        metrics = self._shared_cache.get_metrics()

        # Count how many agents are using the cache
        async with self._lock:
            agent_count = len([a for a in self._agents.values() if hasattr(a, '_tool_cache')])

        return {
            "total_hits": metrics["hits"],
            "total_misses": metrics["misses"],
            "total_size": metrics["size"],
            "cache_count": agent_count if agent_count > 0 else 1,  # Show 1 if cache exists
        }


# Global orchestrator instance
orchestrator = AgentOrchestrator()
