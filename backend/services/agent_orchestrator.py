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
    WSMessageType,
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
from services.flow_service import flow_service
from services.observability_service import observability_service
from services.finding_triage_service import triage_service
from prompting_loader import load_prompt, render_prompt


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

                if not api_key and provider_name != "ollama":
                    # Claude SDK mode can authenticate via Claude Code subscription token
                    # (`claude setup-token`) instead of an Anthropic API key.
                    if (
                        use_claude_sdk
                        and provider_name.strip().lower() == "anthropic"
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
            use_sdk = False

            if config and hasattr(config, 'provider'):
                provider_name = (
                    config.provider.value
                    if hasattr(config.provider, 'value')
                    else str(config.provider)
                )

                # Use SDK if:
                # 1. Provider is explicitly set to "claude_sdk", OR
                # 2. Provider is "anthropic" and use_claude_sdk flag is True
                if provider_name.lower() == "claude_sdk":
                    use_sdk = True
                elif provider_name.lower() == "anthropic":
                    use_claude_sdk = getattr(agent.request, 'use_claude_sdk', False)
                    use_sdk = use_claude_sdk

            if use_sdk:
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
                    if tool_name == "report_finding" and not is_error:
                        try:
                            # Debug: Log the raw result for diagnosis
                            print(f"[Orchestrator] report_finding result type: {type(result)}")
                            if isinstance(result, dict):
                                print(f"[Orchestrator] result keys: {list(result.keys())}")
                            elif isinstance(result, str):
                                print(f"[Orchestrator] result preview: {result[:200]}")

                            # Strategy 1: Check if result is a dict with top-level "finding" key
                            # (This is what our improved MCP tool returns)
                            finding_data = None
                            if isinstance(result, dict) and "finding" in result:
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
                                        source_trace=raw_finding.get("source_trace"),
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

                    elif tool_name == "upsert_sink_signal" and not is_error:
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

            self._broadcast_message(
                WSMessage(type=ws_type, agent_id=agent_id, data=ws_data)
            )

        sdk_orchestrator = ClaudeSDKOrchestrator(
            scan_tier=scan_tier,
            on_ws_event=on_sdk_event,
            provider=None,  # Will be set after provider is created
            tool_core=None,  # Will be set after tool_core is created
        )

        # Create ToolCore with limits factory from orchestrator
        tool_core = ToolCore(
            repo_path=agent.repo_path,
            project_id=agent.repo_id,
            agent_id=agent_id,
            get_scan_limits=sdk_orchestrator.make_fresh_limits,
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


# Global orchestrator instance
orchestrator = AgentOrchestrator()
