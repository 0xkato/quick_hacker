"""Overseer - Strategic orchestrator for Deep Audit campaigns.

The Overseer is an LLM-powered agent that strategically plans and executes
security audits using specialized sub-agents. It operates in waves, dispatching
parallel tasks and synthesizing results to build hypotheses about vulnerabilities.

Key responsibilities:
- Strategic planning of audit waves
- Dispatch of specialized sub-agents (RepoProfiler, SinkHunter, Auditor, etc.)
- Hypothesis lifecycle management (NEW → TRIAGED → TRACING → AUDITING → CONFIRMED/DISMISSED)
- Time budget enforcement
- Final report generation
"""

import asyncio
import json
import os
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    FindingCreate,
    WSMessage,
    WSMessageType,
    ProviderConfig,
    ProviderType,
)
from providers import Message

from agents.base_agent import BaseAgent
from agents.deep_audit.state import CampaignState, Hypothesis, ScopeStatus, HypothesisStatus
from agents.deep_audit.filesystem import MemoriesFilesystem
from agents.deep_audit.dispatcher import WaveDispatcher, WavePlan, DispatchTask
from agents.deep_audit.tools import dispatch as dispatch_tools
from agents.deep_audit.tools import memories as memory_tools
from agents.deep_audit.tools import finalize as finalize_tools
from agents.deep_audit.tools.dispatch import DISPATCH_WAVE_TOOL, DISPATCH_AGENT_TOOL, DISPATCH_FOUNDATION_PHASE_TOOL
from agents.deep_audit.tools.memories import (
    READ_MEMORIES_TOOL,
    LIST_MEMORIES_TOOL,
    WRITE_SYNTHESIS_TOOL,
    WRITE_ARTIFACT_TOOL,
)
from agents.deep_audit.tools.finalize import UPDATE_CAMPAIGN_STATE_TOOL, FINALIZE_REPORT_TOOL
from prompting_loader import load_prompt
from services.observability_service import observability_service
from services.flow_service import flow_service


# Scan tier time budgets in seconds
SCAN_TIER_BUDGETS = {
    "quick": 300,           # 5 minutes
    "medium": 900,          # 15 minutes
    "standard": 900,        # 15 minutes (alias)
    "advanced": 1800,       # 30 minutes
    "deep": 1800,           # 30 minutes (alias)
    "pro": 3600,            # 1 hour
    "exhaustive": 3600,     # 1 hour (alias)
    "ultra": 14400,         # 4 hours
    "evil": 86400,          # 24 hours
}


class Overseer(BaseAgent):
    """Strategic orchestrator for Deep Audit campaigns.

    The Overseer runs as an LLM agent with access to orchestration tools.
    It plans waves, dispatches sub-agents, and synthesizes results to find
    real vulnerabilities.
    """

    agent_type: AgentType = AgentType.DEEP_AUDIT

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
    ):
        """Initialize the Overseer.

        Args:
            request: Agent creation request with configuration
            repo_path: Path to the repository to scan
            on_message: WebSocket message callback
        """
        super().__init__(request, repo_path, on_message)

        self.request = request
        self.repo_path_str = repo_path

        # Determine time budget
        scan_tier = request.scan_tier or "quick"
        self.time_budget = request.time_budget_seconds or SCAN_TIER_BUDGETS.get(scan_tier, 300)

        # Initialize campaign state
        self.campaign_state = CampaignState(
            project_id=request.repo_id,
            scan_tier=scan_tier,
            deadline=time.time() + self.time_budget,
        )

        # Initialize filesystem
        self.filesystem = MemoriesFilesystem(
            project_id=request.repo_id,
            repo_path=repo_path,
        )

        # Initialize dispatcher with Claude Code auth mode (Gas Town approach)
        # ALWAYS use Claude CLI with subscription auth - NO API KEYS
        # ALWAYS use Opus for all agents
        provider_config = {
            "provider": request.provider_config.provider if request.provider_config else ProviderType.ANTHROPIC,
            "model": "claude-opus-4-5-20251101",  # Opus for everything
            "use_claude_code_auth": True,  # ALWAYS use Claude CLI subscription auth
        }
        self.provider_config = provider_config  # Store for later use

        # Model for Claude CLI calls - ALWAYS use Opus for Overseer orchestration
        self.model = "claude-opus-4-5-20251101"

        self.dispatcher = WaveDispatcher(
            repo_path=repo_path,
            filesystem=self.filesystem,
            provider_config=provider_config,
            on_agent_start=self._on_subagent_start,
            on_agent_complete=self._on_subagent_complete,
            on_message=on_message,  # Pass for sub-agent UI visibility
            parent_agent_id=self.id,  # For logging interactions under Overseer's ID
        )

        # Wire up tools with state
        self._init_tools()

        # Conversation history for the Overseer LLM
        self.conversation: list[Message] = []
        self.max_turns = 100  # Safety limit

        # Track metrics
        self.total_tokens = 0
        self.waves_completed = 0

    def _init_tools(self):
        """Initialize tools with filesystem and state references."""
        # Set filesystem for memory tools
        memory_tools.set_filesystem(self.filesystem)

        # Set filesystem and state for finalize tools
        finalize_tools.set_filesystem(self.filesystem)
        finalize_tools.set_campaign_state(self.campaign_state)

        # Set dispatcher for dispatch tools
        dispatch_tools.set_dispatcher(self.dispatcher)

    def _on_subagent_start(self, task_id: str, agent_type: str):
        """Callback when a sub-agent starts."""
        asyncio.create_task(self._emit_subagent_start(task_id, agent_type))

    async def _emit_subagent_start(self, task_id: str, agent_type: str):
        """Emit sub-agent start notification."""
        await self.emit_log(f"[Wave {self.campaign_state.current_wave}] Starting {agent_type} ({task_id})")
        await self.emit(
            WSMessageType.PROGRESS,
            {
                "type": "subagent_start",
                "wave": self.campaign_state.current_wave,
                "task_id": task_id,
                "agent_type": agent_type,
            }
        )

    def _on_subagent_complete(self, task_id: str, agent_type: str, status: str):
        """Callback when a sub-agent completes."""
        asyncio.create_task(self._emit_subagent_complete(task_id, agent_type, status))

    async def _emit_subagent_complete(self, task_id: str, agent_type: str, status: str):
        """Emit sub-agent completion notification."""
        await self.emit_log(f"[Wave {self.campaign_state.current_wave}] {agent_type} ({task_id}) {status}")
        await self.emit(
            WSMessageType.PROGRESS,
            {
                "type": "subagent_complete",
                "wave": self.campaign_state.current_wave,
                "task_id": task_id,
                "agent_type": agent_type,
                "status": status,
            }
        )

    async def _emit_wave_progress(self, wave_id: int, status: str, tasks_count: int = 0):
        """Emit wave progress notification."""
        state = self.campaign_state
        await self.emit(
            WSMessageType.PROGRESS,
            {
                "type": "wave_progress",
                "wave": wave_id,
                "status": status,
                "tasks_count": tasks_count,
                "hypotheses_count": len(state.hypotheses),
                "findings_count": len(state.confirmed_findings),
                "time_remaining": state.time_remaining(),
            }
        )

    def _get_system_prompt(self) -> str:
        """Get the Overseer system prompt."""
        try:
            return load_prompt("agents/overseer_system_prompt.md")
        except FileNotFoundError:
            # Fallback if prompting directory not found
            return self._get_fallback_system_prompt()

    def _get_fallback_system_prompt(self) -> str:
        """Fallback system prompt if file not found."""
        return """You are the Overseer, the strategic orchestrator for a security vulnerability audit campaign.

Your mission: Find real, exploitable vulnerabilities within the allocated time budget.

You have access to tools for:
- Dispatching sub-agents in waves (RepoProfiler, SinkHunter, Auditor, etc.)
- Reading and writing to the /memories/ filesystem
- Updating campaign state
- Generating the final report

Start by dispatching Wave 0 (reconnaissance) to understand the codebase."""

    def _get_tools(self) -> list[dict]:
        """Get the tool definitions for the Overseer."""
        return [
            DISPATCH_FOUNDATION_PHASE_TOOL,  # MUST be called first
            DISPATCH_WAVE_TOOL,
            DISPATCH_AGENT_TOOL,
            READ_MEMORIES_TOOL,
            LIST_MEMORIES_TOOL,
            WRITE_SYNTHESIS_TOOL,
            WRITE_ARTIFACT_TOOL,
            UPDATE_CAMPAIGN_STATE_TOOL,
            FINALIZE_REPORT_TOOL,
        ]

    async def _execute_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Execute a tool call.

        Args:
            name: Tool name
            arguments: Tool arguments

        Returns:
            Tool result as string
        """
        # Dispatch tools (async)
        if name == "dispatch_foundation_phase":
            return await dispatch_tools.dispatch_foundation_phase()
        elif name == "dispatch_wave":
            return await dispatch_tools.dispatch_wave(arguments.get("wave_plan_json", "{}"))
        elif name == "dispatch_agent":
            return await dispatch_tools.dispatch_agent(
                agent_type=arguments.get("agent_type", ""),
                objective=arguments.get("objective", ""),
                scope=arguments.get("scope", "/"),
                deliverable=arguments.get("deliverable", ""),
                inputs=arguments.get("inputs", ""),
                time_budget=arguments.get("time_budget", 300),
            )

        # Memory tools (sync)
        elif name == "read_memories":
            return memory_tools.read_memories(arguments.get("path", ""))
        elif name == "list_memories":
            return memory_tools.list_memories(arguments.get("path", "/memories/"))
        elif name == "write_synthesis":
            return memory_tools.write_synthesis(
                wave_id=arguments.get("wave_id", 0),
                synthesis_content=arguments.get("synthesis_content", ""),
            )
        elif name == "write_artifact":
            return memory_tools.write_artifact(
                path=arguments.get("path", ""),
                content=arguments.get("content", ""),
            )

        # Finalize tools (sync)
        elif name == "update_campaign_state":
            return finalize_tools.update_campaign_state(arguments.get("state_update_json", "{}"))
        elif name == "finalize_report":
            return finalize_tools.finalize_report(arguments.get("final_notes", ""))

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})

    def _build_initial_user_message(self) -> str:
        """Build the initial message to start the campaign."""
        return f"""Begin the security audit campaign.

**Configuration:**
- Project ID: {self.campaign_state.project_id}
- Scan Tier: {self.campaign_state.scan_tier}
- Time Budget: {self.time_budget} seconds
- Repository Path: {self.repo_path_str}

**Current Time Remaining:** {self.campaign_state.time_remaining():.0f} seconds

Start with Wave 0 reconnaissance:
1. Deploy RepoProfiler to map the repository structure
2. After repo profile is available, deploy ThreatModeler and AuthBoundaryMapper

Begin now. Use ALL available time productively."""

    def _build_continuation_message(self) -> str:
        """Build message to continue after tool results."""
        state = self.campaign_state
        return f"""**Campaign Status:**
- Wave: {state.current_wave}
- Time Remaining: {state.time_remaining():.0f} seconds
- Hypotheses: {len(state.hypotheses)} ({len(state.get_pending_hypotheses())} pending)
- Confirmed Findings: {len(state.confirmed_findings)}
- Dismissed: {len(state.dismissed)}
- Scopes Mapped: {len(state.scopes)}

Continue the investigation. What should the next wave focus on?"""

    def _format_conversation_for_cli(self) -> str:
        """Format conversation history for Claude CLI input.

        Since Claude CLI doesn't maintain session state in -p mode,
        we include relevant conversation context in each call.
        """
        # Get the last user message (current turn)
        if not self.conversation:
            return self._build_initial_user_message()

        # Format recent history (last few turns for context)
        parts = []
        recent_messages = self.conversation[-6:]  # Last 3 turns (user + assistant pairs)

        for msg in recent_messages:
            role = msg.role.upper()
            content = msg.content if isinstance(msg.content, str) else str(msg.content)
            parts.append(f"[{role}]\n{content}\n")

        return "\n".join(parts)

    async def _call_claude_cli(self, system_prompt: str, user_message: str) -> dict:
        """Call Claude CLI for Overseer's own LLM orchestration.

        Uses `claude -p` with Claude Code subscription auth (no API key needed).

        Args:
            system_prompt: System prompt for the LLM
            user_message: Current user message (includes conversation context)

        Returns:
            Dict with 'text' (response text) and 'tool_calls' (list of tool calls)
        """
        # Check if Claude CLI is available
        if not shutil.which("claude"):
            raise RuntimeError("Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code")

        # Build the prompt with conversation context
        # For multi-turn, we format the conversation as part of the user message
        full_prompt = user_message

        # Build command
        cmd = [
            "claude",
            "-p",  # Print mode (non-interactive)
            "--model", self.model,
            "--permission-mode", "bypassPermissions",
            "--system-prompt", system_prompt,
            "--output-format", "json",  # Get structured output
            "--no-session-persistence",
            full_prompt,
        ]

        print(f"[Overseer] Calling Claude CLI with model: {self.model}")
        print(f"[Overseer] System prompt length: {len(system_prompt)} chars")
        print(f"[Overseer] User message length: {len(user_message)} chars")

        # Log LLM request for observability
        request_id = observability_service.log_llm_request(
            agent_id=self.id,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}],
            tools_available=["dispatch_wave", "dispatch_agent", "read_memories"],
            model=self.model,
        )

        # Run Claude CLI with timeout
        start_time = time.time()
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.repo_path_str,
            env={**os.environ, "NO_COLOR": "1"},
        )

        try:
            # 5 minute timeout for Overseer LLM calls
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError("Claude CLI timed out after 5 minutes")

        output = stdout.decode("utf-8", errors="replace")
        error_output = stderr.decode("utf-8", errors="replace")

        print(f"[Overseer] Claude CLI returned, output length: {len(output)}")
        if error_output:
            print(f"[Overseer] CLI stderr: {error_output[:500]}")

        if process.returncode != 0:
            raise RuntimeError(f"Claude CLI error: {error_output}")

        # Parse JSON output
        try:
            response_data = json.loads(output)
        except json.JSONDecodeError:
            # If not valid JSON, treat as plain text response
            return {"text": output, "tool_calls": []}

        # Extract text and tool calls from response
        text = ""
        tool_calls = []

        # Handle different response formats
        if isinstance(response_data, dict):
            # Check for result field (stream-json format)
            if "result" in response_data:
                text = response_data.get("result", "")
            elif "content" in response_data:
                # Standard message format
                content = response_data.get("content", [])
                if isinstance(content, str):
                    text = content
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict):
                            if block.get("type") == "text":
                                text += block.get("text", "")
                            elif block.get("type") == "tool_use":
                                tool_calls.append({
                                    "id": block.get("id", str(uuid.uuid4())[:8]),
                                    "name": block.get("name", ""),
                                    "arguments": block.get("input", {}),
                                })
            else:
                text = str(response_data)
        else:
            text = str(response_data)

        # Log LLM response for observability
        duration = time.time() - start_time
        observability_service.log_llm_response(
            agent_id=self.id,
            request_id=request_id,
            content=text[:1000] + "..." if len(text) > 1000 else text,
            tool_calls=[{"name": tc.get("name", ""), "id": tc.get("id", "")} for tc in tool_calls],
            duration_ms=int(duration * 1000),
            model=self.model,
        )

        return {"text": text, "tool_calls": tool_calls}

    async def analyze(self):
        """Run the Overseer orchestration loop.

        Uses a direct dispatch approach:
        1. Run Foundation Phase (RepoProfiler, ScopeMapper, ThreatModeler)
        2. Run Hunting Phase (SinkHunter, EntrypointHunter)
        3. Route signals to specialists
        4. Generate final report

        All sub-agents use Claude CLI with Claude Code subscription auth.
        """
        print("=" * 60)
        print("[Overseer] STARTING PARALLEL SUB-AGENT ORCHESTRATION")
        print(f"[Overseer] Time budget: {self.time_budget} seconds")
        print(f"[Overseer] Project: {self.campaign_state.project_id}")
        print(f"[Overseer] Repository: {self.repo_path_str}")
        print("=" * 60)

        await self.emit_log("Overseer starting parallel sub-agent orchestration...")

        # Add root node for deep audit visualization (flow already initialized by base agent)
        root_node = flow_service.add_node(
            self.id,
            node_type="structured_root",
            label=f"Deep Audit: {self.campaign_state.scan_tier}",
            data={"project_id": self.campaign_state.project_id, "time_budget": self.time_budget},
        )
        await self.emit_flow_update()

        try:
            # === PHASE 1: FOUNDATION ===
            await self.emit_log("Phase 1: Running Foundation Phase...")
            print("[Overseer] Dispatching Foundation Phase sub-agents...")

            # Create flow node for Foundation Phase
            foundation_node = flow_service.add_node(
                self.id,
                node_type="global_recon",
                label="Wave 0: Foundation",
                parent_id=root_node.id if root_node else None,
                data={"phase": "foundation", "agents": ["RepoProfiler", "ScopeMapper", "ThreatModeler"]},
            )
            if foundation_node:
                flow_service.update_node_status(self.id, foundation_node.id, "running")
            await self.emit_flow_update()

            foundation_result = await dispatch_tools.dispatch_foundation_phase()
            print(f"[Overseer] Foundation Phase result: {foundation_result[:500]}...")

            # Update flow node status
            if foundation_node:
                flow_service.update_node_status(self.id, foundation_node.id, "completed")
            await self.emit_flow_update()

            # Check for cancellation
            if self._cancelled:
                return

            # Parse foundation result
            try:
                foundation_data = json.loads(foundation_result)
                if not foundation_data.get("all_succeeded"):
                    await self.emit_log("Foundation Phase had failures, continuing with partial results...")
                    if foundation_node:
                        flow_service.update_node_status(self.id, foundation_node.id, "failed")
            except json.JSONDecodeError:
                await self.emit_log("Could not parse Foundation Phase result, continuing...")

            # Check time budget
            if self.campaign_state.time_remaining() <= 0:
                await self.emit_log("Time budget exhausted after Foundation Phase.")
                finalize_tools.finalize_report("Time budget exhausted after Foundation Phase.")
                await self._process_findings()
                return

            # === PHASE 2: HUNTING ===
            await self.emit_log("Phase 2: Running Hunting Phase...")
            print("[Overseer] Dispatching Hunting Phase sub-agents...")

            # Create flow node for Hunting Phase
            hunting_node = flow_service.add_node(
                self.id,
                node_type="scan",
                label="Wave 1: Hunting",
                parent_id=root_node.id if root_node else None,
                data={"phase": "hunting", "agents": ["SinkHunter", "EntrypointHunter"]},
            )
            if hunting_node:
                flow_service.update_node_status(self.id, hunting_node.id, "running")
            await self.emit_flow_update()

            from agents.deep_audit.dispatcher import WavePlan, DispatchTask

            # Calculate sub-agent time budget based on remaining time
            # Give each hunting agent 20% of remaining time, min 60s, max 1800s
            remaining = self.campaign_state.time_remaining()
            subagent_budget = max(60, min(1800, int(remaining * 0.2)))

            hunting_wave = WavePlan(
                wave_id=1,
                tasks=[
                    DispatchTask(
                        agent_type="SinkHunter",
                        objective="Find dangerous sinks (SQL, command injection, SSRF, etc.)",
                        scope=self.repo_path_str,
                        deliverable="/memories/signals/sinks.json",
                        time_budget=subagent_budget,
                    ),
                    DispatchTask(
                        agent_type="EntrypointHunter",
                        objective="Find all entry points (HTTP routes, CLI handlers, etc.)",
                        scope=self.repo_path_str,
                        deliverable="/memories/signals/entrypoints.json",
                        time_budget=subagent_budget,
                    ),
                ],
                rationale="Hunting Phase: Find signals for verification",
            )

            hunting_result = await self.dispatcher.dispatch_wave(hunting_wave)
            self.waves_completed = 1
            self.campaign_state.current_wave = 1

            # Update flow node status
            if hunting_node:
                hunt_status = "completed" if hunting_result.all_succeeded else "failed"
                flow_service.update_node_status(self.id, hunting_node.id, hunt_status)
            await self.emit_flow_update()

            print(f"[Overseer] Hunting Phase complete: {hunting_result.all_succeeded}")
            await self.emit_log(f"Hunting Phase complete: found signals in {len(hunting_result.results)} agents")

            # Parse sub-agent outputs and extract findings
            await self._collect_findings_from_signals()

            # Check for cancellation
            if self._cancelled:
                return

            # Check time budget
            if self.campaign_state.time_remaining() <= 0:
                await self.emit_log("Time budget exhausted after Hunting Phase.")
                finalize_tools.finalize_report("Time budget exhausted after Hunting Phase.")
                await self._process_findings()
                return

            # === PHASE 3: WAVE LOOP ===
            # Continue dispatching waves until time budget is exhausted
            # Minimum time to dispatch another wave (2 minutes)
            MIN_TIME_FOR_WAVE = 120
            MAX_WAVES = 50  # Safety limit

            while (self.campaign_state.time_remaining() > MIN_TIME_FOR_WAVE
                   and self.waves_completed < MAX_WAVES
                   and not self._cancelled):

                self.waves_completed += 1
                wave_num = self.waves_completed + 1
                remaining = self.campaign_state.time_remaining()

                await self.emit_log(f"Wave {wave_num}: {remaining:.0f}s remaining, dispatching verification agents...")
                print(f"[Overseer] Starting Wave {wave_num} with {remaining:.0f}s remaining")

                # Create flow node for this wave
                wave_node = flow_service.add_node(
                    self.id,
                    node_type="scan",
                    label=f"Wave {wave_num}: Verification",
                    parent_id=root_node.id if root_node else None,
                    data={"phase": "verification", "wave": wave_num, "time_remaining": remaining},
                )
                if wave_node:
                    flow_service.update_node_status(self.id, wave_node.id, "running")
                await self.emit_flow_update()

                # Calculate sub-agent time budget for this wave
                # Give each agent 15% of remaining time, min 60s, max 600s
                subagent_budget = max(60, min(600, int(remaining * 0.15)))

                # Determine what agents to dispatch based on current state
                tasks = []

                # If we have signals, dispatch verification agents
                signals_count = len(self.campaign_state.confirmed_findings)
                if signals_count > 0:
                    # Dispatch DataflowTracer on signals
                    tasks.append(DispatchTask(
                        agent_type="DataflowTracer",
                        objective=f"Trace dataflow for {signals_count} potential vulnerabilities",
                        scope=self.repo_path_str,
                        deliverable=f"/memories/waves/wave_{wave_num}/dataflow_trace.json",
                        time_budget=subagent_budget,
                    ))

                    # Dispatch AuthBoundaryMapper to check auth
                    tasks.append(DispatchTask(
                        agent_type="AuthBoundaryMapper",
                        objective="Map authentication and authorization boundaries for signals",
                        scope=self.repo_path_str,
                        deliverable=f"/memories/waves/wave_{wave_num}/auth_boundaries.json",
                        time_budget=subagent_budget,
                    ))
                else:
                    # No signals yet, dispatch more hunters in different areas
                    tasks.append(DispatchTask(
                        agent_type="SinkHunter",
                        objective="Deep hunt for dangerous sinks (SQL, command injection, SSRF, deserialization)",
                        scope=self.repo_path_str,
                        deliverable=f"/memories/waves/wave_{wave_num}/sinks.json",
                        time_budget=subagent_budget,
                    ))

                if not tasks:
                    await self.emit_log(f"Wave {wave_num}: No tasks to dispatch, exiting wave loop")
                    break

                # Dispatch the wave
                wave_plan = WavePlan(
                    wave_id=wave_num,
                    tasks=tasks,
                    rationale=f"Wave {wave_num}: Verification and deep analysis",
                )

                try:
                    wave_result = await self.dispatcher.dispatch_wave(wave_plan)
                    self.campaign_state.current_wave = wave_num

                    # Update flow node status
                    if wave_node:
                        wave_status = "completed" if wave_result.all_succeeded else "failed"
                        flow_service.update_node_status(self.id, wave_node.id, wave_status)
                    await self.emit_flow_update()

                    # Collect any new findings from this wave
                    await self._collect_wave_findings(wave_num)

                    print(f"[Overseer] Wave {wave_num} complete: {wave_result.all_succeeded}")
                    await self.emit_log(f"Wave {wave_num} complete. Total findings: {len(self.campaign_state.confirmed_findings)}")

                except Exception as e:
                    print(f"[Overseer] Wave {wave_num} failed: {e}")
                    await self.emit_log(f"Wave {wave_num} failed: {e}")
                    if wave_node:
                        flow_service.update_node_status(self.id, wave_node.id, "failed")
                    await self.emit_flow_update()

                # Brief pause between waves
                await asyncio.sleep(1)

            # Log why we exited the loop
            if self._cancelled:
                await self.emit_log("Scan cancelled by user.")
            elif self.campaign_state.time_remaining() <= MIN_TIME_FOR_WAVE:
                await self.emit_log(f"Time budget nearly exhausted ({self.campaign_state.time_remaining():.0f}s remaining)")
            elif self.waves_completed >= MAX_WAVES:
                await self.emit_log(f"Maximum waves reached ({MAX_WAVES})")

            # === PHASE 4: FINALIZE ===
            await self.emit_log("Phase 4: Generating final report...")

            # Create flow node for Finalize Phase
            finalize_node = flow_service.add_node(
                self.id,
                node_type="analysis",
                label="Finalize Report",
                parent_id=root_node.id if root_node else None,
                data={"phase": "finalize"},
            )
            if finalize_node:
                flow_service.update_node_status(self.id, finalize_node.id, "running")
            await self.emit_flow_update()

            finalize_tools.finalize_report("Scan complete.")

            if finalize_node:
                flow_service.update_node_status(self.id, finalize_node.id, "completed")
            await self.emit_flow_update()

        except Exception as e:
            print(f"[Overseer] Error during orchestration: {e}")
            import traceback
            traceback.print_exc()
            self.error_message = str(e)
            await self.emit_log(f"Orchestration error: {e}")

        # Convert confirmed findings to Finding objects
        await self._process_findings()

    def _extract_json_from_output(self, content: str) -> Optional[dict]:
        """Extract JSON from Claude CLI output which may include preamble text."""
        if not content:
            return None

        # Try direct parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in the content
        # Look for first { and last }
        start = content.find('{')
        end = content.rfind('}')
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(content[start:end + 1])
            except json.JSONDecodeError:
                pass

        # Try to find JSON array
        start = content.find('[')
        end = content.rfind(']')
        if start != -1 and end != -1 and end > start:
            try:
                return {"items": json.loads(content[start:end + 1])}
            except json.JSONDecodeError:
                pass

        return None

    async def _collect_findings_from_signals(self):
        """Read sub-agent outputs and extract findings from signals."""
        # Read SinkHunter output
        try:
            sinks_content = self.filesystem.read_file("/memories/signals/sinks.json")
            if sinks_content:
                sinks_data = self._extract_json_from_output(sinks_content)
                if sinks_data:
                    # Handle various output formats
                    signals = (
                        sinks_data.get("signals") or
                        sinks_data.get("sinks") or
                        sinks_data.get("findings") or
                        sinks_data.get("items") or
                        (sinks_data if isinstance(sinks_data, list) else [])
                    )
                    if isinstance(signals, list):
                        for signal in signals:
                            if isinstance(signal, dict):
                                # Convert signal to finding format
                                finding = {
                                    "title": signal.get("title", signal.get("type", "Potential Vulnerability")),
                                    "description": signal.get("description", signal.get("reasoning", "")),
                                    "severity": signal.get("severity", "MEDIUM"),
                                    "vulnerability_type": signal.get("type", signal.get("sink_type", "unknown")),
                                    "location": signal.get("location", signal.get("file_path", "")),
                                    "code_snippet": signal.get("code_snippet", signal.get("code", "")),
                                    "remediation": signal.get("remediation", signal.get("recommendation", "")),
                                    "confidence": signal.get("confidence", 0.7),
                                }
                                self.campaign_state.confirmed_findings.append(finding)
                        print(f"[Overseer] Collected {len(signals)} signals from SinkHunter")
                else:
                    print(f"[Overseer] Could not parse SinkHunter output as JSON")
        except Exception as e:
            print(f"[Overseer] Could not read SinkHunter output: {e}")

        # Read EntrypointHunter output (for context, not findings)
        try:
            entrypoints_content = self.filesystem.read_file("/memories/signals/entrypoints.json")
            if entrypoints_content:
                try:
                    entrypoints_data = json.loads(entrypoints_content)
                    entrypoints = entrypoints_data.get("entrypoints", [])
                    print(f"[Overseer] Found {len(entrypoints)} entrypoints from EntrypointHunter")
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        await self.emit_log(f"Collected {len(self.campaign_state.confirmed_findings)} potential findings from sub-agents")

    async def _collect_wave_findings(self, wave_num: int):
        """Collect findings from a specific wave's outputs."""
        wave_dir = f"/memories/waves/wave_{wave_num}"
        files_to_check = [
            f"{wave_dir}/dataflow_trace.json",
            f"{wave_dir}/auth_boundaries.json",
            f"{wave_dir}/sinks.json",
        ]

        for file_path in files_to_check:
            try:
                content = self.filesystem.read_file(file_path)
                if content:
                    data = self._extract_json_from_output(content)
                    if data:
                        # Extract signals/findings from various formats
                        signals = (
                            data.get("signals") or
                            data.get("findings") or
                            data.get("sinks") or
                            data.get("traces") or
                            data.get("items") or
                            (data if isinstance(data, list) else [])
                        )
                        if isinstance(signals, list):
                            for signal in signals:
                                if isinstance(signal, dict):
                                    finding = {
                                        "title": signal.get("title", signal.get("type", "Potential Vulnerability")),
                                        "description": signal.get("description", signal.get("reasoning", "")),
                                        "severity": signal.get("severity", "MEDIUM"),
                                        "vulnerability_type": signal.get("type", signal.get("sink_type", "unknown")),
                                        "location": signal.get("location", signal.get("file_path", "")),
                                        "code_snippet": signal.get("code_snippet", signal.get("code", "")),
                                        "remediation": signal.get("remediation", signal.get("recommendation", "")),
                                        "confidence": signal.get("confidence", 0.7),
                                    }
                                    self.campaign_state.confirmed_findings.append(finding)
                            if len(signals) > 0:
                                print(f"[Overseer] Wave {wave_num}: Collected {len(signals)} signals from {file_path}")
            except Exception as e:
                print(f"[Overseer] Wave {wave_num}: Could not read {file_path}: {e}")

    async def _process_findings(self):
        """Convert campaign state findings to Finding objects."""
        print(f"[Overseer] Processing {len(self.campaign_state.confirmed_findings)} confirmed findings...")

        processed_count = 0
        error_count = 0
        skipped_count = 0

        for i, finding_data in enumerate(self.campaign_state.confirmed_findings):
            try:
                # Debug: show what we're processing
                if i < 3:  # Only show first 3 to avoid log spam
                    print(f"[Overseer] Finding {i+1}: {finding_data.get('title', 'No title')[:50]}")

                # Extract file path and line number from location
                location = finding_data.get("location", "") or finding_data.get("file_path", "")
                if not location:
                    print(f"[Overseer] Finding {i+1}: Skipping - no file location")
                    skipped_count += 1
                    continue

                file_path = location.split(":")[0] if ":" in location else location
                line_start = self._extract_line_number(location) or 1

                # Normalize severity to uppercase enum value
                severity = finding_data.get("severity", "MEDIUM")
                if isinstance(severity, str):
                    severity = severity.upper()

                finding_create = FindingCreate(
                    title=finding_data.get("title", "Untitled Finding"),
                    description=finding_data.get("description", ""),
                    severity=severity,
                    vulnerability_type=finding_data.get("vulnerability_type", "unknown"),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_start,  # Same as start for single-line findings
                    code_snippet=finding_data.get("code_snippet"),
                    recommended_fix=finding_data.get("remediation") or finding_data.get("recommendation"),
                    confidence=finding_data.get("confidence", 0.8),
                )
                finding = self.add_finding(finding_create)
                if finding:
                    await self.emit_finding(finding)
                    processed_count += 1
                else:
                    skipped_count += 1  # Duplicate
            except Exception as e:
                error_count += 1
                print(f"[Overseer] Error processing finding {i+1}: {e}")
                import traceback
                traceback.print_exc()
                await self.emit_log(f"Error processing finding: {e}")

        print(f"[Overseer] Processed {processed_count} findings, {skipped_count} skipped, {error_count} errors")
        await self.emit_log(f"Processed {processed_count} findings into final report")

    def _extract_line_number(self, location: str) -> Optional[int]:
        """Extract line number from location string like 'file.py:123'."""
        if ":" in location:
            try:
                return int(location.split(":")[-1])
            except ValueError:
                pass
        return None

    def to_schema(self) -> Agent:
        """Convert to Agent schema."""
        default_provider_config = ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-opus-4-5-20251101",
        )

        return Agent(
            id=self.id,
            repo_id=self.repo_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
            provider_config=self.provider_config or default_provider_config,
            scan_tier=self.scan_tier,
            time_budget_seconds=self.time_budget,
            custom_prompt=self.custom_prompt,
            target_files=self.target_files,
            focus_areas=self.focus_areas,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            files_analyzed=len(self.campaign_state.scopes),
            findings_count=len(self.findings),
            error_message=self.error_message,
        )

    def get_campaign_summary(self) -> dict:
        """Get a summary of the campaign for external reporting."""
        state = self.campaign_state
        return {
            "project_id": state.project_id,
            "scan_tier": state.scan_tier,
            "waves_completed": self.waves_completed,
            "time_used_seconds": self.time_budget - state.time_remaining(),
            "hypotheses": {
                "total": len(state.hypotheses),
                "pending": len(state.get_pending_hypotheses()),
                "by_status": self._count_by_status(state.hypotheses),
            },
            "findings": {
                "confirmed": len(state.confirmed_findings),
                "dismissed": len(state.dismissed),
            },
            "coverage": {
                "scopes_analyzed": len(state.scopes),
                "entrypoints_found": len(state.entrypoints),
            },
            "tokens_used": self.total_tokens,
        }

    def _count_by_status(self, hypotheses: list[Hypothesis]) -> dict[str, int]:
        """Count hypotheses by status."""
        counts: dict[str, int] = {}
        for h in hypotheses:
            status = h.status if isinstance(h.status, str) else h.status.value
            counts[status] = counts.get(status, 0) + 1
        return counts
