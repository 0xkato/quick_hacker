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
    "quick": 300,       # 5 minutes
    "standard": 900,    # 15 minutes
    "deep": 1800,       # 30 minutes
    "exhaustive": 3600, # 60 minutes
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

        # Initialize flow for visualization
        flow_service.initialize_flow(self.id)
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
            flow_service.update_node_status(self.id, foundation_node.id, "running")
            await self.emit_flow_update()

            foundation_result = await dispatch_tools.dispatch_foundation_phase()
            print(f"[Overseer] Foundation Phase result: {foundation_result[:500]}...")

            # Update flow node status
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
                    flow_service.update_node_status(self.id, foundation_node.id, "warning")
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
            flow_service.update_node_status(self.id, hunting_node.id, "running")
            await self.emit_flow_update()

            from agents.deep_audit.dispatcher import WavePlan, DispatchTask

            hunting_wave = WavePlan(
                wave_id=1,
                tasks=[
                    DispatchTask(
                        agent_type="SinkHunter",
                        objective="Find dangerous sinks (SQL, command injection, SSRF, etc.)",
                        scope=self.repo_path_str,
                        deliverable="/memories/signals/sinks.json",
                        time_budget=180,
                    ),
                    DispatchTask(
                        agent_type="EntrypointHunter",
                        objective="Find all entry points (HTTP routes, CLI handlers, etc.)",
                        scope=self.repo_path_str,
                        deliverable="/memories/signals/entrypoints.json",
                        time_budget=180,
                    ),
                ],
                rationale="Hunting Phase: Find signals for verification",
            )

            hunting_result = await self.dispatcher.dispatch_wave(hunting_wave)
            self.waves_completed = 1
            self.campaign_state.current_wave = 1

            # Update flow node status
            status = "completed" if hunting_result.all_succeeded else "warning"
            flow_service.update_node_status(self.id, hunting_node.id, status)
            await self.emit_flow_update()

            print(f"[Overseer] Hunting Phase complete: {hunting_result.all_succeeded}")
            await self.emit_log(f"Hunting Phase complete: found signals in {len(hunting_result.results)} agents")

            # Check for cancellation
            if self._cancelled:
                return

            # Check time budget
            if self.campaign_state.time_remaining() <= 0:
                await self.emit_log("Time budget exhausted after Hunting Phase.")
                finalize_tools.finalize_report("Time budget exhausted after Hunting Phase.")
                await self._process_findings()
                return

            # === PHASE 3: FINALIZE ===
            await self.emit_log("Phase 3: Generating final report...")

            # Create flow node for Finalize Phase
            finalize_node = flow_service.add_node(
                self.id,
                node_type="analysis",
                label="Finalize Report",
                parent_id=root_node.id if root_node else None,
                data={"phase": "finalize"},
            )
            flow_service.update_node_status(self.id, finalize_node.id, "running")
            await self.emit_flow_update()

            finalize_tools.finalize_report("Scan complete.")

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

    def _extract_tool_calls(self, response) -> list[dict]:
        """Extract tool calls from LLM response."""
        tool_calls = []

        # Handle different response formats
        if hasattr(response, 'content'):
            content = response.content
            if isinstance(content, list):
                for block in content:
                    if hasattr(block, 'type') and block.type == 'tool_use':
                        tool_calls.append({
                            "id": getattr(block, 'id', str(uuid.uuid4())[:8]),
                            "name": block.name,
                            "arguments": block.input if hasattr(block, 'input') else {},
                        })

        return tool_calls

    def _extract_text(self, response) -> str:
        """Extract text content from LLM response."""
        if hasattr(response, 'content'):
            content = response.content
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                text_parts = []
                for block in content:
                    if hasattr(block, 'type') and block.type == 'text':
                        text_parts.append(block.text)
                return " ".join(text_parts)
        return ""

    def _format_tool_results(self, results: list[dict]) -> str:
        """Format tool results for the conversation."""
        parts = []
        for r in results:
            parts.append(f"**Tool Result ({r['name']}):**\n```\n{r['result']}\n```")
        return "\n\n".join(parts)

    async def _process_findings(self):
        """Convert campaign state findings to Finding objects."""
        for finding_data in self.campaign_state.confirmed_findings:
            try:
                finding_create = FindingCreate(
                    title=finding_data.get("title", "Untitled Finding"),
                    description=finding_data.get("description", ""),
                    severity=finding_data.get("severity", "MEDIUM"),
                    vulnerability_type=finding_data.get("vulnerability_type", "unknown"),
                    file_path=finding_data.get("location", "").split(":")[0] if finding_data.get("location") else None,
                    line_number=self._extract_line_number(finding_data.get("location", "")),
                    code_snippet=finding_data.get("code_snippet"),
                    recommendation=finding_data.get("remediation"),
                    confidence=finding_data.get("confidence", 0.8),
                    verified=True,
                )
                finding = self.add_finding(finding_create)
                await self.emit_finding(finding)
            except Exception as e:
                await self.emit_log(f"Error processing finding: {e}")

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
