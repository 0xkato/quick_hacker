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
from providers import Message, get_provider

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

        # Initialize dispatcher with full provider config
        # Support both API key and Claude Code auth modes
        use_claude_code_auth = getattr(request, 'use_claude_code_auth', False)
        provider_config = {
            "provider": request.provider_config.provider if request.provider_config else ProviderType.ANTHROPIC,
            "model": request.provider_config.model if request.provider_config else "claude-sonnet-4-20250514",
            "api_key": request.provider_config.api_key if request.provider_config and request.provider_config.api_key else None,
            "base_url": request.provider_config.base_url if request.provider_config and request.provider_config.base_url else None,
            "use_claude_code_auth": use_claude_code_auth,  # Pass through for sub-agents
        }
        self.provider_config = provider_config  # Store for later use

        # Create the actual LLM provider for Overseer's own LLM calls
        # Note: The Overseer needs an API key for orchestration even when sub-agents
        # use Claude Code auth. The sub-agents use `claude -p` CLI, but Overseer
        # needs direct API access for its orchestration loop.
        import os
        api_key = provider_config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key and use_claude_code_auth:
            # Warn that Overseer still needs an API key for orchestration
            print("[Overseer] WARNING: Claude Code auth is for sub-agents only.")
            print("[Overseer] The Overseer orchestrator still needs ANTHROPIC_API_KEY env var for its LLM calls.")

        overseer_provider_config = ProviderConfig(
            provider=provider_config["provider"],
            model=provider_config["model"],
            api_key=api_key,
            base_url=provider_config.get("base_url"),
        )
        self.provider = get_provider(overseer_provider_config)

        self.dispatcher = WaveDispatcher(
            repo_path=repo_path,
            filesystem=self.filesystem,
            provider_config=provider_config,
            on_agent_start=self._on_subagent_start,
            on_agent_complete=self._on_subagent_complete,
            on_message=on_message,  # Pass for sub-agent UI visibility
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

    async def analyze(self):
        """Run the Overseer agent loop.

        This is the main orchestration loop that:
        1. Sends messages to the LLM
        2. Executes tool calls
        3. Synthesizes results
        4. Repeats until time runs out

        Returns:
            List of confirmed findings
        """
        print("=" * 60)
        print("[Overseer] STARTING PARALLEL SUB-AGENT ORCHESTRATION")
        print(f"[Overseer] Time budget: {self.time_budget} seconds")
        print(f"[Overseer] Project: {self.campaign_state.project_id}")
        print(f"[Overseer] Repository: {self.repo_path_str}")
        print("=" * 60)

        await self.emit_log("Overseer starting parallel sub-agent orchestration...")

        # Initialize conversation
        system_prompt = self._get_system_prompt()
        tools = self._get_tools()

        # Send initial message
        self.conversation.append(Message(
            role="user",
            content=self._build_initial_user_message(),
        ))

        turn = 0
        while turn < self.max_turns:
            turn += 1

            # Check time budget
            if self.campaign_state.time_remaining() <= 0:
                await self.emit_log("Time budget exhausted. Generating final report...")
                # Force finalize
                result = finalize_tools.finalize_report("Time budget exhausted.")
                break

            # Check for cancellation
            if self._cancelled:
                break

            # Call LLM
            try:
                response = await self.provider.complete(
                    messages=self.conversation,
                    system=system_prompt,
                    tools=tools,
                )
            except Exception as e:
                await self.emit_log(f"LLM error: {e}")
                self.error_message = str(e)
                break

            # Track tokens
            if hasattr(response, 'usage'):
                self.total_tokens += getattr(response.usage, 'total_tokens', 0)

            # Process response
            assistant_message = response.content
            self.conversation.append(Message(role="assistant", content=assistant_message))

            # Check for tool calls
            tool_calls = self._extract_tool_calls(response)

            if not tool_calls:
                # No tool calls - check if this is a final response
                text_content = self._extract_text(response)
                if text_content:
                    await self.emit_log(f"Overseer: {text_content[:200]}...")

                # Check if we should continue
                if "final report" in text_content.lower() or "campaign complete" in text_content.lower():
                    break

                # Prompt to continue
                self.conversation.append(Message(
                    role="user",
                    content=self._build_continuation_message(),
                ))
                continue

            # Execute tool calls
            tool_results = []
            for tool_call in tool_calls:
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("arguments", {})
                tool_id = tool_call.get("id", str(uuid.uuid4())[:8])

                await self.emit_log(f"Executing tool: {tool_name}")

                try:
                    result = await self._execute_tool(tool_name, tool_args)
                    tool_results.append({
                        "id": tool_id,
                        "name": tool_name,
                        "result": result,
                    })
                except Exception as e:
                    tool_results.append({
                        "id": tool_id,
                        "name": tool_name,
                        "result": json.dumps({"error": str(e)}),
                    })

            # Add tool results to conversation
            self.conversation.append(Message(
                role="user",
                content=self._format_tool_results(tool_results),
            ))

            # Update wave counter and emit progress if dispatch_wave was called
            for tc in tool_calls:
                if tc.get("name") == "dispatch_wave":
                    self.waves_completed += 1
                    self.campaign_state.current_wave = self.waves_completed
                    # Parse the wave plan to get task count
                    try:
                        wave_plan = json.loads(tc.get("arguments", {}).get("wave_plan_json", "{}"))
                        tasks_count = len(wave_plan.get("tasks", []))
                    except:
                        tasks_count = 0
                    await self._emit_wave_progress(self.waves_completed, "completed", tasks_count)

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
            model="claude-sonnet-4-20250514",
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
