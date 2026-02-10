"""Wave dispatcher for Deep Agents parallel execution.

Handles dispatching sub-agents in waves and collecting results.

Sub-agent execution modes:
1. Claude CLI (default when use_claude_code_auth=True): Spawns `claude` CLI processes
   directly, using the user's Claude Code subscription. This is the Gas Town approach.
2. ReactAgent (fallback when use_claude_code_auth=False): Uses API key authentication
   with the Anthropic SDK.
"""

import asyncio
import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime
from typing import Optional, Callable, Any
from pydantic import BaseModel, Field

from pathlib import Path

from agents.deep_audit.filesystem import MemoriesFilesystem
from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
)
from agents.deep_audit.state import WaveTask
from agents.deep_audit.utils.json_extractor import extract_json_from_output
from models.schemas import WSMessage, WSMessageType
from services.observability_service import observability_service
import time


def _claude_cli_available() -> bool:
    """Check if the claude CLI is available on PATH."""
    return shutil.which("claude") is not None


# Plugin directory for specialist skills (native Claude Code skills mechanism)
SPECIALIST_PLUGIN_DIR = Path(__file__).resolve().parent / "specialist_plugin"


class DispatchTask(BaseModel):
    """A single sub-agent task to dispatch."""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent_type: str  # RepoProfiler, SinkHunter, etc.
    objective: str   # What to accomplish
    scope: str       # Directory/module to focus on
    inputs: list[str] = Field(default_factory=list)  # Artifacts to read from /memories/
    deliverable: str   # Expected output path
    success_criteria: str = ""
    time_budget: int = 300  # Seconds for this task
    constraints: str = ""  # Additional constraints


class WavePlan(BaseModel):
    """Plan for a wave of parallel tasks."""
    wave_id: int
    tasks: list[DispatchTask] = Field(default_factory=list)
    rationale: str = ""  # Why these tasks, from Overseer's reasoning


class SubagentResult(BaseModel):
    """Result from a single sub-agent execution."""
    task_id: str
    agent_type: str
    status: str  # "completed", "failed", "timeout"
    output_path: Optional[str] = None
    output: Optional[str] = None  # Raw output from the agent
    started_at: datetime
    completed_at: datetime
    error: Optional[str] = None
    tokens_used: int = 0


class WaveResult(BaseModel):
    """Result from a complete wave execution."""
    wave_id: int
    tasks: list[DispatchTask]
    results: list[SubagentResult] = Field(default_factory=list)
    started_at: datetime
    completed_at: Optional[datetime] = None
    all_succeeded: bool = False


# Tool subsets by agent type
# Mapped to actual tool names in AGENT_TOOLS
# Agents output JSON to stdout - dispatcher captures and writes to /memories/
AGENT_TOOL_SUBSETS = {
    "RepoProfiler": ["read_file", "list_directory", "search_code", "get_repo_tree"],
    "ScopeMapper": ["read_file", "list_directory", "search_code", "get_file_structure"],
    "EntrypointHunter": ["read_file", "search_code", "grep_semantic", "get_entry_points"],
    "SinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    # Specialized SinkHunters
    "MemorySinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    "InjectionSinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    "WebSinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    "CryptoSinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    "DataflowTracer": ["read_file", "get_file_structure", "trace_data_flow", "find_usages"],
    "ThreatModeler": ["read_file", "get_repo_tree", "get_file_structure"],
    # Phase 2: Deep Understanding agents (v2)
    "ModuleAnalyzer": ["read_file", "search_code", "grep_semantic", "get_file_structure", "list_directory"],
    "TrustBoundaryMapper": ["read_file", "search_code", "grep_semantic", "get_entry_points", "get_file_structure"],
    "DataFlowMapper": ["read_file", "search_code", "grep_semantic", "get_entry_points", "trace_data_flow"],
    "InvariantExtractor": ["read_file", "search_code", "grep_semantic", "get_file_structure"],
    "AuthBoundaryMapper": ["read_file", "search_code", "grep_semantic", "get_entry_points"],
    # Phase 3: Targeted Hunters (v2)
    "InvariantViolationHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure", "find_usages"],
    "TrustBoundaryGapHunter": ["read_file", "search_code", "grep_semantic", "get_entry_points", "trace_data_flow"],
    "Triager": ["read_file", "get_file_structure", "trace_data_flow"],
    "Auditor": ["read_file", "get_file_structure", "trace_data_flow", "find_usages"],
    "Reproducer": ["read_file", "trace_data_flow"],

    # Routing Phase agents
    "Decider": ["read_file", "search_code"],
    "FamilyCoordinator": ["read_file", "search_code"],

    # Specialist agents (read-only analysis + native skill loading)
    "Specialist": ["read_file", "search_code", "find_usages", "trace_data_flow", "use_skill"],

    # Resolution agents
    "Arbiter": ["read_file", "search_code", "trace_data_flow", "find_usages"],

    # Challenge agents
    "DevilsAdvocate": ["read_file", "search_code", "find_usages"],
}


def get_tools_for_agent_type(agent_type: str) -> list[str]:
    """Get the tool subset for a given agent type."""
    return AGENT_TOOL_SUBSETS.get(agent_type, ["read_file"])


class WaveDispatcher:
    """Dispatches sub-agents in parallel using Claude CLI and collects results.

    The dispatcher implements the "Gas Town" approach:
    1. Takes a WavePlan with tasks to execute
    2. Spawns Claude CLI processes (`claude -p`) for each task in parallel
    3. Uses the user's Claude Code subscription for authentication (no API keys)
    4. Waits for all to complete (batch wave model)
    5. Writes outputs to /memories/ and returns collected results

    Each sub-agent runs as a separate process with:
    - A filtered tool subset (Read, Glob, Grep, Bash)
    - The Foundation Context injected into its system prompt
    - A time budget enforced via asyncio.wait_for()
    """

    def __init__(
        self,
        repo_path: str,
        filesystem: MemoriesFilesystem,
        provider_config: Optional[dict] = None,
        on_agent_start: Optional[Callable[[str, str], None]] = None,
        on_agent_complete: Optional[Callable[[str, str, str], None]] = None,
        on_message: Optional[Callable[[WSMessage], None]] = None,
        parent_agent_id: Optional[str] = None,
    ):
        """Initialize the wave dispatcher.

        Args:
            repo_path: Path to the repository being scanned
            filesystem: MemoriesFilesystem instance for agent I/O
            provider_config: LLM provider configuration
            on_agent_start: Callback(task_id, agent_type) when agent starts
            on_agent_complete: Callback(task_id, agent_type, status) when agent completes
            on_message: WebSocket broadcast callback for UI updates
            parent_agent_id: Overseer's agent ID for logging interactions
        """
        self.repo_path = repo_path
        self.filesystem = filesystem
        self.provider_config = provider_config or {}
        self.on_agent_start = on_agent_start
        self.on_agent_complete = on_agent_complete
        self.on_message = on_message
        self.parent_agent_id = parent_agent_id

    def _broadcast(self, msg_type: WSMessageType, agent_id: str, data: dict):
        """Broadcast a message to UI if callback is set."""
        if self.on_message:
            self.on_message(WSMessage(type=msg_type, agent_id=agent_id, data=data))

    async def dispatch_wave(
        self,
        wave_plan: WavePlan,
        foundation_context: Optional[FoundationContext] = None,
    ) -> WaveResult:
        """Execute a wave of parallel sub-agents.

        Args:
            wave_plan: Contains list of tasks to dispatch
            foundation_context: Optional Foundation Context to inject into all agents

        Returns:
            WaveResult with all agent outputs
        """
        started_at = datetime.utcnow()

        # Create coroutines for all tasks
        tasks = [
            self._spawn_subagent(task, foundation_context)
            for task in wave_plan.tasks
        ]

        # Run all sub-agents in parallel, wait for ALL to complete
        # return_exceptions=True ensures we get results even if some fail
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        subagent_results = []
        for i, result in enumerate(results):
            task = wave_plan.tasks[i]
            if isinstance(result, Exception):
                # Task raised an exception
                subagent_results.append(SubagentResult(
                    task_id=task.task_id,
                    agent_type=task.agent_type,
                    status="failed",
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                    error=str(result),
                ))
            else:
                subagent_results.append(result)

        completed_at = datetime.utcnow()
        all_succeeded = all(r.status == "completed" for r in subagent_results)

        return WaveResult(
            wave_id=wave_plan.wave_id,
            tasks=wave_plan.tasks,
            results=subagent_results,
            started_at=started_at,
            completed_at=completed_at,
            all_succeeded=all_succeeded,
        )

    async def _spawn_subagent(
        self,
        task: DispatchTask,
        foundation_context: Optional[FoundationContext] = None,
    ) -> SubagentResult:
        """Spawn a single sub-agent using Claude CLI or ReactAgent.

        Args:
            task: The task to execute
            foundation_context: Optional Foundation Context to inject into prompt

        Returns:
            SubagentResult with execution details
        """
        started_at = datetime.utcnow()

        # Notify start
        if self.on_agent_start:
            self.on_agent_start(task.task_id, task.agent_type)

        # ALWAYS use Claude CLI (Gas Town approach) - NO API KEYS
        use_claude_code_auth = self.provider_config.get("use_claude_code_auth", True)

        if use_claude_code_auth:
            if _claude_cli_available():
                # Use Claude CLI directly (Gas Town approach)
                # Uses user's Claude Code subscription automatically
                return await self._spawn_subagent_cli(task, foundation_context, started_at)
            else:
                # Claude CLI not available - FAIL, don't fall back to API key
                error_msg = "Claude CLI not found. Install with: npm install -g @anthropic-ai/claude-code"
                print(f"[Dispatcher] ERROR: {error_msg}")
                self._broadcast(
                    WSMessageType.AGENT_STATUS,
                    task.task_id,
                    {
                        "agent_id": task.task_id,
                        "agent_type": task.agent_type,
                        "status": "failed",
                        "error": error_msg,
                    }
                )
                if self.on_agent_complete:
                    self.on_agent_complete(task.task_id, task.agent_type, "failed")
                return SubagentResult(
                    task_id=task.task_id,
                    agent_type=task.agent_type,
                    status="failed",
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                    error=error_msg,
                )

        # Legacy fallback (should not reach here with use_claude_code_auth=True)
        return await self._spawn_subagent_react(task, foundation_context, started_at)

    async def _read_process_output_limited(
        self,
        process: asyncio.subprocess.Process,
        max_size: int,
    ) -> tuple[str, str, bool, int]:
        """Read process output with size limit to prevent OOM.

        Args:
            process: The subprocess to read from
            max_size: Maximum TOTAL bytes to read before truncating (shared between stdout/stderr)

        Returns:
            Tuple of (stdout_str, stderr_str, was_truncated, returncode)
        """
        stdout_chunks = []
        stderr_chunks = []
        was_truncated = False
        total_read = 0  # Shared counter for both streams

        async def read_stream(stream, chunks):
            nonlocal was_truncated, total_read
            while True:
                chunk = await stream.read(8192)  # Read in 8KB chunks
                if not chunk:
                    break
                if total_read + len(chunk) > max_size:
                    # Truncate - shared limit for both streams
                    remaining = max_size - total_read
                    if remaining > 0:
                        chunks.append(chunk[:remaining])
                        total_read += remaining
                    was_truncated = True
                    break
                chunks.append(chunk)
                total_read += len(chunk)

        # Read stdout and stderr concurrently with shared size limit
        await asyncio.gather(
            read_stream(process.stdout, stdout_chunks),
            read_stream(process.stderr, stderr_chunks),
        )

        # Wait for process to complete and get returncode
        await process.wait()
        returncode = process.returncode

        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")

        if was_truncated:
            stdout += "\n\n[OUTPUT TRUNCATED - exceeded size limit]"

        return stdout, stderr, was_truncated, returncode

    async def _spawn_subagent_cli(
        self,
        task: DispatchTask,
        foundation_context: Optional[FoundationContext],
        started_at: datetime,
    ) -> SubagentResult:
        """Spawn sub-agent using Claude CLI directly (Gas Town approach).

        Runs `claude -p` with the task prompt, using the user's Claude Code
        subscription for authentication. This is the same approach Gas Town uses.
        """
        agent_id = f"{task.agent_type}_{task.task_id}"

        try:
            # Get prompt for this agent type (with foundation context if available)
            system_prompt = self._get_subagent_prompt(task, foundation_context)

            # Get tool subset for this agent type
            allowed_tools = get_tools_for_agent_type(task.agent_type)

            # Map our tool names to Claude CLI tool names
            # Claude CLI has built-in tools: Read, Glob, Grep, Bash, etc.
            # Note: Agents output JSON to stdout - we don't need Write tool
            claude_tool_mapping = {
                # File operations (read-only)
                "read_file": "Read",
                "list_directory": "Glob",
                "get_repo_tree": "Glob",
                "get_file_structure": "Glob",
                # Search operations
                "search_code": "Grep",
                "grep_semantic": "Grep",
                "find_usages": "Grep",
                "get_entry_points": "Grep",
                # Bash for complex operations
                "trace_data_flow": "Bash",
                # Skill for native Claude Code skill loading
                "use_skill": "Skill",
            }

            # Convert our tool names to Claude CLI tool names
            claude_tools = set()
            for tool in allowed_tools:
                if tool in claude_tool_mapping:
                    claude_tools.add(claude_tool_mapping[tool])

            # Ensure we have basic tools (Read, Glob, Grep always available)
            claude_tools.update(["Read", "Glob", "Grep"])

            claude_tools = sorted(claude_tools)  # Consistent ordering

            # Broadcast sub-agent started
            self._broadcast(
                WSMessageType.AGENT_STATUS,
                agent_id,
                {
                    "agent_id": agent_id,
                    "name": agent_id,
                    "agent_type": task.agent_type,
                    "status": "running",
                    "task_id": task.task_id,
                    "objective": task.objective,
                }
            )

            # Build the user prompt for the task
            user_prompt = f"""Execute this task:

**Objective:** {task.objective}
**Scope:** {task.scope}
**Deliverable:** {task.deliverable}
**Success Criteria:** {task.success_criteria or 'Complete the objective thoroughly'}

{f'**Constraints:** {task.constraints}' if task.constraints else ''}

Begin your analysis now."""

            # Get model from config - Opus for everything
            model = self.provider_config.get("model", "claude-opus-4-5-20251101")
            # Claude CLI accepts both aliases (sonnet, opus, haiku) and full names
            # We prefer full names for version control, but fall back to alias if needed
            model_arg = model  # Use exact model name from config

            # Build claude CLI command
            # IMPORTANT: Use --append-system-prompt instead of --system-prompt
            # --system-prompt REPLACES the entire default prompt (including tool instructions)
            # --append-system-prompt PRESERVES Claude Code's built-in tool usage capabilities
            cmd = [
                "claude",
                "-p",  # Print mode (non-interactive)
                "--model", model_arg,
                "--permission-mode", "bypassPermissions",
                "--tools", ",".join(claude_tools),
                "--append-system-prompt", system_prompt,  # Append to preserve tool instructions
                "--output-format", "text",
                "--no-session-persistence",  # Don't save session to disk
            ]

            # Add specialist plugin for native skill loading (Specialist agents only)
            if task.agent_type == "Specialist" and SPECIALIST_PLUGIN_DIR.is_dir():
                cmd.extend(["--plugin-dir", str(SPECIALIST_PLUGIN_DIR)])

            cmd.append(user_prompt)

            print(f"[Dispatcher] Spawning Claude CLI sub-agent {agent_id}")
            print(f"[Dispatcher] Tools: {', '.join(claude_tools)}")
            if task.agent_type == "Specialist" and SPECIALIST_PLUGIN_DIR.is_dir():
                print(f"[Dispatcher] Native skills plugin loaded: {SPECIALIST_PLUGIN_DIR}")

            # Verify Foundation Context file exists for downstream agents
            # This helps debug cases where agents should have read context but didn't
            foundation_context_path = self.filesystem.memory_root / "foundation" / "context.md"
            if foundation_context_path.exists():
                ctx_size = foundation_context_path.stat().st_size
                print(f"[Dispatcher] Foundation Context available: {foundation_context_path} ({ctx_size} bytes)")
            else:
                print(f"[Dispatcher] Foundation Context NOT available (file does not exist)")

            # Log LLM request for observability (use parent agent ID for frontend visibility)
            log_agent_id = self.parent_agent_id or agent_id
            request_id = observability_service.log_llm_request(
                agent_id=log_agent_id,
                messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
                tools_available=list(claude_tools),
                model=model_arg,
            )

            # Run claude CLI as subprocess
            # Use asyncio.create_subprocess_exec for async execution
            start_time = time.time()
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.repo_path,
                env={**os.environ, "NO_COLOR": "1"},  # Disable color codes in output
            )

            # Wait for completion with timeout and output size limit
            # Limit output to 10MB to prevent OOM from runaway subagents
            MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10 MB
            try:
                output, error_output, was_truncated, returncode = await asyncio.wait_for(
                    self._read_process_output_limited(process, MAX_OUTPUT_SIZE),
                    timeout=task.time_budget,
                )

                if was_truncated:
                    print(f"[Dispatcher] {agent_id} output truncated at {MAX_OUTPUT_SIZE} bytes")

                # Use returncode from the function (guaranteed valid after wait())
                if returncode != 0:
                    error_message = f"Claude CLI exited with code {returncode}: {error_output}"
                    print(f"[Dispatcher] {agent_id} failed: {error_message}")
                elif not output or not output.strip():
                    # Non-zero exit with empty output is suspicious
                    error_message = "Claude CLI produced no output"
                    print(f"[Dispatcher] {agent_id} produced no output")
                else:
                    error_message = None
                    print(f"[Dispatcher] {agent_id} completed successfully")
                    # Log stderr warnings even on success
                    if error_output and error_output.strip():
                        print(f"[Dispatcher] {agent_id} stderr: {error_output[:200]}...")

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                error_message = f"Task exceeded time budget of {task.time_budget}s"
                output = ""
                print(f"[Dispatcher] {agent_id} timed out")

            completed_at = datetime.utcnow()
            status = "completed" if not error_message else "failed"
            duration = time.time() - start_time

            # Log LLM response for observability (use parent agent ID for frontend visibility)
            observability_service.log_llm_response(
                agent_id=log_agent_id,
                request_id=request_id,
                content=output[:1000] + "..." if len(output) > 1000 else output,
                tool_calls=[],
                duration_ms=int(duration * 1000),
                model=model_arg,
                subagent=task.agent_type,
            )

            # Check if output contains questions - surface them for visibility
            questions = self._detect_questions_in_output(output) if output else []
            if questions and not error_message:
                for q in questions:
                    print(f"[Dispatcher] {agent_id} asked: {q[:150]}...")
                # Broadcast questions to UI for user visibility
                self._broadcast(
                    WSMessageType.AGENT_STATUS,
                    agent_id,
                    {
                        "agent_id": agent_id,
                        "agent_type": task.agent_type,
                        "status": "has_questions",
                        "questions": questions,
                        "task_id": task.task_id,
                    }
                )

            # Write output to deliverable path if we have content
            # IMPORTANT: Write even if there's an error - output may still contain useful data
            if output and output.strip():
                try:
                    self.filesystem.write_file(task.deliverable, output)
                    print(f"[Dispatcher] Wrote {len(output)} bytes to {task.deliverable}")
                except Exception as e:
                    # CRITICAL: Propagate write failure to status
                    error_message = f"Failed to write deliverable: {e}"
                    status = "failed"
                    print(f"[Dispatcher] {error_message}")

            # Broadcast sub-agent completed
            self._broadcast(
                WSMessageType.AGENT_STATUS,
                agent_id,
                {
                    "agent_id": agent_id,
                    "name": agent_id,
                    "agent_type": task.agent_type,
                    "status": status,
                    "task_id": task.task_id,
                    "findings_count": 0,
                    "error": error_message,
                }
            )

            # Notify completion (legacy callback)
            if self.on_agent_complete:
                self.on_agent_complete(task.task_id, task.agent_type, status)

            return SubagentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                status=status,
                output_path=task.deliverable,
                output=output if not error_message else None,  # Include raw output
                started_at=started_at,
                completed_at=completed_at,
                error=error_message,
                tokens_used=0,
            )

        except Exception as e:
            completed_at = datetime.utcnow()
            error_msg = str(e)
            print(f"[Dispatcher] {agent_id} exception: {error_msg}")
            # Broadcast failure
            self._broadcast(
                WSMessageType.AGENT_STATUS,
                agent_id,
                {
                    "agent_id": agent_id,
                    "name": agent_id,
                    "agent_type": task.agent_type,
                    "status": "failed",
                    "task_id": task.task_id,
                    "error": error_msg,
                }
            )
            if self.on_agent_complete:
                self.on_agent_complete(task.task_id, task.agent_type, "failed")
            return SubagentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                status="failed",
                started_at=started_at,
                completed_at=completed_at,
                error=error_msg,
            )

    async def _spawn_subagent_react(
        self,
        task: DispatchTask,
        foundation_context: Optional[FoundationContext],
        started_at: datetime,
    ) -> SubagentResult:
        """Spawn sub-agent using ReactAgent with API key auth."""
        try:
            # Get prompt for this agent type (with foundation context if available)
            prompt = self._get_subagent_prompt(task, foundation_context)

            # Get tool subset for this agent type
            allowed_tools = get_tools_for_agent_type(task.agent_type)

            # Import here to avoid circular imports
            from agents.react_agent import ReActSecurityAgent as ReactAgent
            from models.schemas import AgentCreateRequest, ProviderConfig, ProviderType

            # Create a minimal request for the sub-agent with full provider config
            request = AgentCreateRequest(
                repo_id=self.filesystem.project_id,
                name=f"{task.agent_type}_{task.task_id}",
                provider_config=ProviderConfig(
                    provider=self.provider_config.get("provider", ProviderType.ANTHROPIC),
                    model=self.provider_config.get("model", "claude-opus-4-5-20251101"),
                    api_key=self.provider_config.get("api_key"),
                    base_url=self.provider_config.get("base_url"),
                ),
                time_budget_seconds=task.time_budget,
                custom_prompt=prompt,
            )

            # Create ReactAgent instance with filtered tools
            # Pass on_message callback for UI visibility of sub-agent activity
            agent = ReactAgent(
                request=request,
                repo_path=self.repo_path,
                allowed_tools=allowed_tools,
                on_message=self.on_message,
            )

            # Broadcast sub-agent started
            self._broadcast(
                WSMessageType.AGENT_STATUS,
                agent.id,
                {
                    "agent_id": agent.id,
                    "name": agent.name,
                    "agent_type": task.agent_type,
                    "status": "running",
                    "task_id": task.task_id,
                    "objective": task.objective,
                }
            )

            # Override the system prompt with our task-specific prompt
            agent.system_prompt = prompt

            # Run the agent
            await agent.run()

            completed_at = datetime.utcnow()
            status = "completed" if not agent.error_message else "failed"

            # Broadcast sub-agent completed
            self._broadcast(
                WSMessageType.AGENT_STATUS,
                agent.id,
                {
                    "agent_id": agent.id,
                    "name": agent.name,
                    "agent_type": task.agent_type,
                    "status": status,
                    "task_id": task.task_id,
                    "findings_count": len(agent.findings) if hasattr(agent, 'findings') else 0,
                    "error": agent.error_message,
                }
            )

            # Notify completion (legacy callback)
            if self.on_agent_complete:
                self.on_agent_complete(task.task_id, task.agent_type, status)

            return SubagentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                status=status,
                output_path=task.deliverable,
                started_at=started_at,
                completed_at=completed_at,
                error=agent.error_message,
                tokens_used=getattr(agent, 'total_tokens', 0),
            )

        except asyncio.TimeoutError:
            completed_at = datetime.utcnow()
            # Broadcast timeout
            self._broadcast(
                WSMessageType.AGENT_STATUS,
                task.task_id,
                {
                    "agent_id": task.task_id,
                    "name": f"{task.agent_type}_{task.task_id}",
                    "agent_type": task.agent_type,
                    "status": "timeout",
                    "task_id": task.task_id,
                    "error": f"Task exceeded time budget of {task.time_budget}s",
                }
            )
            if self.on_agent_complete:
                self.on_agent_complete(task.task_id, task.agent_type, "timeout")
            return SubagentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                status="timeout",
                started_at=started_at,
                completed_at=completed_at,
                error=f"Task exceeded time budget of {task.time_budget}s",
            )

        except Exception as e:
            completed_at = datetime.utcnow()
            # Broadcast failure
            self._broadcast(
                WSMessageType.AGENT_STATUS,
                task.task_id,
                {
                    "agent_id": task.task_id,
                    "name": f"{task.agent_type}_{task.task_id}",
                    "agent_type": task.agent_type,
                    "status": "failed",
                    "task_id": task.task_id,
                    "error": str(e),
                }
            )
            if self.on_agent_complete:
                self.on_agent_complete(task.task_id, task.agent_type, "failed")
            return SubagentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                status="failed",
                started_at=started_at,
                completed_at=completed_at,
                error=str(e),
            )

    def _get_subagent_prompt(
        self,
        task: DispatchTask,
        foundation_context: Optional[FoundationContext] = None,
    ) -> str:
        """Build the prompt for a sub-agent with Foundation Context embedded.

        Args:
            task: The task containing agent type and context
            foundation_context: Foundation Context to embed directly in the prompt

        Returns:
            Complete prompt string for the sub-agent including Foundation Context

        Note:
            GAS TOWN ARCHITECTURE: We embed Foundation Context directly in the
            system prompt because subagents run as separate `claude -p` processes
            that cannot access:
            - ContextVars (process boundary isolation)
            - Virtual /memories/ filesystem (they run with cwd=repo_path)

            By prepending the context to the prompt, subagents receive full
            Foundation Context without needing to read any files.
        """
        # Get base prompt from prompting system or fallback
        base_prompt = self._get_base_prompt(task)

        # GAS TOWN: Embed Foundation Context directly in the system prompt
        # This is critical - subagents CANNOT read /memories/ or access ContextVars
        if foundation_context:
            context_section = foundation_context.to_prompt_context()
            prompt = f"""## Foundation Context (Pre-loaded)

{context_section}

---

{base_prompt}"""
            print(f"[Dispatcher] Embedded Foundation Context ({len(context_section)} chars) in {task.agent_type} prompt")
        else:
            prompt = base_prompt
            print(f"[Dispatcher] No Foundation Context available for {task.agent_type}")

        return prompt

    def _get_base_prompt(self, task: DispatchTask) -> str:
        """Get the base prompt template for an agent type.

        Args:
            task: The task containing agent type and context

        Returns:
            Base prompt string (without Foundation Context)
        """
        try:
            # Try to load from prompting system
            from prompting_loader import load_prompt, render_prompt

            # Try subagents directory first
            prompt_path = f"subagents/{task.agent_type.lower()}.md"
            try:
                # render_prompt loads the file and replaces {{placeholders}}
                prompt = render_prompt(
                    prompt_path,
                    objective=task.objective,
                    scope=task.scope,
                    inputs=", ".join(task.inputs) if task.inputs else "None",
                    deliverable=task.deliverable,
                    constraints=task.constraints or "None",
                )
                return prompt
            except FileNotFoundError:
                # Fall back to Python prompts
                return self._get_fallback_prompt(task.agent_type, task)
        except ImportError:
            # prompting_loader not available, use fallback
            return self._get_fallback_prompt(task.agent_type, task)

    def _get_fallback_prompt(
        self,
        agent_type: str,
        task: Optional[DispatchTask] = None,
    ) -> str:
        """Get fallback prompt from Python templates.

        Args:
            agent_type: Type of agent
            task: Optional task for context injection

        Returns:
            Base prompt string (Foundation Context is added by _get_subagent_prompt)
        """
        from agents.deep_audit.subagents import get_prompt_for_agent_type

        # Get base prompt for agent type
        # Note: Foundation Context is now embedded by _get_subagent_prompt()
        # using the Gas Town approach (direct prompt injection)
        base = get_prompt_for_agent_type(agent_type)

        if task:
            # Simple string replacement for templates
            base = base.replace("{scope_id}", task.scope.replace("/", "_"))
            base = base.replace("{scope_path}", task.scope)
            base = base.replace("{case_file_path}", task.deliverable)

        return base

    async def dispatch_single(
        self,
        task: Optional[DispatchTask] = None,
        foundation_context: Optional[FoundationContext] = None,
        *,
        agent_type: Optional[str] = None,
        objective: Optional[str] = None,
        scope: Optional[str] = None,
        deliverable: Optional[str] = None,
        time_budget: Optional[int] = None,
    ) -> SubagentResult:
        """Dispatch a single sub-agent (convenience method).

        Can be called with a DispatchTask object OR with keyword arguments.

        Args:
            task: The task to execute (if provided, other args ignored)
            foundation_context: Optional Foundation Context to inject into prompt
            agent_type: Agent type (if not using task)
            objective: What to accomplish (if not using task)
            scope: Directory scope (if not using task)
            deliverable: Output path (if not using task)
            time_budget: Seconds for this task (if not using task)

        Returns:
            SubagentResult
        """
        # If keyword args provided instead of task, build the task
        if task is None and agent_type is not None:
            task = DispatchTask(
                agent_type=agent_type,
                objective=objective or "",
                scope=scope or self.repo_path,
                deliverable=deliverable or f"/memories/{agent_type.lower()}_output.json",
                time_budget=time_budget or 300,
            )
        return await self._spawn_subagent(task, foundation_context)

    async def dispatch_foundation_phase(self) -> tuple[WaveResult, Optional[FoundationContext]]:
        """Run Foundation Phase: RepoProfiler, ScopeMapper, ThreatModeler in parallel.

        Returns:
            Tuple of (WaveResult, FoundationContext or None if failed)
        """
        wave_plan = WavePlan(
            wave_id=0,
            tasks=[
                DispatchTask(
                    agent_type="RepoProfiler",
                    objective="Profile the repository",
                    scope=self.repo_path,
                    deliverable="/memories/foundation/repo_profile.json",
                ),
                DispatchTask(
                    agent_type="ScopeMapper",
                    objective="Map repository scope and security-critical areas",
                    scope=self.repo_path,
                    deliverable="/memories/foundation/scope_map.json",
                ),
                DispatchTask(
                    agent_type="ThreatModeler",
                    objective="Build threat model with trust boundaries and attacker capabilities",
                    scope=self.repo_path,
                    deliverable="/memories/foundation/threat_model.json",
                ),
            ],
            rationale="Foundation Phase: Build context before hunting",
        )

        result = await self.dispatch_wave(wave_plan)

        # Try to build FoundationContext from outputs
        if result.all_succeeded:
            try:
                context = await self._build_foundation_context()
                print(f"[Foundation] SUCCESS: Built Foundation Context")
                return result, context
            except Exception as e:
                print(f"[Foundation] FAILED to build Foundation Context: {e}")
                import traceback
                traceback.print_exc()
                return result, None
        else:
            # Log which foundation agents failed
            print(f"[Foundation] FAILED: Not all foundation agents succeeded")
            for r in result.results:
                status_str = f"status={r.status}"
                if r.error:
                    status_str += f", error={r.error[:100]}"
                print(f"[Foundation]   {r.agent_type}: {status_str}")

        return result, None

    async def dispatch_understanding_phase(
        self,
        foundation_context: Optional[FoundationContext] = None,
        time_budget_per_agent: int = 300,
    ) -> tuple[WaveResult, Optional[dict]]:
        """Run Understanding Phase: ModuleAnalyzer, TrustBoundaryMapper, DataFlowMapper, InvariantExtractor.

        These agents build the Security Map — a deep understanding of the codebase's
        security architecture including trust boundaries, invariants, and data flows.

        Args:
            foundation_context: Foundation Context from Phase 1
            time_budget_per_agent: Time budget per agent in seconds

        Returns:
            Tuple of (WaveResult, security_map dict or None if failed)
        """
        # Build inputs context from foundation outputs
        foundation_inputs = ""
        if foundation_context:
            foundation_inputs = foundation_context.to_prompt_context()

        wave_plan = WavePlan(
            wave_id=0,  # Understanding phase is wave 0.5 (between foundation=0 and hunting=1)
            tasks=[
                DispatchTask(
                    agent_type="ModuleAnalyzer",
                    objective="Analyze each security-critical module: responsibilities, trust level, entry/exit points, assumptions, and dependencies. Focus on modules identified in the scope map.",
                    scope=self.repo_path,
                    deliverable="/memories/understanding/module_analysis.json",
                    time_budget=time_budget_per_agent,
                ),
                DispatchTask(
                    agent_type="TrustBoundaryMapper",
                    objective="Map all trust boundaries: where data crosses from untrusted to trusted zones, what enforcement exists at each crossing, and identify gaps where enforcement is missing or incomplete.",
                    scope=self.repo_path,
                    deliverable="/memories/understanding/trust_boundaries.json",
                    time_budget=time_budget_per_agent,
                ),
                DispatchTask(
                    agent_type="DataFlowMapper",
                    objective="Trace critical data flows from user input to sensitive sinks. Identify what validation/sanitization occurs along each path and where it's missing.",
                    scope=self.repo_path,
                    deliverable="/memories/understanding/data_flows.json",
                    time_budget=time_budget_per_agent,
                ),
                DispatchTask(
                    agent_type="InvariantExtractor",
                    objective="Extract security invariants the codebase relies on — assumptions like 'all SQL uses parameterized queries' or 'all endpoints require auth'. Identify where these invariants are enforced and where they might break.",
                    scope=self.repo_path,
                    deliverable="/memories/understanding/invariants.json",
                    time_budget=time_budget_per_agent,
                ),
            ],
            rationale="Understanding Phase: Build Security Map before targeted hunting",
        )

        result = await self.dispatch_wave(wave_plan, foundation_context=foundation_context)

        # Try to build Security Map from outputs
        security_map = None
        if result.all_succeeded:
            try:
                security_map = await self._build_security_map()
                print("[Understanding] SUCCESS: Built Security Map")
            except Exception as e:
                print(f"[Understanding] FAILED to build Security Map: {e}")
                import traceback
                traceback.print_exc()
        else:
            # Try partial security map from whatever succeeded
            try:
                security_map = await self._build_security_map(partial=True)
                if security_map:
                    print("[Understanding] Built PARTIAL Security Map from available outputs")
            except Exception as e:
                print(f"[Understanding] Could not build even partial Security Map: {e}")

            print("[Understanding] PARTIAL: Not all understanding agents succeeded")
            for r in result.results:
                status_str = f"status={r.status}"
                if r.error:
                    status_str += f", error={r.error[:100]}"
                print(f"[Understanding]   {r.agent_type}: {status_str}")

        return result, security_map

    async def _build_security_map(self, partial: bool = False) -> Optional[dict]:
        """Build Security Map from understanding phase outputs.

        Args:
            partial: If True, build with whatever outputs are available

        Returns:
            Security map dict or None
        """
        security_map = {}

        # Read each understanding output
        outputs = {
            "module_analysis": "/memories/understanding/module_analysis.json",
            "trust_boundaries": "/memories/understanding/trust_boundaries.json",
            "data_flows": "/memories/understanding/data_flows.json",
            "invariants": "/memories/understanding/invariants.json",
        }

        for key, path in outputs.items():
            try:
                content = self.filesystem.read_file(path)
                parsed = self._extract_json_from_output(content)
                if parsed:
                    security_map[key] = parsed
                    print(f"[Understanding] Loaded {key}: {len(content)} bytes")
                else:
                    print(f"[Understanding] WARNING: Could not parse {key}")
                    if not partial:
                        raise ValueError(f"Could not parse {path}")
            except FileNotFoundError:
                print(f"[Understanding] WARNING: {key} not found at {path}")
                if not partial:
                    raise

        if not security_map:
            return None

        # Write synthesized security map summary
        summary = self._synthesize_security_map_summary(security_map)
        self.filesystem.write_file("/memories/understanding/security_map_summary.md", summary)
        print(f"[Understanding] Wrote security_map_summary.md ({len(summary)} bytes)")

        # Also write the raw security map as JSON for programmatic access
        self.filesystem.write_json("/memories/understanding/security_map.json", security_map)

        return security_map

    def _synthesize_security_map_summary(self, security_map: dict) -> str:
        """Synthesize a human-readable security map summary for prompt injection.

        This summary is prepended to hunting agent prompts alongside Foundation Context.
        """
        sections = ["# Security Map Summary\n"]

        # Module Analysis
        if "module_analysis" in security_map:
            ma = security_map["module_analysis"]
            modules = ma.get("modules", ma.get("analysis", []))
            if isinstance(modules, list):
                sections.append(f"## Modules Analyzed: {len(modules)}")
                for m in modules[:10]:  # Cap at 10 for prompt size
                    name = m.get("name", m.get("module", "unknown"))
                    trust = m.get("trust_level", "unknown")
                    sections.append(f"- **{name}** (trust: {trust})")
                sections.append("")

        # Trust Boundaries
        if "trust_boundaries" in security_map:
            tb = security_map["trust_boundaries"]
            boundaries = tb.get("boundaries", tb.get("trust_boundaries", []))
            gaps = tb.get("gaps", tb.get("missing_enforcement", []))
            if isinstance(boundaries, list):
                sections.append(f"## Trust Boundaries: {len(boundaries)}")
                for b in boundaries[:8]:
                    name = b.get("name", b.get("boundary", "unknown"))
                    enforcement = b.get("enforcement", "unknown")
                    sections.append(f"- **{name}**: {enforcement}")
                sections.append("")
            if isinstance(gaps, list) and gaps:
                sections.append(f"## Trust Boundary Gaps: {len(gaps)}")
                for g in gaps[:5]:
                    desc = g.get("description", g.get("gap", str(g)))
                    if isinstance(desc, str):
                        sections.append(f"- {desc[:200]}")
                sections.append("")

        # Data Flows
        if "data_flows" in security_map:
            df = security_map["data_flows"]
            flows = df.get("flows", df.get("data_flows", []))
            if isinstance(flows, list):
                sections.append(f"## Critical Data Flows: {len(flows)}")
                for f in flows[:8]:
                    source = f.get("source", "unknown")
                    sink = f.get("sink", "unknown")
                    validated = f.get("validated", f.get("sanitized", "unknown"))
                    sections.append(f"- {source} → {sink} (validated: {validated})")
                sections.append("")

        # Invariants
        if "invariants" in security_map:
            inv = security_map["invariants"]
            invariants = inv.get("invariants", [])
            if isinstance(invariants, list):
                sections.append(f"## Security Invariants: {len(invariants)}")
                for i in invariants[:10]:
                    statement = i.get("statement", i.get("invariant", str(i)))
                    confidence = i.get("confidence", "unknown")
                    if isinstance(statement, str):
                        sections.append(f"- {statement[:200]} (confidence: {confidence})")
                sections.append("")

        return "\n".join(sections)

    def _extract_json_from_output(self, content: str) -> Optional[dict]:
        """Extract JSON from Claude CLI output. Delegates to shared util."""
        return extract_json_from_output(content)

    async def _build_foundation_context(self) -> FoundationContext:
        """Build FoundationContext from foundation phase outputs."""
        # Read outputs from filesystem (sync methods, no await needed)
        print("[Foundation] Reading foundation phase outputs...")

        try:
            repo_profile_content = self.filesystem.read_file("/memories/foundation/repo_profile.json")
            print(f"[Foundation] repo_profile.json: {len(repo_profile_content)} bytes")
        except FileNotFoundError as e:
            print(f"[Foundation] ERROR: repo_profile.json not found: {e}")
            raise

        try:
            scope_map_content = self.filesystem.read_file("/memories/foundation/scope_map.json")
            print(f"[Foundation] scope_map.json: {len(scope_map_content)} bytes")
        except FileNotFoundError as e:
            print(f"[Foundation] ERROR: scope_map.json not found: {e}")
            raise

        try:
            threat_model_content = self.filesystem.read_file("/memories/foundation/threat_model.json")
            print(f"[Foundation] threat_model.json: {len(threat_model_content)} bytes")
        except FileNotFoundError as e:
            print(f"[Foundation] ERROR: threat_model.json not found: {e}")
            raise

        # Extract JSON from Claude's text output
        repo_profile = self._extract_json_from_output(repo_profile_content)
        scope_map = self._extract_json_from_output(scope_map_content)
        threat_model = self._extract_json_from_output(threat_model_content)

        if not repo_profile:
            print(f"[Foundation] ERROR: Could not parse repo_profile.json. Content preview: {repo_profile_content[:500]}")
            raise ValueError("Could not parse repo_profile.json")
        if not scope_map:
            print(f"[Foundation] ERROR: Could not parse scope_map.json. Content preview: {scope_map_content[:500]}")
            raise ValueError("Could not parse scope_map.json")
        if not threat_model:
            print(f"[Foundation] ERROR: Could not parse threat_model.json. Content preview: {threat_model_content[:500]}")
            raise ValueError("Could not parse threat_model.json")

        print("[Foundation] All JSON files parsed successfully, building context...")

        # Parse and build context
        context = FoundationContext.from_dict({
            "repo_profile": repo_profile,
            "scope_map": scope_map,
            "threat_model": threat_model,
        })

        # Write human-readable context to a file that all subagents can read
        # This is simpler and more reliable than placeholder replacement
        context_md = context.to_prompt_context()
        self.filesystem.write_file("/memories/foundation/context.md", context_md)
        print(f"[Foundation] Wrote context to /memories/foundation/context.md ({len(context_md)} bytes)")

        return context

    def inject_foundation_context(self, task: DispatchTask, foundation_context: FoundationContext) -> DispatchTask:
        """Inject Foundation Context into a task's prompt context.

        Args:
            task: The task to inject context into
            foundation_context: The Foundation Context to inject

        Returns:
            Modified task with Foundation Context in constraints
        """
        context_text = foundation_context.to_prompt_context()
        if task.constraints:
            task.constraints = f"FOUNDATION_CONTEXT:\n{context_text}\n\n{task.constraints}"
        else:
            task.constraints = f"FOUNDATION_CONTEXT:\n{context_text}"
        return task

    # Devil's Advocate challenge templates
    DEVILS_ADVOCATE_CHALLENGES = {
        "quick_dismissal": [
            "Is there ANY alternative path that could make this exploitable?",
            "What would need to be true for this to BE vulnerable?",
            "Did you consider what happens if the attacker controls a different input?",
            "Think broader - what assumptions might not hold?",
            "Try to prove yourself wrong before concluding.",
        ],
        "incomplete_analysis": [
            "Did you check all entry points to this code?",
            "Are there indirect paths through wrapper functions?",
            "What about generated code or config files?",
            "Did you trace ALL the way from user input to sink?",
        ],
        "missing_context": [
            "How does this code fit into the larger system?",
            "What are the trust boundaries around this component?",
            "Is this code reachable by the attacker profile in our threat model?",
        ],
    }

    def should_challenge_result(
        self,
        result: SubagentResult,
        analysis_time_seconds: float,
        signal_severity: str,
    ) -> tuple[bool, str]:
        """Determine if a specialist result should be challenged.

        Args:
            result: The result from the specialist agent
            analysis_time_seconds: How long the analysis took
            signal_severity: Severity of the signal being analyzed

        Returns:
            Tuple of (should_challenge, challenge_type)
        """
        # Quick dismissals of high-severity signals warrant challenge
        if result.status == "completed" and analysis_time_seconds < 30:
            if signal_severity in ("CRITICAL", "HIGH"):
                return True, "quick_dismissal"

        # Parse the output to check for "NOT_VULNERABLE" with low confidence
        # This would need to read the actual output file

        return False, ""

    def generate_challenge_prompt(self, challenge_type: str, original_task: DispatchTask) -> str:
        """Generate a Devil's Advocate challenge prompt.

        Args:
            challenge_type: Type of challenge (quick_dismissal, incomplete_analysis, etc.)
            original_task: The original task that was challenged

        Returns:
            Challenge prompt string
        """
        challenges = self.DEVILS_ADVOCATE_CHALLENGES.get(challenge_type, [])
        if not challenges:
            challenges = self.DEVILS_ADVOCATE_CHALLENGES["quick_dismissal"]

        challenge_questions = "\n".join(f"- {q}" for q in challenges)

        return f"""## Devil's Advocate Challenge

Your previous analysis concluded quickly. Before accepting that conclusion, consider:

{challenge_questions}

**Original Task:** {original_task.objective}
**Scope:** {original_task.scope}

Please re-examine with these questions in mind. If your conclusion remains the same after thorough consideration, explain why each challenge question doesn't change your assessment.

Remember: False negatives (missing real bugs) are worse than false positives.
"""

    async def dispatch_with_challenge(
        self,
        task: DispatchTask,
        foundation_context: Optional[FoundationContext] = None,
        signal_severity: str = "MEDIUM",
        max_challenges: int = 1,
    ) -> tuple[SubagentResult, list[SubagentResult]]:
        """Dispatch a task with potential Devil's Advocate challenge.

        Args:
            task: The task to dispatch
            foundation_context: Optional Foundation Context
            signal_severity: Severity of the signal being analyzed
            max_challenges: Maximum number of challenge rounds

        Returns:
            Tuple of (final_result, challenge_results)
        """
        challenge_results = []

        # Initial dispatch
        start_time = datetime.utcnow()
        result = await self._spawn_subagent(task, foundation_context)
        analysis_time = (datetime.utcnow() - start_time).total_seconds()

        # Check if we should challenge
        challenges_issued = 0
        while challenges_issued < max_challenges:
            should_challenge, challenge_type = self.should_challenge_result(
                result, analysis_time, signal_severity
            )

            if not should_challenge:
                break

            # Generate challenge task
            challenge_prompt = self.generate_challenge_prompt(challenge_type, task)
            challenge_task = DispatchTask(
                task_id=f"{task.task_id}-challenge-{challenges_issued}",
                agent_type=task.agent_type,
                objective=f"Re-examine: {task.objective}",
                scope=task.scope,
                inputs=task.inputs,
                deliverable=f"{task.deliverable}.challenge{challenges_issued}",
                constraints=f"{challenge_prompt}\n\n{task.constraints}",
                time_budget=task.time_budget,
            )

            # Dispatch challenge
            start_time = datetime.utcnow()
            challenge_result = await self._spawn_subagent(challenge_task, foundation_context)
            analysis_time = (datetime.utcnow() - start_time).total_seconds()

            challenge_results.append(challenge_result)
            result = challenge_result
            challenges_issued += 1

        return result, challenge_results

    async def dispatch_specialist_wave_with_challenges(
        self,
        wave_plan: WavePlan,
        foundation_context: Optional[FoundationContext] = None,
        signal_severities: Optional[dict[str, str]] = None,
    ) -> WaveResult:
        """Dispatch a wave of specialist tasks with Devil's Advocate challenges.

        Args:
            wave_plan: Wave of tasks to dispatch
            foundation_context: Foundation Context
            signal_severities: Map of task_id -> severity for challenge decisions

        Returns:
            WaveResult including any challenge iterations
        """
        signal_severities = signal_severities or {}
        started_at = datetime.utcnow()

        # Create coroutines for all tasks with potential challenges
        async def dispatch_task_with_challenge(task: DispatchTask):
            severity = signal_severities.get(task.task_id, "MEDIUM")
            final_result, challenges = await self.dispatch_with_challenge(
                task, foundation_context, severity
            )
            return final_result

        tasks = [dispatch_task_with_challenge(task) for task in wave_plan.tasks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        subagent_results = []
        for i, result in enumerate(results):
            task = wave_plan.tasks[i]
            if isinstance(result, Exception):
                subagent_results.append(SubagentResult(
                    task_id=task.task_id,
                    agent_type=task.agent_type,
                    status="failed",
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                    error=str(result),
                ))
            else:
                subagent_results.append(result)

        return WaveResult(
            wave_id=wave_plan.wave_id,
            tasks=wave_plan.tasks,
            results=subagent_results,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            all_succeeded=all(r.status == "completed" for r in subagent_results),
        )

    def detect_specialist_disagreement(
        self,
        signal_id: str,
        specialist_reports: dict[str, dict],
    ) -> bool:
        """Detect if specialists disagree on a signal's exploitability.

        Args:
            signal_id: The signal being analyzed
            specialist_reports: Map of specialist_id -> report dict

        Returns:
            True if there's disagreement that needs Arbiter
        """
        if len(specialist_reports) < 2:
            return False

        verdicts = set()
        for report in specialist_reports.values():
            verdict = report.get("verdict", "").lower()
            if verdict in ("vulnerable", "exploitable", "valid"):
                verdicts.add("vulnerable")
            elif verdict in ("not_vulnerable", "not_exploitable", "invalid", "speculative"):
                verdicts.add("not_vulnerable")
            elif verdict in ("needs_more_analysis", "uncertain"):
                verdicts.add("uncertain")

        # Disagreement exists if we have both "vulnerable" and "not_vulnerable"
        return "vulnerable" in verdicts and "not_vulnerable" in verdicts

    async def dispatch_arbiter(
        self,
        signal_id: str,
        signal_context: str,
        specialist_reports: dict[str, dict],
        foundation_context: Optional[FoundationContext] = None,
    ) -> SubagentResult:
        """Dispatch Arbiter to resolve specialist disagreement.

        The Arbiter follows "expand first, then analyze" principle:
        1. Find all related sinks
        2. Find all entry points to this area
        3. Build complete attack surface picture
        4. Then make detailed judgment

        Args:
            signal_id: The disputed signal ID
            signal_context: Full signal context string
            specialist_reports: Map of specialist_id -> their report
            foundation_context: Foundation Context for scope awareness

        Returns:
            SubagentResult with Arbiter's verdict
        """
        # Format specialist reports for Arbiter
        reports_text = []
        for specialist_id, report in specialist_reports.items():
            reports_text.append(f"""
### Specialist: {specialist_id}
**Verdict:** {report.get('verdict', 'Unknown')}
**Reasoning:** {report.get('reasoning', 'No reasoning provided')}
**Evidence:** {report.get('evidence', 'No evidence provided')}
""")

        arbiter_task = DispatchTask(
            task_id=f"arbiter-{signal_id}",
            agent_type="Arbiter",
            objective=f"Resolve disagreement on signal {signal_id}",
            scope="",  # Arbiter should expand search broadly
            inputs=[],
            deliverable=f"/memories/arbiter/{signal_id}_verdict.json",
            constraints=f"""## Signal Under Dispute

{signal_context}

## Specialist Reports (DISAGREEMENT DETECTED)

{"".join(reports_text)}

## Your Task

The specialists above DISAGREE on whether this signal is exploitable.

Follow the "EXPAND FIRST, THEN ANALYZE" principle:

1. **EXPAND THE SEARCH FIRST:**
   - Find ALL related sinks in this code area
   - Find ALL entry points that could reach this code
   - Look for similar patterns nearby
   - Build complete picture of attack surface

2. **THEN ANALYZE EACH AVENUE:**
   - With full context of all possibilities
   - Detailed check of each path
   - Consider what specialists may have missed

3. **MAKE YOUR VERDICT:**
   - Based on complete understanding
   - Not just picking a side
   - Your own independent analysis

Output a JSON verdict:
```json
{{
  "signal_id": "{signal_id}",
  "verdict": "vulnerable|not_vulnerable|needs_reproducer",
  "confidence": 0-100,
  "expanded_scope": ["files you examined beyond original"],
  "reasoning": "your analysis",
  "specialist_errors": {{"specialist_id": "what they missed"}}
}}
```
""",
            time_budget=600,  # Give Arbiter more time for thorough analysis
        )

        return await self._spawn_subagent(arbiter_task, foundation_context)

    def _detect_questions_in_output(self, output: str) -> list[str]:
        """Detect questions in sub-agent output.

        Looks for common question patterns that indicate the agent needs
        clarification or additional context. Questions are surfaced to the
        user for visibility - NOT auto-answered.

        Args:
            output: The raw output from the sub-agent

        Returns:
            List of detected questions (empty if none found)
        """
        if not output:
            return []

        questions = []
        lines = output.split('\n')

        # Question patterns that indicate the agent needs input
        question_indicators = [
            # Direct questions
            '?',
            # Clarification requests
            'could you clarify',
            'can you clarify',
            'please clarify',
            'could you specify',
            'can you specify',
            'please specify',
            'need more information',
            'need clarification',
            'unclear whether',
            'not sure if',
            'should i',
            'do you want',
            'would you like',
            # Context requests
            'where is',
            'where can i find',
            'which file',
            'what is the',
        ]

        for line in lines:
            line_lower = line.lower().strip()
            # Skip empty lines and code blocks
            if not line_lower or line_lower.startswith('```'):
                continue

            # Check for question indicators
            for indicator in question_indicators:
                if indicator in line_lower:
                    # Clean up the line and add if substantial
                    clean_line = line.strip()
                    if len(clean_line) > 10 and clean_line not in questions:
                        questions.append(clean_line)
                        break  # Only add once per line

        return questions[:5]  # Limit to first 5 questions
