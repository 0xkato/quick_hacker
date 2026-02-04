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

from agents.deep_audit.filesystem import MemoriesFilesystem
from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
)
from agents.deep_audit.state import WaveTask
from models.schemas import WSMessage, WSMessageType
from services.observability_service import observability_service
import time


def _claude_cli_available() -> bool:
    """Check if the claude CLI is available on PATH."""
    return shutil.which("claude") is not None


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
    "DataflowTracer": ["read_file", "get_file_structure", "trace_data_flow", "find_usages"],
    "ThreatModeler": ["read_file", "get_repo_tree", "get_file_structure"],
    "AuthBoundaryMapper": ["read_file", "search_code", "grep_semantic", "get_entry_points"],
    "Triager": ["read_file", "get_file_structure", "trace_data_flow"],
    "Auditor": ["read_file", "get_file_structure", "trace_data_flow", "find_usages"],
    "Reproducer": ["read_file", "trace_data_flow"],

    # Routing Phase agents
    "Decider": ["read_file"],
    "FamilyCoordinator": ["read_file"],

    # Specialist agents (read-only analysis)
    "Specialist": ["read_file", "search_code", "find_usages", "trace_data_flow"],

    # Resolution agents
    "Arbiter": ["read_file", "search_code", "trace_data_flow", "find_usages"],
}


def get_tools_for_agent_type(agent_type: str) -> list[str]:
    """Get the tool subset for a given agent type."""
    return AGENT_TOOL_SUBSETS.get(agent_type, ["read_file"])


class WaveDispatcher:
    """Dispatches sub-agents in parallel and collects results.

    The dispatcher:
    1. Takes a WavePlan with tasks to execute
    2. Spawns ReactAgent instances for each task in parallel
    3. Waits for all to complete (batch wave model)
    4. Returns collected results
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
            cmd = [
                "claude",
                "-p",  # Print mode (non-interactive)
                "--model", model_arg,
                "--permission-mode", "bypassPermissions",
                "--tools", ",".join(claude_tools),
                "--system-prompt", system_prompt,
                "--output-format", "text",
                "--no-session-persistence",  # Don't save session to disk
                user_prompt,
            ]

            print(f"[Dispatcher] Spawning Claude CLI sub-agent {agent_id}")
            print(f"[Dispatcher] Tools: {', '.join(claude_tools)}")

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

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=task.time_budget,
                )
                output = stdout.decode("utf-8", errors="replace")
                error_output = stderr.decode("utf-8", errors="replace")

                if process.returncode != 0:
                    error_message = f"Claude CLI exited with code {process.returncode}: {error_output}"
                    print(f"[Dispatcher] {agent_id} failed: {error_message}")
                else:
                    error_message = None
                    print(f"[Dispatcher] {agent_id} completed successfully")

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

            # Write output to deliverable path if we have content
            if output and not error_message:
                try:
                    self.filesystem.write_file(task.deliverable, output)
                except Exception as e:
                    print(f"[Dispatcher] Failed to write deliverable: {e}")

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
        """Build the prompt for a sub-agent.

        Args:
            task: The task containing agent type and context
            foundation_context: Optional Foundation Context to inject

        Returns:
            Complete prompt string for the sub-agent
        """
        # Prepare foundation context text if available
        foundation_context_text = ""
        if foundation_context:
            foundation_context_text = foundation_context.to_prompt_context()

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
                    FOUNDATION_CONTEXT=foundation_context_text,
                )
                # Also replace {{FOUNDATION_CONTEXT}} if not handled by render_prompt
                if "{{FOUNDATION_CONTEXT}}" in prompt:
                    prompt = prompt.replace("{{FOUNDATION_CONTEXT}}", foundation_context_text)
                return prompt
            except FileNotFoundError:
                # Fall back to Python prompts
                return self._get_fallback_prompt(task.agent_type, task, foundation_context)
        except ImportError:
            # prompting_loader not available, use fallback
            return self._get_fallback_prompt(task.agent_type, task, foundation_context)

    def _get_fallback_prompt(
        self,
        agent_type: str,
        task: Optional[DispatchTask] = None,
        foundation_context: Optional[FoundationContext] = None,
    ) -> str:
        """Get fallback prompt from Python templates.

        Args:
            agent_type: Type of agent
            task: Optional task for context injection
            foundation_context: Optional Foundation Context to inject

        Returns:
            Prompt string
        """
        from agents.deep_audit.subagents import get_prompt_for_agent_type

        # Get base prompt for agent type
        base = get_prompt_for_agent_type(agent_type)

        if task:
            # Simple string replacement for templates
            base = base.replace("{scope_id}", task.scope.replace("/", "_"))
            base = base.replace("{scope_path}", task.scope)
            base = base.replace("{case_file_path}", task.deliverable)

        # Inject Foundation Context if available
        if foundation_context:
            context_text = foundation_context.to_prompt_context()
            base = base.replace("{{FOUNDATION_CONTEXT}}", context_text)
            # If no placeholder, prepend to the prompt
            if "{{FOUNDATION_CONTEXT}}" not in base and context_text:
                base = f"## Foundation Context\n{context_text}\n\n{base}"

        return base

    async def dispatch_single(
        self,
        task: DispatchTask,
        foundation_context: Optional[FoundationContext] = None,
    ) -> SubagentResult:
        """Dispatch a single sub-agent (convenience method).

        Args:
            task: The task to execute
            foundation_context: Optional Foundation Context to inject into prompt

        Returns:
            SubagentResult
        """
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
                return result, context
            except Exception as e:
                print(f"Failed to build Foundation Context: {e}")
                return result, None

        return result, None

    async def _build_foundation_context(self) -> FoundationContext:
        """Build FoundationContext from foundation phase outputs."""
        # Read outputs from filesystem (sync methods, no await needed)
        repo_profile_json = self.filesystem.read_file("/memories/foundation/repo_profile.json")
        scope_map_json = self.filesystem.read_file("/memories/foundation/scope_map.json")
        threat_model_json = self.filesystem.read_file("/memories/foundation/threat_model.json")

        # Parse and build context
        return FoundationContext.from_dict({
            "repo_profile": json.loads(repo_profile_json),
            "scope_map": json.loads(scope_map_json),
            "threat_model": json.loads(threat_model_json),
        })

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
