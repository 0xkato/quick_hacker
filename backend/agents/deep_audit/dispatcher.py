"""Wave dispatcher for Deep Agents parallel execution.

Handles dispatching sub-agents in waves and collecting results.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Optional, Callable
from pydantic import BaseModel, Field

from agents.deep_audit.filesystem import MemoriesFilesystem
from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
)
from agents.deep_audit.state import WaveTask


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
# All agents get write_file (to write outputs to /memories/)
AGENT_TOOL_SUBSETS = {
    "RepoProfiler": ["read_file", "list_directory", "search_code", "get_repo_tree", "write_file"],
    "ScopeMapper": ["read_file", "list_directory", "search_code", "get_file_structure", "write_file"],
    "EntrypointHunter": ["read_file", "search_code", "grep_semantic", "get_entry_points", "write_file"],
    "SinkHunter": ["read_file", "search_code", "grep_semantic", "get_file_structure", "upsert_sink_signal", "write_file"],
    "DataflowTracer": ["read_file", "get_file_structure", "trace_data_flow", "find_usages", "write_file", "read_memories"],
    "ThreatModeler": ["read_file", "get_repo_tree", "get_file_structure", "write_file"],
    "AuthBoundaryMapper": ["read_file", "search_code", "grep_semantic", "get_entry_points", "write_file"],
    "Triager": ["read_file", "get_file_structure", "trace_data_flow", "triage_finding", "write_file", "read_memories"],
    "Auditor": ["read_file", "get_file_structure", "trace_data_flow", "trace_path_verdict", "report_finding", "find_usages", "write_file", "read_memories", "list_memories"],
    "Reproducer": ["read_file", "trace_data_flow", "trace_path_verdict", "write_file", "read_memories"],

    # New Foundation Phase agents
    "Decider": ["read_file", "read_memories", "write_file"],
    "FamilyCoordinator": ["read_file", "read_memories", "write_file", "list_memories"],

    # Specialist agents (generic - can read/write)
    "Specialist": ["read_file", "search_code", "find_usages", "trace_data_flow", "write_file", "read_memories"],

    # Resolution agents
    "Arbiter": ["read_file", "search_code", "trace_data_flow", "find_usages", "write_file", "read_memories", "list_memories"],
}


def get_tools_for_agent_type(agent_type: str) -> list[str]:
    """Get the tool subset for a given agent type."""
    return AGENT_TOOL_SUBSETS.get(agent_type, ["read_file", "write_file"])


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
    ):
        """Initialize the wave dispatcher.

        Args:
            repo_path: Path to the repository being scanned
            filesystem: MemoriesFilesystem instance for agent I/O
            provider_config: LLM provider configuration
            on_agent_start: Callback(task_id, agent_type) when agent starts
            on_agent_complete: Callback(task_id, agent_type, status) when agent completes
        """
        self.repo_path = repo_path
        self.filesystem = filesystem
        self.provider_config = provider_config or {}
        self.on_agent_start = on_agent_start
        self.on_agent_complete = on_agent_complete

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
        """Spawn a single sub-agent as a ReactAgent instance.

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

        try:
            # Get prompt for this agent type (with foundation context if available)
            prompt = self._get_subagent_prompt(task, foundation_context)

            # Get tool subset for this agent type
            allowed_tools = get_tools_for_agent_type(task.agent_type)

            # Import here to avoid circular imports
            from agents.react_agent import ReActSecurityAgent as ReactAgent
            from models.schemas import AgentCreateRequest, ProviderConfig, ProviderType

            # Create a minimal request for the sub-agent
            request = AgentCreateRequest(
                repo_id=self.filesystem.project_id,
                name=f"{task.agent_type}_{task.task_id}",
                provider_config=ProviderConfig(
                    provider=self.provider_config.get("provider", ProviderType.ANTHROPIC),
                    model=self.provider_config.get("model", "claude-sonnet-4-20250514"),
                ),
                time_budget_seconds=task.time_budget,
                custom_prompt=prompt,
            )

            # Create ReactAgent instance with filtered tools
            agent = ReactAgent(
                request=request,
                repo_path=self.repo_path,
                allowed_tools=allowed_tools,
            )

            # Override the system prompt with our task-specific prompt
            agent.system_prompt = prompt

            # Run the agent
            await agent.run()

            completed_at = datetime.utcnow()
            status = "completed" if not agent.error_message else "failed"

            # Notify completion
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
        from agents.deep_audit.subagents import (
            REPO_PROFILER_PROMPT,
            SCOPE_MAPPER_PROMPT_TEMPLATE,
            SINK_HUNTER_PROMPT_TEMPLATE,
            ENTRYPOINT_HUNTER_PROMPT_TEMPLATE,
            AUDITOR_PROMPT_TEMPLATE,
        )

        prompts = {
            "RepoProfiler": REPO_PROFILER_PROMPT,
            "ScopeMapper": SCOPE_MAPPER_PROMPT_TEMPLATE,
            "SinkHunter": SINK_HUNTER_PROMPT_TEMPLATE,
            "EntrypointHunter": ENTRYPOINT_HUNTER_PROMPT_TEMPLATE,
            "Auditor": AUDITOR_PROMPT_TEMPLATE,
        }

        base = prompts.get(agent_type, f"You are a {agent_type} agent. Complete the assigned task.")

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
        # Read outputs from filesystem
        repo_profile_json = await self.filesystem.read_file("/memories/foundation/repo_profile.json")
        scope_map_json = await self.filesystem.read_file("/memories/foundation/scope_map.json")
        threat_model_json = await self.filesystem.read_file("/memories/foundation/threat_model.json")

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
