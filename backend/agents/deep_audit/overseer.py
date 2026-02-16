"""Overseer - Strategic orchestrator for Deep Audit campaigns.

The Overseer orchestrates security audits by spawning specialized sub-agents
via Claude CLI. It operates in phases, dispatching parallel waves of agents
and collecting findings to build a comprehensive vulnerability report.

Architecture:
- Uses the "Gas Town" approach: Claude CLI with subscription auth (no API keys)
- All sub-agents run as separate `claude -p` processes
- Parallel execution within waves, sequential between phases

Phases:
1. Foundation Phase: RepoProfiler, ScopeMapper, ThreatModeler build context
2. Hunting Phase: SinkHunter, EntrypointHunter find signals
3. Wave Loop: Rotate through vulnerability types, verify with DataflowTracer
4. Finalize: Generate report, emit findings

Key responsibilities:
- Time budget enforcement based on scan tier (quick: 5min to evil: 24hr)
- Dispatch of specialized sub-agents via WaveDispatcher
- Collection of findings from sub-agent outputs in /memories/
- Final report generation at /memories/overseer/final_report.md

See agents/deep_audit/README.md for full architecture documentation.
"""

import asyncio
import json
import os
import shutil
import re
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
    FindingClassification,
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
from agents.deep_audit.signal_flow_tracker import SignalFlowTracker
from agents.deep_audit.tools import dispatch as dispatch_tools
from agents.deep_audit.tools import memories as memory_tools
from agents.deep_audit.tools import finalize as finalize_tools
from agents.deep_audit.specialists.registry import (
    SpecialistRegistry,
    SpecialistFamily,
    get_family_for_signal,
    get_specialists_for_signal,
)
from agents.deep_audit.foundation import SignalCategory
from agents.deep_audit.foundation import FoundationContext, SuspiciousSignal, SignalSeverity
from agents.deep_audit.subagents import get_specialist_prompt
from agents.deep_audit.calibration import (
    CalibrationStore,
    ConfidenceCalibrator,
    VerdictRecord,
)
from agents.deep_audit.utils.json_extractor import extract_json_from_output, extract_all_json_objects
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
from services.findings_service import findings_service
from services.sink_signal_service import sink_signal_service, compute_signal_fingerprint
from models.sink_signals import SinkSignalStatus, SinkSignalKind, SinkSignal


# Scan tier time budgets in seconds - aligned with scan_tier_service.py
# NOTE: Authoritative values are in services/scan_tier_service.py:SCAN_TIER_BUDGET_SECONDS
SCAN_TIER_BUDGETS = {
    "quick": 300,           # 5 minutes
    "medium": 900,          # 15 minutes
    "standard": 900,        # 15 minutes (alias for medium)
    "advanced": 2700,       # 45 minutes (was 30min - now matches scan_tier_service)
    "deep": 2700,           # 45 minutes (alias for advanced)
    "pro": 5400,            # 90 minutes (was 60min - now matches scan_tier_service)
    "exhaustive": 5400,     # 90 minutes (alias for pro)
    "ultra": 14400,         # 4 hours
    "evil": 86400,          # 24 hours
}

# Phase budget allocation percentages (v2 pipeline)
# Total must sum to 1.0
PHASE_BUDGET_PCTS = {
    "orientation": 0.10,     # Phase 1: Foundation (RepoProfiler, ScopeMapper, ThreatModeler)
    "understanding": 0.35,   # Phase 2: Deep Understanding (ModuleAnalyzer, TrustBoundaryMapper, DataFlowMapper, InvariantExtractor)
    "hunting": 0.30,         # Phase 3: Targeted Hunting (SinkHunter, InvariantViolationHunter, TrustBoundaryGapHunter)
    "verification": 0.20,    # Phase 4: Specialist routing + Triager
    "finalize": 0.05,        # Phase 5: Report generation
}

# Minimum time (seconds) for each phase regardless of budget percentage
PHASE_MIN_SECONDS = {
    "orientation": 60,
    "understanding": 90,
    "hunting": 60,
    "verification": 60,
    "finalize": 10,
}

# Tiers where understanding phase is skipped (too short)
SKIP_UNDERSTANDING_TIERS = {"quick"}


class Overseer(BaseAgent):
    """Strategic orchestrator for Deep Audit campaigns.

    The Overseer runs a phased audit campaign, spawning sub-agents via Claude CLI
    to perform parallel code analysis. All agents use the user's Claude Code
    subscription for authentication (Gas Town approach).

    Attributes:
        campaign_state: CampaignState tracking hypotheses, findings, and coverage
        filesystem: MemoriesFilesystem for agent artifact I/O
        dispatcher: WaveDispatcher for spawning Claude CLI sub-agents
        time_budget: Total seconds allocated for this scan tier
        waves_completed: Number of waves dispatched so far

    Example:
        >>> overseer = Overseer(request, repo_path, on_message=ws_callback)
        >>> await overseer.analyze()  # Runs full audit campaign
        >>> findings = overseer.findings  # Get confirmed findings
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
        # Use explicit None check to allow time_budget_seconds=0 (though unlikely)
        self.time_budget = (
            request.time_budget_seconds
            if request.time_budget_seconds is not None
            else SCAN_TIER_BUDGETS.get(scan_tier, 300)
        )

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
        # Default to Opus for quality, but allow user override via provider_config
        default_model = "claude-opus-4-5-20251101"
        user_model = (
            request.provider_config.model
            if request.provider_config and request.provider_config.model
            else None
        )
        # Use user's model if provided, otherwise default to Opus
        model_to_use = user_model or default_model

        provider_config = {
            "provider": request.provider_config.provider if request.provider_config else ProviderType.ANTHROPIC,
            "model": model_to_use,
            "use_claude_code_auth": True,  # ALWAYS use Claude CLI subscription auth
        }
        self.provider_config = provider_config  # Store for later use

        # Model for Claude CLI calls
        self.model = model_to_use

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

        # Initialize calibration system for tracking specialist accuracy
        calibration_path = str(self.filesystem.memory_root / "calibration")
        self.calibration_store = CalibrationStore(calibration_path)
        self.calibrator = ConfidenceCalibrator(self.calibration_store)

        # Tier-adaptive quick dismissal threshold
        self.quick_dismissal_threshold = self.QUICK_DISMISSAL_THRESHOLDS.get(scan_tier, 60)

        # Foundation Context from Phase 1 (stored on instance to avoid ContextVar issues)
        self.foundation_ctx: Optional[FoundationContext] = None

        # Security Map from understanding phase (v2)
        self.security_map: Optional[dict] = None

        # Cached set of dismissed signal fingerprints (loaded once before routing phase)
        self._dismissed_fingerprints: Optional[set[str]] = None

        # Pipeline signal flow tracker — records every stage decision for health report
        self.signal_tracker = SignalFlowTracker()

        # Phase budget allocation (v2)
        self.phase_budgets = self._calculate_phase_budgets()

    def _calculate_phase_budgets(self) -> dict[str, float]:
        """Calculate time budget for each phase based on total budget and tier.

        Returns:
            Dict mapping phase name to seconds allocated.
        """
        budgets = {}
        scan_tier = self.campaign_state.scan_tier

        for phase, pct in PHASE_BUDGET_PCTS.items():
            # Skip understanding for quick tier
            if phase == "understanding" and scan_tier in SKIP_UNDERSTANDING_TIERS:
                budgets[phase] = 0
                continue

            allocated = self.time_budget * pct
            minimum = PHASE_MIN_SECONDS.get(phase, 30)
            budgets[phase] = max(allocated, minimum)

        # If understanding is skipped, redistribute its budget to hunting + verification
        if budgets.get("understanding", 0) == 0:
            extra = self.time_budget * PHASE_BUDGET_PCTS["understanding"]
            budgets["hunting"] = budgets.get("hunting", 0) + extra * 0.6
            budgets["verification"] = budgets.get("verification", 0) + extra * 0.4

        print(f"[Overseer] Phase budgets (total={self.time_budget}s, tier={scan_tier}):")
        for phase, secs in budgets.items():
            print(f"[Overseer]   {phase}: {secs:.0f}s ({secs/self.time_budget*100:.0f}%)")

        return budgets

    def _init_tools(self):
        """Initialize tools with filesystem and state references."""
        # Set filesystem for memory tools
        memory_tools.set_filesystem(self.filesystem)

        # Set filesystem and state for finalize tools
        finalize_tools.set_filesystem(self.filesystem)
        finalize_tools.set_campaign_state(self.campaign_state)

        # Set dispatcher for dispatch tools
        dispatch_tools.set_dispatcher(self.dispatcher)

    def _log_task_exception(self, task: asyncio.Task):
        """Callback for background tasks to surface exceptions instead of swallowing them."""
        if not task.cancelled() and task.exception():
            print(f"[Overseer] Background emit failed: {task.exception()}")

    def _on_subagent_start(self, task_id: str, agent_type: str):
        """Callback when a sub-agent starts."""
        t = asyncio.create_task(self._emit_subagent_start(task_id, agent_type))
        t.add_done_callback(self._log_task_exception)

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
        t = asyncio.create_task(self._emit_subagent_complete(task_id, agent_type, status))
        t.add_done_callback(self._log_task_exception)

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

    async def analyze(self):
        """Run the Overseer orchestration loop (v2 pipeline).

        Uses a phased dispatch approach with percentage-based budget allocation:
        1. Orientation Phase (10%): RepoProfiler, ScopeMapper, ThreatModeler
        2. Deep Understanding Phase (35%): ModuleAnalyzer, TrustBoundaryMapper,
           DataFlowMapper, InvariantExtractor → builds Security Map
        3. Targeted Hunting Phase (30%): SinkHunter, EntrypointHunter +
           InvariantViolationHunter, TrustBoundaryGapHunter (from Security Map)
        4. Verification Phase (20%): Specialist routing + invariant-aware Triager
        5. Finalize Phase (5%): Report generation

        All sub-agents use Claude CLI with Claude Code subscription auth.
        Phase 2 is skipped for 'quick' tier scans.
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

            # Call dispatcher directly instead of through dispatch_tools to avoid ContextVar issues
            # dispatch_tools.dispatch_foundation_phase() relies on ContextVar which may not propagate
            # across async task boundaries correctly
            foundation_wave_result, foundation_ctx = await self.dispatcher.dispatch_foundation_phase()
            print(f"[Overseer] Foundation Phase complete: all_succeeded={foundation_wave_result.all_succeeded}")

            # Store Foundation Context on instance for direct access (avoids ContextVar issues)
            self.foundation_ctx = foundation_ctx
            # Also store in dispatch_tools for backward compatibility
            if foundation_ctx:
                dispatch_tools.set_foundation_context(foundation_ctx)
                print(f"[Overseer] Foundation Context built: languages={foundation_ctx.repo_profile.languages}")
                print(f"[Overseer] Foundation Context: frameworks={foundation_ctx.repo_profile.frameworks}")
            else:
                print(f"[Overseer] WARNING: Foundation Context was NOT built")

            # Update flow node status
            if foundation_node:
                flow_service.update_node_status(self.id, foundation_node.id, "completed")
            await self.emit_flow_update()

            # Check for cancellation
            if self._cancelled:
                return

            # Check foundation result
            if not foundation_wave_result.all_succeeded:
                await self.emit_log("Foundation Phase had failures, continuing with partial results...")
                if foundation_node:
                    flow_service.update_node_status(self.id, foundation_node.id, "failed")
                for r in foundation_wave_result.results:
                    if r.status != "completed":
                        print(f"[Overseer] Foundation agent {r.agent_type} failed: {r.error}")

            # Save state checkpoint after Phase 1
            await self._save_campaign_state()

            # Check time budget
            if self.campaign_state.time_remaining() <= 0:
                await self.emit_log("Time budget exhausted after Foundation Phase.")
                finalize_tools.finalize_report("Time budget exhausted after Foundation Phase.")
                await self._process_findings()
                return

            # === PHASE 2: DEEP UNDERSTANDING (v2) ===
            # Build Security Map: trust boundaries, invariants, data flows, module analysis
            # Skip for quick tier (not enough time budget)
            scan_tier = self.campaign_state.scan_tier
            if scan_tier not in SKIP_UNDERSTANDING_TIERS and self.phase_budgets.get("understanding", 0) > 0:
                await self.emit_log("Phase 2: Running Deep Understanding Phase...")
                print("[Overseer] Dispatching Understanding Phase sub-agents...")

                # Create flow node for Understanding Phase
                understanding_node = flow_service.add_node(
                    self.id,
                    node_type="analysis",
                    label="Phase 2: Deep Understanding",
                    parent_id=root_node.id if root_node else None,
                    data={"phase": "understanding", "agents": ["ModuleAnalyzer", "TrustBoundaryMapper", "DataFlowMapper", "InvariantExtractor"]},
                )
                if understanding_node:
                    flow_service.update_node_status(self.id, understanding_node.id, "running")
                await self.emit_flow_update()

                # Calculate per-agent budget from phase budget (4 agents run in parallel)
                understanding_budget = self.phase_budgets["understanding"]
                per_agent_budget = max(60, min(1800, int(understanding_budget * 0.8)))  # 80% to agents, 20% overhead

                understanding_result, security_map = await self.dispatcher.dispatch_understanding_phase(
                    foundation_context=foundation_ctx,
                    time_budget_per_agent=per_agent_budget,
                )

                # Store security map for use by hunting and verification phases
                self.security_map = security_map

                # Update flow node status
                if understanding_node:
                    understanding_status = "completed" if understanding_result.all_succeeded else "failed"
                    flow_service.update_node_status(self.id, understanding_node.id, understanding_status)
                await self.emit_flow_update()

                if security_map:
                    n_invariants = len(security_map.get("invariants", {}).get("invariants", []))
                    n_boundaries = len(security_map.get("trust_boundaries", {}).get("boundaries", security_map.get("trust_boundaries", {}).get("trust_boundaries", [])))
                    n_flows = len(security_map.get("data_flows", {}).get("flows", security_map.get("data_flows", {}).get("data_flows", [])))
                    print(f"[Overseer] Security Map: {n_invariants} invariants, {n_boundaries} boundaries, {n_flows} flows")
                    await self.emit_log(f"Understanding Phase complete: {n_invariants} invariants, {n_boundaries} boundaries, {n_flows} data flows")

                    # Inject Security Map summary into Foundation Context for all downstream agents
                    if self.foundation_ctx:
                        self.foundation_ctx.security_map_summary = json.dumps(security_map, indent=2)
                else:
                    print("[Overseer] WARNING: Security Map not available")
                    await self.emit_log("Understanding Phase complete (no Security Map built)")

                # Check for cancellation
                if self._cancelled:
                    return

                # Save state checkpoint after Phase 2
                await self._save_campaign_state()

                # Check time budget
                if self.campaign_state.time_remaining() <= 0:
                    await self.emit_log("Time budget exhausted after Understanding Phase.")
                    finalize_tools.finalize_report("Time budget exhausted after Understanding Phase.")
                    await self._process_findings()
                    return
            else:
                print(f"[Overseer] Skipping Understanding Phase (tier={scan_tier})")
                await self.emit_log(f"Skipping Understanding Phase (tier={scan_tier})")

            # === PHASE 3: HUNTING ===
            await self.emit_log("Phase 3: Running Hunting Phase...")
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

            # Calculate sub-agent time budget from hunting phase budget
            # Agents run in parallel, so each gets ~80% of the phase wall-clock budget
            # (matching understanding phase formula; 20% reserved for dispatch overhead)
            hunting_phase_budget = self.phase_budgets.get("hunting", self.campaign_state.time_remaining() * 0.3)
            remaining = self.campaign_state.time_remaining()
            subagent_budget = max(120, min(1800, int(min(remaining, hunting_phase_budget) * 0.8)))

            # Build hunting tasks — standard SinkHunter + EntrypointHunter
            hunting_tasks = [
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
            ]

            # v2: Add targeted hunters if Security Map is available
            if self.security_map:
                targeted_tasks = self._build_targeted_hunting_tasks(subagent_budget)
                hunting_tasks.extend(targeted_tasks)
                print(f"[Overseer] Added {len(targeted_tasks)} targeted hunters from Security Map")

            hunting_wave = WavePlan(
                wave_id=1,
                tasks=hunting_tasks,
                rationale="Hunting Phase: Find signals for verification (+ targeted hunters from Security Map)",
            )

            # Use foundation_ctx from Foundation Phase (already available in local scope)
            # This avoids ContextVar issues that can occur across async boundaries
            if foundation_ctx is None:
                print("[Overseer] WARNING: Foundation Context not available - Hunting agents will run without context")
                await self.emit_log("WARNING: Foundation Context not available - analysis may be less accurate")
            hunting_result = await self.dispatcher.dispatch_wave(hunting_wave, foundation_context=foundation_ctx)
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

            # Save state checkpoint after Phase 3 (Hunting)
            await self._save_campaign_state()

            # Check for cancellation
            if self._cancelled:
                return

            # Check time budget
            if self.campaign_state.time_remaining() <= 0:
                await self.emit_log("Time budget exhausted after Hunting Phase.")
                finalize_tools.finalize_report("Time budget exhausted after Hunting Phase.")
                await self._process_findings()
                return

            # === PHASE 3b: WAVE LOOP ===
            # Continue dispatching waves until hunting budget is exhausted
            # Use percentage-based budget: reserve verification + finalize time
            verification_budget = self.phase_budgets.get("verification", max(60, self.time_budget * 0.20))
            finalize_budget = self.phase_budgets.get("finalize", max(10, self.time_budget * 0.05))
            TIME_RESERVED_FOR_ROUTING = max(120, int(verification_budget + finalize_budget))
            # Minimum time to run one wave (subagent execution + overhead)
            MIN_WAVE_EXECUTION_TIME = 60
            # Exit wave loop when we have less than reserved + one wave worth of time
            MIN_TIME_FOR_WAVE = TIME_RESERVED_FOR_ROUTING + MIN_WAVE_EXECUTION_TIME
            MAX_WAVES = 50  # Safety limit
            # Also limit waves based on time: at most 1 wave per 2 minutes of budget
            MAX_WAVES_BY_TIME = max(1, self.time_budget // 120)
            EFFECTIVE_MAX_WAVES = min(MAX_WAVES, MAX_WAVES_BY_TIME)

            print(f"[Overseer] Time budget: {self.time_budget}s, reserving {TIME_RESERVED_FOR_ROUTING}s for routing, max waves: {EFFECTIVE_MAX_WAVES}")

            # Different vulnerability types to hunt for in rotation
            HUNT_FOCUSES = [
                ("SQL injection, command injection, code execution", "injection"),
                ("SSRF, open redirect, path traversal", "network"),
                ("Deserialization, unsafe reflection, type confusion", "deserialization"),
                ("Memory corruption, buffer overflow, use-after-free", "memory"),
                ("Authentication bypass, authorization flaws, privilege escalation", "auth"),
                ("Cryptographic weaknesses, insecure randomness, hardcoded secrets", "crypto"),
                ("Race conditions, TOCTOU, concurrency bugs", "race"),
                ("Input validation, XSS, template injection", "input"),
                ("IDOR, broken access control, insecure direct object reference", "idor"),
                ("Mass assignment, parameter pollution, unvalidated redirect", "api_misuse"),
                ("State invariant breaks, business logic flaws, workflow bypass", "logic"),
                ("Weak randomness, predictable tokens, insufficient entropy", "randomness"),
                ("Information disclosure, verbose errors, debug endpoints", "disclosure"),
                ("Dependency vulnerabilities, outdated libraries, known CVEs", "supply_chain"),
            ]

            while (self.campaign_state.time_remaining() > MIN_TIME_FOR_WAVE
                   and self.waves_completed < EFFECTIVE_MAX_WAVES
                   and not self._cancelled):

                self.waves_completed += 1
                wave_num = self.waves_completed  # Wave number matches completed count
                remaining = self.campaign_state.time_remaining()

                # Pick a hunt focus based on wave number (rotate through focuses)
                # Wave 1 uses focus index 0, wave 2 uses index 1, etc.
                focus_idx = (wave_num - 1) % len(HUNT_FOCUSES)
                hunt_focus, focus_name = HUNT_FOCUSES[focus_idx]

                await self.emit_log(f"Wave {wave_num}: {remaining:.0f}s remaining - hunting for {focus_name} vulnerabilities")
                print(f"[Overseer] Starting Wave {wave_num} with {remaining:.0f}s remaining, focus: {focus_name}")

                # Create flow node for this wave
                wave_node = flow_service.add_node(
                    self.id,
                    node_type="scan",
                    label=f"Wave {wave_num}: {focus_name.title()}",
                    parent_id=root_node.id if root_node else None,
                    data={"phase": "hunting", "wave": wave_num, "focus": focus_name, "time_remaining": remaining},
                )
                if wave_node:
                    flow_service.update_node_status(self.id, wave_node.id, "running")
                await self.emit_flow_update()

                # Calculate sub-agent time budget for this wave
                # Give each agent 15% of remaining time, min 60s, max 600s
                subagent_budget = max(60, min(600, int(remaining * 0.15)))

                # Build wave tasks - ALWAYS include SinkHunter with focused objective
                tasks = []
                signals_count = len(self.campaign_state.confirmed_findings)

                # Always hunt for MORE vulnerabilities with a specific focus
                tasks.append(DispatchTask(
                    agent_type="SinkHunter",
                    objective=f"Hunt specifically for {hunt_focus} vulnerabilities. Look for dangerous function calls, unsafe patterns, and exploitable code paths.",
                    scope=self.repo_path_str,
                    deliverable=f"/memories/waves/wave_{wave_num}/sinks_{focus_name}.json",
                    time_budget=subagent_budget,
                ))

                # Add flow node for SinkHunter
                sink_node = flow_service.add_node(
                    self.id,
                    node_type="scan",
                    label=f"SinkHunter: {focus_name}",
                    parent_id=wave_node.id if wave_node else None,
                    data={"agent": "SinkHunter", "focus": focus_name},
                )
                if sink_node:
                    flow_service.update_node_status(self.id, sink_node.id, "running")

                # If we have signals, also verify them
                if signals_count > 0 and wave_num % 2 == 0:
                    # Every other wave, also run verification
                    # Include actual signals in the objective so the agent knows what to verify
                    signals_context = self._format_signals_for_context(max_signals=10)
                    tasks.append(DispatchTask(
                        agent_type="DataflowTracer",
                        objective=f"""Trace dataflow for potential vulnerabilities. For each signal, determine if user input can reach the dangerous sink.

{signals_context}

For each signal above:
1. Find where user input enters the system
2. Trace if that input can reach the vulnerable code
3. Check for sanitization/validation along the path
4. Determine if the vulnerability is exploitable

Output JSON with your analysis for each signal.""",
                        scope=self.repo_path_str,
                        deliverable=f"/memories/waves/wave_{wave_num}/dataflow_trace.json",
                        time_budget=subagent_budget,
                    ))

                    # Add flow node for DataflowTracer
                    trace_node = flow_service.add_node(
                        self.id,
                        node_type="analysis",
                        label="DataflowTracer",
                        parent_id=wave_node.id if wave_node else None,
                        data={"agent": "DataflowTracer", "signals": signals_count},
                    )
                    if trace_node:
                        flow_service.update_node_status(self.id, trace_node.id, "running")

                await self.emit_flow_update()

                # Dispatch the wave
                wave_plan = WavePlan(
                    wave_id=wave_num,
                    tasks=tasks,
                    rationale=f"Wave {wave_num}: Hunting {focus_name} + verification",
                )

                try:
                    # Use local foundation_ctx from Phase 1, not ContextVar which may not propagate across async tasks
                    wave_result = await self.dispatcher.dispatch_wave(wave_plan, foundation_context=foundation_ctx)
                    self.campaign_state.current_wave = wave_num

                    # Update flow node statuses
                    for result in wave_result.results:
                        status = "completed" if result.status == "completed" else "failed"
                        # Find and update the agent's flow node
                        if result.agent_type == "SinkHunter" and sink_node:
                            flow_service.update_node_status(self.id, sink_node.id, status)

                    if wave_node:
                        wave_status = "completed" if wave_result.all_succeeded else "failed"
                        flow_service.update_node_status(self.id, wave_node.id, wave_status)
                    await self.emit_flow_update()

                    # Collect any new findings from this wave
                    await self._collect_wave_findings(wave_num)

                    new_signals = len(self.campaign_state.confirmed_findings) - signals_count
                    print(f"[Overseer] Wave {wave_num} complete: {wave_result.all_succeeded}, +{new_signals} new signals")
                    await self.emit_log(f"Wave {wave_num} complete. Found {new_signals} new signals. Total: {len(self.campaign_state.confirmed_findings)}")

                    # === INCREMENTAL ROUTING ===
                    # Route new signals to specialists immediately instead of waiting until end
                    # This gives users faster feedback on vulnerability validity
                    if new_signals > 0 and self.campaign_state.time_remaining() > 120:
                        await self._route_new_signals_incrementally(signals_count, wave_num)

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
                await self.emit_log(f"Reserving time for Phase 4 routing ({self.campaign_state.time_remaining():.0f}s remaining, reserved {TIME_RESERVED_FOR_ROUTING}s)")
                print(f"[Overseer] Exiting wave loop to reserve time for routing: {self.campaign_state.time_remaining():.0f}s remaining")
            elif self.waves_completed >= EFFECTIVE_MAX_WAVES:
                await self.emit_log(f"Maximum waves reached ({EFFECTIVE_MAX_WAVES} for {self.time_budget}s budget)")

            # Save state checkpoint after wave loop
            await self._save_campaign_state()

            # === PHASE 4: VERIFICATION (Signal Routing) ===
            # Route each signal through: Decider → FamilyCoordinator → Specialist → Triager
            # v2: Triager now has invariant awareness from Security Map
            findings_count = len(self.campaign_state.confirmed_findings)
            time_remaining = self.campaign_state.time_remaining()
            print(f"[Overseer] Phase 4 (Verification) check: {findings_count} findings, {time_remaining:.0f}s remaining")
            await self.emit_log(f"Phase 4 (Verification) check: {findings_count} findings, {time_remaining:.0f}s remaining")

            if findings_count > 0 and time_remaining > 60:
                await self._route_all_signals()
            else:
                skip_reasons = []
                if findings_count == 0:
                    skip_reasons.append("no findings collected")
                if time_remaining <= 60:
                    skip_reasons.append(f"insufficient time ({time_remaining:.0f}s <= 60s)")
                reason_str = ", ".join(skip_reasons)
                print(f"[Overseer] Skipping Phase 4 (specialists): {reason_str}")
                await self.emit_log(f"Skipping Phase 4 (specialists): {reason_str}")

            # Save state checkpoint after Phase 4
            await self._save_campaign_state()

            # === PHASE 5: FINALIZE ===
            await self.emit_log("Phase 5: Generating final report...")

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
            # Save state on crash for potential recovery
            await self._save_campaign_state()

        # Convert confirmed findings to Finding objects
        await self._process_findings()

        # Print pipeline health report — makes signal drops visible
        self.signal_tracker.print_report()
        await self.emit_log(self.signal_tracker.summary_text())
        await self.emit(WSMessageType.PROGRESS, {
            "type": "pipeline_health",
            "summary": self.signal_tracker.summary(),
        })

    def _extract_json_from_output(self, content: str) -> Optional[dict]:
        """Extract JSON from Claude CLI output. Delegates to shared util."""
        return extract_json_from_output(content)

    async def _save_campaign_state(self):
        """Persist campaign state for crash recovery.

        Saves to /memories/overseer/campaign_state.json after each phase
        transition so progress survives crashes.
        """
        try:
            state_dict = {
                "project_id": self.campaign_state.project_id,
                "scan_tier": self.campaign_state.scan_tier,
                "deadline": self.campaign_state.deadline,
                "phase": self.campaign_state.phase if isinstance(self.campaign_state.phase, str) else self.campaign_state.phase.value if hasattr(self.campaign_state.phase, "value") else str(self.campaign_state.phase),
                "current_wave": self.campaign_state.current_wave,
                "confirmed_findings_count": len(self.campaign_state.confirmed_findings),
                "confirmed_findings": self.campaign_state.confirmed_findings,
                "waves_completed": self.waves_completed,
                "saved_at": datetime.utcnow().isoformat(),
            }
            # Strip non-serializable _typed_signal from findings before saving
            for f in state_dict.get("confirmed_findings", []):
                f.pop("_typed_signal", None)
            self.filesystem.write_file(
                "/memories/overseer/campaign_state.json",
                json.dumps(state_dict, indent=2, default=str),
            )
            print(f"[Overseer] Campaign state saved (phase={state_dict['phase']}, findings={state_dict['confirmed_findings_count']})")
        except Exception as e:
            print(f"[Overseer] Could not save campaign state: {e}")

    async def _load_campaign_state(self) -> bool:
        """Try to load saved campaign state for crash recovery.

        Returns True if state was successfully restored.
        """
        try:
            content = self.filesystem.read_file("/memories/overseer/campaign_state.json")
            if content:
                data = json.loads(content)
                # Restore key fields
                saved_findings = data.get("confirmed_findings", [])
                if saved_findings:
                    self.campaign_state.confirmed_findings = saved_findings
                    self.waves_completed = data.get("waves_completed", 0)
                    self.campaign_state.current_wave = data.get("current_wave", 0)
                    print(f"[Overseer] Restored campaign state from checkpoint (phase: {data.get('phase')}, findings: {len(saved_findings)})")
                    return True
        except Exception as e:
            print(f"[Overseer] Could not load campaign state: {e}")
        return False

    def _format_signals_for_context(self, max_signals: int = 10) -> str:
        """Format collected signals into a prompt-friendly string for verification agents."""
        if not self.campaign_state.confirmed_findings:
            return "No signals collected yet."

        signals = self.campaign_state.confirmed_findings[:max_signals]
        lines = [f"## {len(self.campaign_state.confirmed_findings)} Signals Found (showing top {len(signals)}):\n"]

        for i, signal in enumerate(signals, 1):
            location = signal.get("location", "unknown location")
            vuln_type = signal.get("vulnerability_type", signal.get("type", "unknown"))
            title = signal.get("title", "Untitled")
            description = signal.get("description", "")[:200]
            code = signal.get("code_snippet", "")[:150]

            lines.append(f"### Signal {i}: {title}")
            lines.append(f"- **Type:** {vuln_type}")
            lines.append(f"- **Location:** {location}")
            if description:
                lines.append(f"- **Description:** {description}")
            if code:
                lines.append(f"- **Code:** `{code}`")
            lines.append("")

        return "\n".join(lines)

    def _build_targeted_hunting_tasks(self, base_budget: int) -> list:
        """Build targeted hunting tasks from Security Map invariants and trust boundary gaps.

        Creates InvariantViolationHunter and TrustBoundaryGapHunter tasks
        based on what the understanding phase discovered.

        Args:
            base_budget: Base time budget per agent in seconds

        Returns:
            List of DispatchTask for targeted hunters
        """
        from agents.deep_audit.dispatcher import DispatchTask
        from agents.deep_audit.subagents import (
            get_invariant_violation_hunter_prompt,
            get_trust_boundary_gap_hunter_prompt,
        )

        tasks = []

        if not self.security_map:
            return tasks

        # Extract invariants to verify
        invariants_data = self.security_map.get("invariants", {})
        invariants = invariants_data.get("invariants", [])

        # Prioritize: high-confidence invariants that are critical to security
        for i, inv in enumerate(invariants[:3]):  # Cap at 3 invariant hunters
            statement = inv.get("statement", inv.get("invariant", ""))
            inv_id = inv.get("id", f"inv_{i}")
            confidence = inv.get("confidence", "medium")

            if not statement:
                continue

            tasks.append(DispatchTask(
                agent_type="InvariantViolationHunter",
                objective=f"Verify invariant: {statement}",
                scope=self.repo_path_str,
                deliverable=f"/memories/waves/wave_1/invariant_{inv_id}.json",
                time_budget=base_budget,
                constraints=f"INVARIANT_ID: {inv_id}\nINVARIANT: {statement}\nCONFIDENCE: {confidence}",
            ))

        # Extract trust boundary gaps
        tb_data = self.security_map.get("trust_boundaries", {})
        gaps = tb_data.get("gaps", tb_data.get("missing_enforcement", []))

        for i, gap in enumerate(gaps[:2]):  # Cap at 2 gap hunters
            desc = gap.get("description", gap.get("gap", str(gap)))
            gap_id = gap.get("id", f"gap_{i}")

            if not desc or not isinstance(desc, str):
                continue

            tasks.append(DispatchTask(
                agent_type="TrustBoundaryGapHunter",
                objective=f"Investigate trust boundary gap: {desc[:200]}",
                scope=self.repo_path_str,
                deliverable=f"/memories/waves/wave_1/boundary_gap_{gap_id}.json",
                time_budget=base_budget,
                constraints=f"GAP_ID: {gap_id}\nGAP: {desc}",
            ))

        return tasks

    async def _collect_findings_from_signals(self):
        """Read sub-agent outputs and extract findings from signals."""
        collection_errors = []

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
                        sinks_data.get("data_flows") or
                        sinks_data.get("items") or
                        (sinks_data if isinstance(sinks_data, list) else [])
                    )
                    if isinstance(signals, list):
                        for signal in signals:
                            if isinstance(signal, dict):
                                # Convert signal to finding format
                                # CRITICAL: Preserve signal_id for downstream routing
                                # Generate title from category if no explicit title
                                category = signal.get("category", signal.get("vulnerability_type", "unknown"))
                                default_title = f"Potential {category.replace('_', ' ').title()}"
                                raw_sev = signal.get("severity", "medium")
                                finding = {
                                    "signal_id": signal.get("signal_id", f"sig-{uuid.uuid4().hex[:8]}"),
                                    "title": signal.get("title", signal.get("type", default_title)),
                                    "description": signal.get("description", signal.get("reasoning", signal.get("why_suspicious", ""))),
                                    "severity": raw_sev.lower() if isinstance(raw_sev, str) else "medium",
                                    "category": category,
                                    "vulnerability_type": signal.get("type", signal.get("sink_type", "unknown")),
                                    "location": signal.get("location", signal.get("file_path", "")),
                                    "file_path": signal.get("file_path", signal.get("location", "")),
                                    "line_start": signal.get("line_start", signal.get("line_number")),
                                    "line_end": signal.get("line_end"),
                                    "code_snippet": signal.get("code_snippet", signal.get("code", "")),
                                    "why_suspicious": signal.get("why_suspicious", signal.get("description", "")),
                                    "remediation": signal.get("remediation", signal.get("recommendation", "")),
                                    "confidence": signal.get("confidence", 0.7),
                                    "entry_point_trace": signal.get("entry_point_trace", []),
                                    "sink_function": signal.get("sink_function"),
                                    "guards_present": signal.get("guards_present", []),
                                    "next_steps": signal.get("next_steps", []),
                                    "hunter_notes": signal.get("hunter_notes", ""),
                                }
                                if self._add_finding_deduped(finding):
                                    # Also construct typed SuspiciousSignal (dual-track)
                                    self._attach_typed_signal(finding)
                        # Emit progress only when signals were actually collected
                        if signals:
                            await self.emit(
                                WSMessageType.PROGRESS,
                                {
                                    "type": "hunting_signals_collected",
                                    "agent": "SinkHunter",
                                    "signals_count": len(signals),
                                    "phase": "hunting",
                                }
                            )
                            print(f"[Overseer] Collected {len(signals)} signals from SinkHunter")
                        else:
                            print("[Overseer] SinkHunter returned no signals")
                else:
                    error_msg = "Could not parse SinkHunter output as JSON"
                    print(f"[Overseer] {error_msg}")
                    collection_errors.append(error_msg)
            else:
                error_msg = "SinkHunter output file is empty"
                print(f"[Overseer] {error_msg}")
                collection_errors.append(error_msg)
        except FileNotFoundError:
            error_msg = "SinkHunter output not found at /memories/signals/sinks.json"
            print(f"[Overseer] {error_msg}")
            collection_errors.append(error_msg)
        except Exception as e:
            error_msg = f"Could not read SinkHunter output: {e}"
            print(f"[Overseer] {error_msg}")
            collection_errors.append(error_msg)

        # Read EntrypointHunter output (for context, not findings)
        try:
            entrypoints_content = self.filesystem.read_file("/memories/signals/entrypoints.json")
            if entrypoints_content:
                # Use consistent JSON extraction (handles Claude's markdown-wrapped output)
                entrypoints_data = self._extract_json_from_output(entrypoints_content)
                if entrypoints_data:
                    entrypoints = entrypoints_data.get("entrypoints", [])
                    self.campaign_state.entrypoints = entrypoints
                    print(f"[Overseer] Found {len(entrypoints)} entrypoints from EntrypointHunter")
                else:
                    error_msg = "Could not parse EntrypointHunter output as JSON"
                    print(f"[Overseer] {error_msg}")
                    collection_errors.append(error_msg)
        except Exception as e:
            error_msg = f"Could not read EntrypointHunter output: {e}"
            print(f"[Overseer] {error_msg}")
            collection_errors.append(error_msg)

        # Report errors to UI for visibility
        if collection_errors:
            await self.emit_log(f"WARNING: {len(collection_errors)} collection error(s): {'; '.join(collection_errors)}")

        await self.emit_log(f"Collected {len(self.campaign_state.confirmed_findings)} potential findings from sub-agents")

    def _add_finding_deduped(self, finding: dict) -> bool:
        """Add a finding to confirmed_findings if not a duplicate.

        Deduplicates on (file_path, line_start, normalized_category) to prevent the same
        sink from being routed through the full pipeline multiple times across waves.

        Returns:
            True if the finding was added, False if it was a duplicate.
        """
        raw_cat = finding.get("category", "")
        normalized_cat = raw_cat.lower().replace(" ", "_").replace("-", "_") if raw_cat else ""
        fp = (
            finding.get("file_path", ""),
            finding.get("line_start") or 0,
            normalized_cat,
        )
        if fp in self.campaign_state._signal_fingerprints:
            return False
        self.campaign_state._signal_fingerprints.add(fp)
        self.campaign_state.confirmed_findings.append(finding)
        return True

    def _attach_typed_signal(self, finding: dict):
        """Construct a SuspiciousSignal and attach it to the finding dict.

        Dual-track approach: finding dict remains the primary data carrier,
        but a typed SuspiciousSignal is attached for use by specialist context
        building (to_specialist_context()) and campaign state tracking.
        """
        try:
            cat_str = finding.get("category", "unknown").lower().replace(" ", "_").replace("-", "_")
            sev_str = finding.get("severity", "medium").upper()
            typed_signal = SuspiciousSignal(
                signal_id=finding["signal_id"],
                category=SignalCategory(cat_str) if cat_str != "unknown" else SignalCategory.UNKNOWN,
                severity=SignalSeverity(sev_str.lower()) if sev_str.lower() in ("critical", "high", "medium", "low", "info") else SignalSeverity.MEDIUM,
                file_path=finding.get("file_path", ""),
                line_start=finding.get("line_start") or 0,
                code_snippet=finding.get("code_snippet", ""),
                why_suspicious=finding.get("why_suspicious", ""),
                entry_point_trace=finding.get("entry_point_trace", []),
                sink_function=finding.get("sink_function"),
                hunter_notes=finding.get("hunter_notes"),
            )
            finding["_typed_signal"] = typed_signal
            self.campaign_state.add_signal(typed_signal)
        except (ValueError, KeyError) as e:
            print(f"[Overseer] Could not create typed signal for {finding.get('signal_id', '?')}: {e}")

    async def _collect_wave_findings(self, wave_num: int):
        """Collect findings from a specific wave's outputs."""
        wave_dir = f"/memories/waves/wave_{wave_num}"

        # Dynamically find all signal files in wave directory
        # Deliverables use patterns like sinks_{focus_name}.json, not just sinks.json
        try:
            all_files = self.filesystem.list_directory(wave_dir)
        except FileNotFoundError:
            print(f"[Overseer] Wave {wave_num}: Directory not found: {wave_dir}")
            return

        # Match files by prefix pattern (handles sinks.json, sinks_memory.json, etc.)
        sink_files = [f for f in all_files if f.startswith("sinks") and f.endswith(".json")]
        dataflow_files = [f for f in all_files if "dataflow" in f.lower() and f.endswith(".json")]
        auth_files = [f for f in all_files if "auth" in f.lower() and f.endswith(".json")]

        files_to_check = [f"{wave_dir}/{f}" for f in sink_files + dataflow_files + auth_files]

        if not files_to_check:
            print(f"[Overseer] Wave {wave_num}: No signal files found in {wave_dir}")
            return

        for file_path in files_to_check:
            try:
                content = self.filesystem.read_file(file_path)
                if content:
                    data = self._extract_json_from_output(content)
                    if not data:
                        # Fallback: try extracting all JSON objects from multi-object output
                        all_objects = extract_all_json_objects(content)
                        if all_objects:
                            SIGNAL_KEYS = {"signals", "findings", "sinks", "data_flows", "traces", "items"}
                            for obj in all_objects:
                                if isinstance(obj, dict) and any(k in obj for k in SIGNAL_KEYS):
                                    data = obj
                                    break
                            if not data:
                                data = all_objects[0]
                    if data:
                        # Extract signals/findings from various formats
                        signals = (
                            data.get("signals") or
                            data.get("findings") or
                            data.get("sinks") or
                            data.get("data_flows") or
                            data.get("traces") or
                            data.get("items") or
                            (data if isinstance(data, list) else [])
                        )
                        if isinstance(signals, list):
                            for signal in signals:
                                if isinstance(signal, dict):
                                    # CRITICAL: Preserve signal_id for downstream routing
                                    # Generate title from category if no explicit title (SinkHunter outputs category, not title)
                                    category = signal.get("category", signal.get("vulnerability_type", "unknown"))
                                    default_title = f"Potential {category.replace('_', ' ').title()}"
                                    raw_severity = signal.get("severity", "medium")
                                    finding = {
                                        "signal_id": signal.get("signal_id", f"sig-{uuid.uuid4().hex[:8]}"),
                                        "title": signal.get("title", signal.get("type", default_title)),
                                        "description": signal.get("description", signal.get("reasoning", signal.get("why_suspicious", ""))),
                                        "severity": raw_severity.lower() if isinstance(raw_severity, str) else "medium",
                                        "category": signal.get("category", signal.get("vulnerability_type", "unknown")),
                                        "vulnerability_type": signal.get("type", signal.get("sink_type", "unknown")),
                                        "location": signal.get("location", signal.get("file_path", "")),
                                        "file_path": signal.get("file_path", signal.get("location", "")),
                                        "line_start": signal.get("line_start", signal.get("line_number")),
                                        "line_end": signal.get("line_end"),
                                        "code_snippet": signal.get("code_snippet", signal.get("code", "")),
                                        "why_suspicious": signal.get("why_suspicious", signal.get("description", "")),
                                        "remediation": signal.get("remediation", signal.get("recommendation", "")),
                                        "confidence": signal.get("confidence", 0.7),
                                        "entry_point_trace": signal.get("entry_point_trace", []),
                                        "sink_function": signal.get("sink_function"),
                                        "guards_present": signal.get("guards_present", []),
                                        "next_steps": signal.get("next_steps", []),
                                        "hunter_notes": signal.get("hunter_notes", ""),
                                    }
                                    if self._add_finding_deduped(finding):
                                        self._attach_typed_signal(finding)
                            if len(signals) > 0:
                                print(f"[Overseer] Wave {wave_num}: Collected {len(signals)} signals from {file_path}")
            except Exception as e:
                print(f"[Overseer] Wave {wave_num}: Could not read {file_path}: {e}")

    def _format_signals_for_specialist(self, signals: list[dict], max_signals: int = 5) -> str:
        """Format signals for a specialist prompt."""
        lines = []
        for i, signal in enumerate(signals[:max_signals], 1):
            location = signal.get("location", signal.get("file_path", "unknown"))
            title = signal.get("title", "Untitled")
            code = signal.get("code_snippet", "")[:200]
            why = signal.get("why_suspicious", signal.get("description", ""))[:150]

            lines.append(f"### Signal {i}: {title}")
            lines.append(f"- **Location:** {location}")
            if code:
                lines.append(f"- **Code:** `{code}`")
            if why:
                lines.append(f"- **Suspicious because:** {why}")
            lines.append("")

        return "\n".join(lines)

    async def _collect_specialist_verdicts(self):
        """Collect verdicts from specialist outputs."""
        try:
            # List files in verification directory
            verification_files = self.filesystem.list_directory("/memories/verification/")
            for filename in verification_files:
                if filename.endswith("_verdict.json"):
                    content = self.filesystem.read_file(f"/memories/verification/{filename}")
                    if content:
                        verdict_data = self._extract_json_from_output(content)
                        if verdict_data:
                            verdict = verdict_data.get("verdict", "unknown")
                            signal_id = verdict_data.get("signal_id", "")

                            # Skip if no signal_id - can't match to a finding
                            if not signal_id:
                                print(f"[Overseer] WARNING: Verdict in {filename} has no signal_id, cannot match")
                                continue

                            print(f"[Overseer] Specialist verdict: {signal_id} -> {verdict}")

                            # Find and update the signal
                            matched = False
                            for finding in self.campaign_state.confirmed_findings:
                                if finding.get("signal_id") == signal_id:
                                    matched = True
                                    if verdict == "vulnerable":
                                        finding["verified"] = True
                                        finding["confidence"] = verdict_data.get("confidence", 0.9)
                                    elif verdict == "not_vulnerable":
                                        finding["dismissed_by_specialist"] = True
                                        finding["specialist_reasoning"] = verdict_data.get("reasoning", "")
                                    break

                            if not matched:
                                print(f"[Overseer] WARNING: Verdict for signal {signal_id} not found in confirmed_findings")
        except Exception as e:
            print(f"[Overseer] Error collecting specialist verdicts: {e}")

    # =========================================================================
    # SIGNAL ROUTING PIPELINE
    # =========================================================================

    async def _route_signal_through_pipeline(self, signal: dict) -> Optional[dict]:
        """Route a single signal through Decider → FamilyCoordinator → Specialist → [Devil's Advocate] → Triager.

        Args:
            signal: A signal dict from SinkHunter with keys like signal_id, category, file_path, etc.

        Returns:
            Finding dict if signal is verified as vulnerability, None if dismissed.
        """
        signal_id = signal.get("signal_id", f"sig-{uuid.uuid4().hex[:8]}")
        signal_severity = signal.get("severity", "MEDIUM").upper()
        signal_title = signal.get("title", "Untitled")

        # Track this signal through the pipeline
        self.signal_tracker.enter(signal_id, signal_title, signal_severity)

        # Pre-check: skip signals that were dismissed in a previous scan.
        # Load cache on first call, then O(1) set lookups for subsequent signals.
        if self._dismissed_fingerprints is None:
            await self._load_dismissed_fingerprints()
        if self._dismissed_fingerprints:
            try:
                category = signal.get("category", signal.get("vulnerability_type", "unknown"))
                file_path = signal.get("file_path", signal.get("location", ""))
                line_number = signal.get("line_start", signal.get("line_number"))
                label = signal.get("title", signal.get("why_suspicious", category))
                fingerprint = compute_signal_fingerprint(
                    kind=category, file_path=file_path, line_number=line_number, label=label,
                )
                if fingerprint in self._dismissed_fingerprints:
                    print(f"[Overseer] Signal {signal_id}: Previously dismissed (fingerprint {fingerprint}), skipping")
                    self.signal_tracker.record_drop(signal_id, "pre_check", "previously dismissed")
                    return None
            except Exception as e:
                print(f"[Overseer] Dismissal pre-check failed for {signal_id}: {e}")

        # Stage 1: Decider - Should we investigate?
        decider_result = await self._run_decider(signal)
        if not decider_result or decider_result.get("decision") == "dismiss":
            rationale = (decider_result or {}).get("rationale", "no rationale")
            print(f"[Overseer] Signal {signal_id}: Dismissed by Decider")
            self.signal_tracker.record_drop(signal_id, "decider", rationale)
            return None
        self.signal_tracker.record_stage(signal_id, "decider", "investigate")

        # Stage 2: FamilyCoordinator - Which specialist? What context?
        coordinator_result = await self._run_family_coordinator(signal, decider_result)
        if not coordinator_result:
            print(f"[Overseer] Signal {signal_id}: FamilyCoordinator failed, using defaults")
            coordinator_result = {"primary_specialist": "mass_assignment_auditor", "family": "api_design", "context_for_specialist": ""}
        family = coordinator_result.get("family", "unknown")
        self.signal_tracker.record_stage(signal_id, "coordinator", family)

        # Stage 3: Specialist - Technical validation
        specialist_start = time.time()
        specialist_result = await self._run_specialist(signal, coordinator_result)
        specialist_duration = time.time() - specialist_start

        specialist_verdict = (specialist_result or {}).get("verdict", "error")
        if specialist_verdict in ("not_vulnerable", "invalid", "dismiss", "dismissed"):
            self.signal_tracker.record_stage(
                signal_id, "specialist", specialist_verdict,
                (specialist_result or {}).get("reasoning", "")[:200],
            )
        else:
            self.signal_tracker.record_stage(signal_id, "specialist", specialist_verdict)

        # Stage 3.5: Devil's Advocate - Challenge quick dismissals of high-severity signals
        da_result = None
        if specialist_result and self._should_challenge_specialist(
            signal_severity, specialist_result, specialist_duration
        ):
            print(f"[Overseer] Signal {signal_id}: Challenging specialist dismissal with Devil's Advocate")
            challenge_result = await self._run_devils_advocate(signal, specialist_result)
            if challenge_result and challenge_result.get("recommendation") == "reconsider":
                da_result = challenge_result
                specialist_result["challenged"] = True
                specialist_result["challenge_findings"] = challenge_result.get("challenge_findings", [])
                if challenge_result.get("new_evidence"):
                    specialist_result["verdict"] = "needs_more_info"
                    specialist_result["devils_advocate_override"] = True
                self.signal_tracker.record_stage(signal_id, "devils_advocate", "reconsider")
            else:
                self.signal_tracker.record_stage(signal_id, "devils_advocate", "uphold")

        # Stage 4: Triager - Final classification (even if specialist failed/errored)
        finding = await self._run_triager(signal, specialist_result, da_result=da_result)

        if finding:
            classification = finding.get("classification", "unknown")
            self.signal_tracker.record_stage(signal_id, "triager", classification)
        else:
            self.signal_tracker.record_drop(signal_id, "triager", "dismissed/by_design")

        return finding

    # Threshold for considering a specialist dismissal "quick" (seconds), by scan tier.
    # Higher tiers allow more analysis time before considering a dismissal suspicious.
    QUICK_DISMISSAL_THRESHOLDS = {
        "quick": 30, "medium": 45, "advanced": 60,
        "pro": 90, "ultra": 120, "evil": 180,
    }

    def _should_challenge_specialist(
        self,
        signal_severity: str,
        specialist_result: dict,
        duration_seconds: float,
    ) -> bool:
        """Determine if specialist result should be challenged by Devil's Advocate.

        Triggers:
        - High-severity signal dismissed quickly (< QUICK_DISMISSAL_THRESHOLD_SECONDS)
        - Low confidence dismissal of critical signal
        - Generic reasoning for dismissal
        """
        # Guard: specialist_result must exist
        if not specialist_result:
            return False

        # Only challenge dismissals, not confirmations
        verdict = specialist_result.get("verdict", "").lower()
        if verdict not in ("not_vulnerable", "invalid", "dismiss", "dismissed"):
            return False

        # Always challenge quick dismissals of critical/high severity
        if signal_severity in ("CRITICAL", "HIGH"):
            # Quick dismissal (< threshold seconds)
            if duration_seconds < self.quick_dismissal_threshold:
                return True
            # Low confidence
            confidence = specialist_result.get("confidence", 100)
            if isinstance(confidence, (int, float)) and confidence < 70:
                return True

        # Challenge MEDIUM severity with stricter thresholds
        if signal_severity == "MEDIUM":
            # Very quick dismissal (half the normal threshold)
            if duration_seconds < self.quick_dismissal_threshold / 2:
                return True
            # Very low confidence
            confidence = specialist_result.get("confidence", 100)
            if isinstance(confidence, (int, float)) and confidence < 50:
                return True

        return False

    async def _run_devils_advocate(self, signal: dict, specialist_result: dict) -> Optional[dict]:
        """Run Devil's Advocate to challenge a specialist dismissal.

        Devil's Advocate tries to prove the specialist wrong by:
        - Finding alternative paths to exploitation
        - Checking for bypass conditions
        - Looking for edge cases the specialist missed
        """
        from agents.deep_audit.subagents import get_devils_advocate_prompt

        signal_id = signal.get("signal_id", "unknown")
        signal_context = json.dumps(signal, indent=2)
        dismissal_verdict = json.dumps(specialist_result, indent=2)

        prompt = get_devils_advocate_prompt(signal_context, dismissal_verdict, signal_id)

        try:
            foundation_ctx = self.foundation_ctx
            result = await self.dispatcher.dispatch_single(
                agent_type="DevilsAdvocate",
                objective=prompt,
                scope=self.repo_path_str,
                deliverable=f"/memories/challenge/{signal.get('signal_id', 'unknown')}_challenge.json",
                time_budget=120,  # 2 minutes for thorough challenge
                foundation_context=foundation_ctx,
            )

            if result and result.output:
                return self._extract_json_from_output(result.output)
            return None

        except Exception as e:
            print(f"[Overseer] Devil's Advocate failed: {e}")
            return None

    async def _run_decider(self, signal: dict) -> Optional[dict]:
        """Stage 1: Decider evaluates if signal is worth investigating.

        Decider looks at each signal individually and decides:
        - investigate: Signal looks promising, route to specialist
        - dismiss: Signal is clearly not a vulnerability (e.g., test code, dead code)

        Args:
            signal: Signal dict from hunter

        Returns:
            Dict with decision and routing info, or None on error
        """
        signal_context = json.dumps(signal, indent=2)

        objective = f"""Evaluate this signal and decide if it's worth investigating.

## Signal to Evaluate
```json
{signal_context}
```

Decide:
- "investigate" if this looks like a real potential vulnerability
- "dismiss" if this is clearly not a vulnerability (test code, unreachable, etc.)

Output your decision as JSON with keys: decision, rationale"""

        try:
            foundation_ctx = self.foundation_ctx
            result = await self.dispatcher.dispatch_single(
                agent_type="Decider",
                objective=objective,
                scope=self.repo_path_str,
                deliverable=f"/memories/routing/decider_{signal.get('signal_id', 'unknown')}.json",
                time_budget=60,  # 1 minute max for decision
                foundation_context=foundation_ctx,
            )

            if result and result.output:
                parsed = self._extract_json_from_output(result.output)
                if parsed:
                    return parsed
                # JSON parse failed - default to investigate (don't drop signals)
                print(f"[Overseer] Decider JSON parse failed, defaulting to investigate")
                return {"decision": "investigate", "parse_error": "Could not parse Decider output"}
            # No output - default to investigate
            return {"decision": "investigate", "no_output": True}

        except Exception as e:
            print(f"[Overseer] Decider failed for signal: {e}")
            # On error, default to investigate (don't drop signals)
            return {"decision": "investigate", "error": str(e)}

    async def _run_family_coordinator(self, signal: dict, decider_result: dict) -> Optional[dict]:
        """Stage 2: FamilyCoordinator picks specialists and provides context.

        IMPORTANT: FamilyCoordinator provides CODE CONTEXT to specialists,
        NOT the threat model. The threat model is only used by Triager.

        Args:
            signal: Signal dict from hunter
            decider_result: Output from Decider stage

        Returns:
            Dict with specialist assignment and context, or None on error
        """
        from agents.deep_audit.foundation import SignalCategory

        # Determine the family for this signal
        category_str = signal.get("category", signal.get("vulnerability_type", "unknown"))
        # Normalize: lowercase, underscored, strip common prefixes from hunters
        normalized_cat = category_str.lower().replace(" ", "_").replace("-", "_")
        for prefix in ("potential_", "possible_", "suspected_"):
            if normalized_cat.startswith(prefix):
                normalized_cat = normalized_cat[len(prefix):]
                break
        try:
            category = SignalCategory(normalized_cat)
            family = get_family_for_signal(category)
        except (ValueError, KeyError):
            # Category-based fallback: try fuzzy matching via registry
            registry_lookup = SpecialistRegistry()
            best_match = registry_lookup.find_best_specialist_for_category(normalized_cat)
            if best_match:
                family = best_match.family
            else:
                family = SpecialistFamily.API_DESIGN  # Last resort fallback

        # Get specialists in this family
        registry = SpecialistRegistry()
        family_specialists = registry.get_by_family(family)
        specialist_list = "\n".join([f"- {s.id}: {s.proficiency}" for s in family_specialists])

        signal_context = json.dumps(signal, indent=2)

        # Include Decider assessment for context
        decider_context = ""
        if decider_result:
            decider_context = f"""
## Decider Assessment
- Recommended action: {decider_result.get('action', decider_result.get('decision', 'unknown'))}
- Priority: {decider_result.get('priority', 'unknown')}
- Reasoning: {decider_result.get('rationale', decider_result.get('reasoning', 'N/A'))}
"""

        objective = f"""Coordinate specialist assignment for this signal.

## Signal
```json
{signal_context}
```
{decider_context}
## Family: {family.value}

## Available Specialists
{specialist_list}

Pick the most appropriate specialist(s) and provide code context they need.
DO NOT include threat model - that's for Triager only.

Output as JSON with: primary_specialist, secondary_specialist (optional), context_for_specialist"""

        try:
            foundation_ctx = self.foundation_ctx
            result = await self.dispatcher.dispatch_single(
                agent_type="FamilyCoordinator",
                objective=objective,
                scope=self.repo_path_str,
                deliverable=f"/memories/routing/coordinator_{signal.get('signal_id', 'unknown')}.json",
                time_budget=90,  # 1.5 minutes
                foundation_context=foundation_ctx,
            )

            if result and result.output:
                coord_result = self._extract_json_from_output(result.output)
                if coord_result:
                    coord_result["family"] = family.value
                return coord_result
            return None

        except Exception as e:
            print(f"[Overseer] FamilyCoordinator failed: {e}")
            # On error, use default specialist for category
            try:
                category = SignalCategory(category_str.lower().replace(" ", "_").replace("-", "_"))
                specialists = get_specialists_for_signal(category)
            except (ValueError, KeyError):
                specialists = []
            return {
                "primary_specialist": specialists[0] if specialists else "mass_assignment_auditor",
                "family": family.value,
                "context_for_specialist": "Error getting coordinator context",
                "error": str(e),
            }

    async def _run_specialist(self, signal: dict, coordinator_result: dict) -> Optional[dict]:
        """Stage 3: Specialist validates signal technically.

        Specialist focuses ONLY on technical validation:
        - Is this actually a vulnerability?
        - Can it be exploited?
        - What's the technical evidence?

        For CRITICAL severity signals, runs cross-validation with 2 specialists.
        If they disagree, dispatches Arbiter to resolve.

        Args:
            signal: Signal dict from hunter
            coordinator_result: Output from FamilyCoordinator with specialist assignment

        Returns:
            Dict with verdict (vulnerable/not_vulnerable/needs_more_info), or None on error
        """
        signal_severity = signal.get("severity", "MEDIUM").upper()
        signal_id = signal.get('signal_id', 'unknown')

        # For critical signals, use cross-validation
        if signal_severity == "CRITICAL":
            return await self._run_specialist_cross_validation(signal, coordinator_result)

        # Standard single-specialist flow for non-critical
        return await self._run_single_specialist(signal, coordinator_result)

    async def _run_single_specialist(self, signal: dict, coordinator_result: dict, *, _skip_calibration: bool = False) -> Optional[dict]:
        """Run a single specialist for standard validation.

        Args:
            _skip_calibration: If True, skip calibration cross-validation promotion.
                Used when called FROM cross-validation to prevent infinite recursion.
        """
        specialist_id = coordinator_result.get("primary_specialist") or "mass_assignment_auditor"
        context = coordinator_result.get("context_for_specialist", "")
        signal_id = signal.get('signal_id', 'unknown')

        # Get specialist info
        registry = SpecialistRegistry()
        specialist_info = registry.get_by_id(specialist_id)

        if not specialist_info:
            # Fallback to first specialist in family
            family_str = coordinator_result.get("family", "api_design")
            try:
                family = SpecialistFamily(family_str)
                family_specialists = registry.get_by_family(family)
                if family_specialists:
                    specialist_info = family_specialists[0]
            except (ValueError, KeyError) as e:
                print(f"[Overseer] Specialist family lookup failed for '{specialist_id}': {e}")

        if not specialist_info:
            print(f"[Overseer] No specialist found for {specialist_id}")
            return {"verdict": "needs_more_info", "error": "No specialist found"}

        # Check if this specialist needs cross-validation based on calibration history
        # Skip this check when called from within cross-validation to prevent infinite recursion
        specialist_type = specialist_info.id
        if not _skip_calibration and self.calibrator.should_require_cross_validation(specialist_type):
            print(f"[Overseer] Calibration: {specialist_type} requires cross-validation due to historical performance")
            # Promote to cross-validation even if not critical
            return await self._run_specialist_cross_validation(signal, coordinator_result)

        # Format signal for specialist — use typed signal if available
        typed_signal = signal.get("_typed_signal")
        if typed_signal:
            signal_context = typed_signal.to_specialist_context()
            signal_context += f"\n\n## Additional Context from Coordinator\n{context}"
        else:
            signal_context = f"""## Signal
- ID: {signal_id}
- Category: {signal.get('category', signal.get('vulnerability_type', 'unknown'))}
- File: {signal.get('file_path', signal.get('location', 'unknown'))}
- Line: {signal.get('line_start', signal.get('line_number', '?'))}
- Code: {signal.get('code_snippet', 'N/A')}
- Why suspicious: {signal.get('why_suspicious', signal.get('description', 'N/A'))}

## Additional Context from Coordinator
{context}"""

        prompt = get_specialist_prompt(
            specialist_name=specialist_info.name,
            specialist_id=specialist_info.id,
            proficiency=specialist_info.proficiency,
            signal_id=signal_id,
            signal_context=signal_context,
        )

        start_time = time.time()
        try:
            foundation_ctx = self.foundation_ctx
            result = await self.dispatcher.dispatch_single(
                agent_type="Specialist",
                objective=prompt,
                scope=self.repo_path_str,
                deliverable=f"/memories/verification/{specialist_id}_{signal_id}.json",
                time_budget=180,
                foundation_context=foundation_ctx,
            )

            analysis_time = time.time() - start_time

            if result and result.output:
                verdict = self._extract_json_from_output(result.output)
                if verdict:
                    verdict["specialist_id"] = specialist_id
                    verdict["specialist_name"] = specialist_info.name

                    # Verify native skill was loaded
                    skill_invoked = verdict.get("skill_invoked")
                    if skill_invoked and skill_invoked != "null":
                        print(f"[Overseer] {specialist_id} loaded skill: {skill_invoked}")
                    else:
                        print(f"[Overseer] WARNING: {specialist_id} did NOT load native skill")

                    # Record verdict in calibration system
                    confidence = verdict.get("confidence", 50)
                    self.calibration_store.record_verdict(VerdictRecord(
                        signal_id=signal_id,
                        specialist_type=specialist_type,
                        verdict=verdict.get("verdict", "unknown"),
                        confidence=confidence,
                        analysis_time_seconds=analysis_time,
                    ))

                    # Apply trust weighting from calibration
                    weighted_verdict, weighted_confidence = self.calibrator.weight_verdict(
                        specialist_type,
                        verdict.get("verdict", "unknown"),
                        confidence,
                    )
                    verdict["original_confidence"] = confidence
                    verdict["weighted_confidence"] = weighted_confidence
                    verdict["trust_weight"] = self.calibrator.calculate_trust_weight(specialist_type)

                    # Check for calibration alerts
                    alerts = self.calibrator.check_alerts(specialist_type)
                    if alerts:
                        verdict["calibration_alerts"] = [a.message for a in alerts]
                        for alert in alerts:
                            print(f"[Overseer] Calibration Alert: {alert.message}")

                return verdict
            return None

        except Exception as e:
            print(f"[Overseer] Specialist {specialist_id} failed: {e}")
            return {"verdict": "error", "specialist_id": specialist_id, "error": str(e)}

    async def _run_specialist_cross_validation(self, signal: dict, coordinator_result: dict) -> Optional[dict]:
        """Run cross-validation with 2 specialists for critical signals.

        If specialists disagree, dispatches Arbiter to resolve.
        """
        signal_id = signal.get('signal_id', 'unknown')
        print(f"[Overseer] Signal {signal_id}: Running cross-validation (CRITICAL severity)")

        # Get primary and secondary specialists
        primary_id = coordinator_result.get("primary_specialist") or "mass_assignment_auditor"
        secondary_id = coordinator_result.get("secondary_specialist")

        # If no secondary, get another from the same family
        if not secondary_id:
            registry = SpecialistRegistry()
            family_str = coordinator_result.get("family", "api_design")
            try:
                family = SpecialistFamily(family_str)
                family_specialists = registry.get_by_family(family)
                for s in family_specialists:
                    if s.id != primary_id:
                        secondary_id = s.id
                        break
            except (ValueError, KeyError):
                pass

        if not secondary_id:
            # Can't cross-validate, fall back to single specialist
            # _skip_calibration=True prevents infinite recursion back into cross-validation
            return await self._run_single_specialist(signal, coordinator_result, _skip_calibration=True)

        # Run both specialists in parallel
        # _skip_calibration=True prevents infinite recursion: cross-validation -> single -> calibration check -> cross-validation
        primary_task = self._run_single_specialist(signal, {**coordinator_result, "primary_specialist": primary_id}, _skip_calibration=True)
        secondary_task = self._run_single_specialist(signal, {**coordinator_result, "primary_specialist": secondary_id}, _skip_calibration=True)

        results = await asyncio.gather(primary_task, secondary_task, return_exceptions=True)

        primary_result = results[0] if not isinstance(results[0], Exception) else None
        secondary_result = results[1] if not isinstance(results[1], Exception) else None

        # Check for agreement
        if primary_result and secondary_result:
            primary_verdict = primary_result.get("verdict", "").lower()
            secondary_verdict = secondary_result.get("verdict", "").lower()

            # Normalize verdicts
            primary_is_vuln = primary_verdict in ("vulnerable", "exploitable", "valid")
            secondary_is_vuln = secondary_verdict in ("vulnerable", "exploitable", "valid")

            if primary_is_vuln == secondary_is_vuln:
                # Specialists agree
                print(f"[Overseer] Signal {signal_id}: Specialists agree - {primary_verdict}")
                primary_result["cross_validated"] = True
                primary_result["secondary_verdict"] = secondary_verdict
                return primary_result
            else:
                # Disagreement - dispatch Arbiter
                print(f"[Overseer] Signal {signal_id}: Specialist disagreement - dispatching Arbiter")
                return await self._run_arbiter(signal, primary_result, secondary_result)

        # If one failed, use the other
        return primary_result or secondary_result

    async def _run_arbiter(self, signal: dict, verdict_a: dict, verdict_b: dict) -> Optional[dict]:
        """Dispatch Arbiter to resolve specialist disagreement."""
        from agents.deep_audit.subagents import get_arbiter_prompt

        signal_id = signal.get('signal_id', 'unknown')
        signal_context = json.dumps(signal, indent=2)

        specialist_verdicts = f"""### Specialist A: {verdict_a.get('specialist_id', 'unknown')}
Verdict: {verdict_a.get('verdict', 'unknown')}
Confidence: {verdict_a.get('confidence', 'N/A')}
Reasoning: {verdict_a.get('reasoning', 'None')}

### Specialist B: {verdict_b.get('specialist_id', 'unknown')}
Verdict: {verdict_b.get('verdict', 'unknown')}
Confidence: {verdict_b.get('confidence', 'N/A')}
Reasoning: {verdict_b.get('reasoning', 'None')}"""

        prompt = get_arbiter_prompt(
            signal_id=signal_id,
            disagreement_context=signal_context,
            specialist_verdicts=specialist_verdicts,
        )

        try:
            foundation_ctx = self.foundation_ctx
            result = await self.dispatcher.dispatch_single(
                agent_type="Arbiter",
                objective=prompt,
                scope=self.repo_path_str,
                deliverable=f"/memories/arbiter/{signal_id}_arbiter.json",
                time_budget=240,  # 4 minutes for Arbiter
                foundation_context=foundation_ctx,
            )

            if result and result.output:
                arbiter_result = self._extract_json_from_output(result.output)
                if arbiter_result:
                    arbiter_result["arbitrated"] = True
                    arbiter_result["specialist_a"] = verdict_a.get("specialist_id")
                    arbiter_result["specialist_b"] = verdict_b.get("specialist_id")
                return arbiter_result
            return None

        except Exception as e:
            print(f"[Overseer] Arbiter failed: {e}")
            # Fall back to primary specialist result
            return verdict_a

    async def _run_triager(self, signal: dict, specialist_result: Optional[dict], da_result: Optional[dict] = None) -> Optional[dict]:
        """Stage 4: Triager classifies signal based on threat model.

        Triager makes final classification:
        - SECURITY_VULNERABILITY: Real, exploitable vuln matching threat model
        - HARDENING: Real issue but not in threat model scope (nice-to-fix)
        - BY_DESIGN: Intentional behavior, not a vulnerability
        - DISMISSED: Not a real vulnerability

        Triager considers:
        - Specialist's technical verdict (if available)
        - Devil's Advocate challenge results (if specialist was challenged)
        - Threat model (what attackers are in scope)
        - Business context (what's actually at risk)

        Args:
            signal: Signal dict from hunter
            specialist_result: Output from Specialist (may be None or have error)
            da_result: Output from Devil's Advocate challenge (may be None)

        Returns:
            Finding dict if classified as vulnerability, None if dismissed
        """
        # Get threat model from foundation context
        threat_model = "Unknown - no threat model available"
        try:
            tm_content = self.filesystem.read_file("/memories/foundation/threat_model.json")
            if tm_content:
                tm_data = self._extract_json_from_output(tm_content)
                if tm_data:
                    threat_model = json.dumps(tm_data, indent=2)
        except Exception as e:
            print(f"[Overseer] Could not load threat model for triager: {e}")

        # Format specialist verdict
        if specialist_result:
            if specialist_result.get("error"):
                specialist_summary = f"Specialist encountered error: {specialist_result.get('error')}"
            else:
                verdict = specialist_result.get("verdict", "unknown")
                confidence = specialist_result.get("confidence", "N/A")
                reasoning = specialist_result.get("reasoning", "No reasoning provided")
                evidence = specialist_result.get("evidence", [])
                poc = specialist_result.get("poc_sketch", "")
                fix = specialist_result.get("suggested_fix", "")
                skill = specialist_result.get("skill_used", "")
                specialist_summary = f"""Verdict: {verdict}
Confidence: {confidence}
Reasoning: {reasoning}
Evidence: {json.dumps(evidence, indent=2) if evidence else 'None provided'}
PoC Sketch: {poc if poc else 'None'}
Suggested Fix: {fix if fix else 'None'}
Skill Used: {skill if skill else 'None'}"""
                # Include DA challenge if specialist was challenged
                if specialist_result.get("challenged"):
                    challenge_findings = specialist_result.get("challenge_findings", [])
                    specialist_summary += f"\n\nDevil's Advocate Challenge: RECONSIDER"
                    specialist_summary += f"\nChallenge Findings: {json.dumps(challenge_findings, indent=2) if challenge_findings else 'None'}"
                    if specialist_result.get("devils_advocate_override"):
                        specialist_summary += "\nDA Override: Specialist verdict overridden to needs_more_info"
        else:
            specialist_summary = "No specialist verdict available (specialist failed or timed out)"

        signal_context = json.dumps(signal, indent=2)

        # Format Devil's Advocate challenge if available
        da_section = ""
        if da_result:
            da_section = f"""
## Devil's Advocate Challenge
- Challenge verdict: {da_result.get('recommendation', 'N/A')}
- Challenge reasoning: {da_result.get('reasoning', da_result.get('challenge_reasoning', 'N/A'))}
- New evidence: {json.dumps(da_result.get('new_evidence', da_result.get('challenge_findings', [])), indent=2)}
"""

        objective = f"""Make final classification for this signal.

## Signal
```json
{signal_context}
```

## Specialist Analysis
{specialist_summary}
{da_section}
## Threat Model
```json
{threat_model}
```

Classify as:
- SECURITY_VULNERABILITY: Real vuln, attacker in scope can exploit
- HARDENING: Real issue but attacker not in scope (nice-to-fix)
- BY_DESIGN: Intentional behavior
- DISMISSED: Not a real vulnerability

CRITICAL: Your ENTIRE response must be a single raw JSON object.
No markdown. No prose. No explanation. No code fences. Start with {{ and end with }}.
Any non-JSON text causes a pipeline failure and this signal is LOST.

Required schema (output this directly, not in a code block):
{{"signal_id": "<from input>", "classification": "SECURITY_VULNERABILITY|HARDENING|BY_DESIGN|DISMISSED", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 85, "title": "concise title", "description": "2-4 sentences", "reasoning": "why", "impact": "damage", "attack_path": "exploitation steps", "recommendation": "fix"}}"""

        try:
            foundation_ctx = self.foundation_ctx
            result = await self.dispatcher.dispatch_single(
                agent_type="Triager",
                objective=objective,
                scope=self.repo_path_str,
                deliverable=f"/memories/triage/{signal.get('signal_id', 'unknown')}_triage.json",
                time_budget=120,  # 2 minutes
                foundation_context=foundation_ctx,
            )

            if result and result.output:
                triage_result = self._extract_json_from_output(result.output)
                if triage_result:
                    self.signal_tracker.record_parse("json_ok")
                    classification = triage_result.get("classification", "DISMISSED")

                    if classification == "SECURITY_VULNERABILITY":
                        # Build finding from triage result
                        # Normalize severity to lowercase for Severity enum
                        raw_severity = triage_result.get("severity", "medium")
                        normalized_severity = raw_severity.lower() if isinstance(raw_severity, str) else "medium"

                        # Synthesize description from available fields if triager didn't provide one
                        description = triage_result.get("description", "")
                        if not description.strip():
                            parts = []
                            if triage_result.get("reasoning"):
                                parts.append(triage_result["reasoning"])
                            if triage_result.get("impact"):
                                parts.append(f"Impact: {triage_result['impact']}")
                            if triage_result.get("attack_path"):
                                parts.append(f"Attack path: {triage_result['attack_path']}")
                            description = " ".join(parts) if parts else signal.get("why_suspicious", "")

                        return {
                            "signal_id": signal.get("signal_id"),
                            "title": triage_result.get("title", signal.get("title", "Untitled")),
                            "description": description,
                            "severity": normalized_severity,
                            "vulnerability_type": signal.get("category", signal.get("vulnerability_type", "unknown")),
                            "location": signal.get("file_path", signal.get("location", "")),
                            "file_path": signal.get("file_path", ""),
                            "line_start": signal.get("line_start", signal.get("line_number")),
                            "code_snippet": signal.get("code_snippet", ""),
                            "remediation": triage_result.get("recommendation", ""),
                            "confidence": specialist_result.get("confidence", 0.7) if specialist_result else 0.5,
                            "verified_by": specialist_result.get("specialist_id") if specialist_result else None,
                            "classification": classification,
                        }
                    elif classification == "HARDENING":
                        # Still return as finding but lower priority
                        hardening_desc = triage_result.get("description", "")
                        if not hardening_desc.strip():
                            parts = []
                            if triage_result.get("reasoning"):
                                parts.append(triage_result["reasoning"])
                            if triage_result.get("recommendation"):
                                parts.append(f"Recommendation: {triage_result['recommendation']}")
                            hardening_desc = " ".join(parts) if parts else signal.get("why_suspicious", "")
                        return {
                            "signal_id": signal.get("signal_id"),
                            "title": f"[Hardening] {triage_result.get('title', signal.get('title', 'Untitled'))}",
                            "description": hardening_desc,
                            "severity": "low",  # Hardening items are always low (lowercase for Severity enum)
                            "vulnerability_type": signal.get("category", "hardening"),
                            "location": signal.get("file_path", ""),
                            "file_path": signal.get("file_path", ""),
                            "line_start": signal.get("line_start"),
                            "code_snippet": signal.get("code_snippet", ""),
                            "remediation": triage_result.get("recommendation", ""),
                            "confidence": 0.5,
                            "classification": classification,
                        }
                    # BY_DESIGN and DISMISSED return None
                    return None
            # JSON parse failure — try to extract classification from markdown prose
            if result and result.output:
                fallback = self._parse_triager_markdown_fallback(result.output, signal, specialist_result)
                if fallback is not None:
                    self.signal_tracker.record_parse("markdown_fallback")
                    print(f"[Overseer] Triager JSON failed but markdown fallback succeeded for {signal.get('signal_id')}: {fallback.get('classification')}")
                    return fallback
            self.signal_tracker.record_parse("parse_failure")
            print(f"[Overseer] Triager returned unparseable output for {signal.get('signal_id')} - preserving as UNVERIFIED")
            return self._build_unverified_finding(signal, specialist_result, "triager_parse_failure")

        except Exception as e:
            self.signal_tracker.record_parse("parse_failure")
            print(f"[Overseer] Triager failed: {e} - preserving signal as UNVERIFIED")
            return self._build_unverified_finding(signal, specialist_result, f"triager_error: {e}")

    def _parse_triager_markdown_fallback(
        self, raw_output: str, signal: dict, specialist_result: Optional[dict]
    ) -> Optional[dict]:
        """Extract classification from triager markdown when JSON parsing fails.

        Models sometimes respond with prose instead of JSON. This extracts the
        classification from patterns like "## Final Classification: SECURITY_VULNERABILITY"
        or "classified it as a **SECURITY_VULNERABILITY**" and builds a finding dict
        from the prose + original signal data.
        """
        text = raw_output.upper()

        # Determine classification from prose
        classification = None
        for candidate in ["SECURITY_VULNERABILITY", "HARDENING", "BY_DESIGN", "DISMISSED", "BUG", "MISCONFIGURATION"]:
            if candidate in text:
                classification = candidate
                break

        if not classification:
            return None

        # DISMISSED / BY_DESIGN → drop the signal (same as JSON path)
        if classification in ("DISMISSED", "BY_DESIGN"):
            return None

        # Extract severity from prose (e.g. "HIGH severity" or "severity: HIGH")
        severity = "medium"
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in text:
                severity = sev.lower()
                break

        # Use the full prose as the description — it's richer than most JSON descriptions
        # Trim to first ~2000 chars to avoid storing a wall of text
        description = raw_output.strip()[:2000]

        if classification == "SECURITY_VULNERABILITY":
            return {
                "signal_id": signal.get("signal_id"),
                "title": signal.get("title", "Untitled"),
                "description": description,
                "severity": severity,
                "vulnerability_type": signal.get("category", signal.get("vulnerability_type", "unknown")),
                "location": signal.get("file_path", signal.get("location", "")),
                "file_path": signal.get("file_path", ""),
                "line_start": signal.get("line_start", signal.get("line_number")),
                "code_snippet": signal.get("code_snippet", ""),
                "remediation": signal.get("remediation", ""),
                "confidence": specialist_result.get("confidence", 0.7) if specialist_result else 0.5,
                "verified_by": specialist_result.get("specialist_id") if specialist_result else None,
                "classification": classification,
            }
        elif classification == "HARDENING":
            return {
                "signal_id": signal.get("signal_id"),
                "title": f"[Hardening] {signal.get('title', 'Untitled')}",
                "description": description,
                "severity": "low",
                "vulnerability_type": signal.get("category", "hardening"),
                "location": signal.get("file_path", ""),
                "file_path": signal.get("file_path", ""),
                "line_start": signal.get("line_start"),
                "code_snippet": signal.get("code_snippet", ""),
                "remediation": signal.get("remediation", ""),
                "confidence": 0.5,
                "classification": classification,
            }
        elif classification in ("BUG", "MISCONFIGURATION"):
            return {
                "signal_id": signal.get("signal_id"),
                "title": f"[{classification.title()}] {signal.get('title', 'Untitled')}",
                "description": description,
                "severity": severity,
                "vulnerability_type": signal.get("category", classification.lower()),
                "location": signal.get("file_path", ""),
                "file_path": signal.get("file_path", ""),
                "line_start": signal.get("line_start"),
                "code_snippet": signal.get("code_snippet", ""),
                "remediation": signal.get("remediation", ""),
                "confidence": 0.5,
                "classification": classification,
            }

        return None

    async def _load_dismissed_fingerprints(self) -> None:
        """Load dismissed signal fingerprints from SinkSignalService into memory.

        Called once before routing phase starts. Cached in self._dismissed_fingerprints
        so per-signal checks are O(1) set lookups instead of disk reads.
        """
        try:
            dismissed = await sink_signal_service.list_signals(
                project_id=self.campaign_state.project_id,
                status=SinkSignalStatus.DISMISSED,
            )
            self._dismissed_fingerprints = {s.fingerprint for s in dismissed}
            if self._dismissed_fingerprints:
                print(f"[Overseer] Loaded {len(self._dismissed_fingerprints)} previously dismissed signals")
        except Exception as e:
            print(f"[Overseer] Failed to load dismissed fingerprints: {e}")
            self._dismissed_fingerprints = set()

    async def _persist_dismissal(self, signal: dict) -> None:
        """Write DISMISSED status to SinkSignalService so it persists across scans.

        This prevents the same signal from being re-processed in future scans.
        Uses the same fingerprint scheme as SinkHunter so the match is exact.
        """
        try:
            category = signal.get("category", signal.get("vulnerability_type", "unknown"))
            file_path = signal.get("file_path", signal.get("location", ""))
            line_number = signal.get("line_start", signal.get("line_number"))
            label = signal.get("title", signal.get("why_suspicious", category))

            fingerprint = compute_signal_fingerprint(
                kind=category,
                file_path=file_path,
                line_number=line_number,
                label=label,
            )

            project_id = self.campaign_state.project_id
            # Upsert: if signal exists, status won't downgrade from DISMISSED.
            # If signal doesn't exist yet, create it as DISMISSED.
            dismissed_signal = SinkSignal(
                fingerprint=fingerprint,
                kind=SinkSignalKind.SINK,
                label=label,
                file_path=file_path,
                line_number=line_number,
                status=SinkSignalStatus.DISMISSED,
                source="deep_audit_pipeline",
                metadata={"dismissed_by": "pipeline", "signal_id": signal.get("signal_id", "")},
            )
            await sink_signal_service.upsert_signals(
                project_id=project_id,
                signals=[dismissed_signal],
            )
            # Update in-memory cache so subsequent signals in this scan are also caught
            if self._dismissed_fingerprints is not None:
                self._dismissed_fingerprints.add(fingerprint)
        except Exception as e:
            # Non-fatal — don't break the pipeline for bookkeeping failures
            print(f"[Overseer] Failed to persist dismissal for {signal.get('signal_id', '?')}: {e}")

    def _build_unverified_finding(
        self, signal: dict, specialist_result: Optional[dict], reason: str
    ) -> dict:
        """Build an unverified finding from a signal when routing fails.

        This preserves the signal as a finding for manual review rather than
        silently dropping it when Triager/Specialist fails to classify.

        Args:
            signal: Original signal from hunter
            specialist_result: Result from specialist (may be None)
            reason: Why the finding is unverified

        Returns:
            Finding dict marked as UNVERIFIED
        """
        category = signal.get("category", signal.get("vulnerability_type", "unknown"))
        return {
            "signal_id": signal.get("signal_id"),
            "title": f"[Unverified] {signal.get('title', category.replace('_', ' ').title())}",
            "description": signal.get("why_suspicious", signal.get("description", "")),
            "severity": signal.get("severity", "medium").lower(),  # Use lowercase for Severity enum
            "vulnerability_type": category,
            "location": signal.get("file_path", signal.get("location", "")),
            "file_path": signal.get("file_path", ""),
            "line_start": signal.get("line_start", signal.get("line_number")),
            "code_snippet": signal.get("code_snippet", ""),
            "remediation": "Manual review required - automated triage failed.",
            "confidence": 0.3,  # Low confidence since unverified
            "verified_by": specialist_result.get("specialist_id") if specialist_result else None,
            "classification": "UNVERIFIED",
            "unverified_reason": reason,
        }

    async def _route_new_signals_incrementally(self, previous_count: int, wave_num: int):
        """Route newly discovered signals through specialists immediately.

        This is called after each wave to provide faster feedback on vulnerability validity,
        rather than waiting until the end of all hunting waves.

        Args:
            previous_count: Number of signals before this wave (to identify new ones)
            wave_num: Current wave number for logging
        """
        # Get only the NEW signals from this wave
        all_signals = self.campaign_state.confirmed_findings
        new_signals = all_signals[previous_count:]

        if not new_signals:
            return

        # Limit signals per wave to avoid spending too much time on routing
        MAX_SIGNALS_PER_WAVE_BY_TIER = {
            "quick": 3, "medium": 5, "advanced": 8,
            "pro": 10, "ultra": 15, "evil": 20,
        }
        MAX_SIGNALS_PER_WAVE = MAX_SIGNALS_PER_WAVE_BY_TIER.get(
            self.campaign_state.scan_tier, 5
        )

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_signals = sorted(
            new_signals,
            key=lambda s: severity_order.get(s.get("severity", "medium").lower(), 2)
        )
        signals_to_route = sorted_signals[:MAX_SIGNALS_PER_WAVE]

        await self.emit_log(f"Wave {wave_num}: Routing {len(signals_to_route)} high-priority signals to specialists...")
        print(f"[Overseer] Incremental routing: {len(signals_to_route)} signals from wave {wave_num}")

        verified_count = 0
        dismissed_count = 0

        for i, signal in enumerate(signals_to_route):
            # Check time budget - need at least 60s for each routing
            if self.campaign_state.time_remaining() < 60:
                print(f"[Overseer] Stopping incremental routing - low time budget")
                break

            signal_id = signal.get("signal_id", f"sig-{i}")
            severity = signal.get("severity", "medium")

            try:
                # Route through full pipeline: Decider → FamilyCoordinator → Specialist → Triager
                finding = await self._route_signal_through_pipeline(signal)

                if finding:
                    verified_count += 1
                    # Mark signal as routed and store the verified finding
                    signal["_routed"] = True
                    signal["_verified_finding"] = finding
                    await self.emit_log(f"  ✓ {signal_id} ({severity}): Verified as {finding.get('classification', 'vulnerability')}")

                    # Persist finding immediately for UI visibility (survives refresh)
                    db_finding = await self._persist_finding_immediately(finding)
                    if db_finding:
                        await self.emit_finding(db_finding)
                else:
                    dismissed_count += 1
                    signal["_routed"] = True
                    signal["_dismissed"] = True
                    await self._persist_dismissal(signal)
                    await self.emit_log(f"  ✗ {signal_id} ({severity}): Dismissed by specialist")

            except Exception as e:
                print(f"[Overseer] Error routing signal {signal_id}: {e}")
                # Don't mark as routed so it can be retried in Phase 4

        print(f"[Overseer] Incremental routing complete: {verified_count} verified, {dismissed_count} dismissed")
        await self.emit_log(f"Wave {wave_num} routing: {verified_count} verified, {dismissed_count} dismissed")

    async def _route_all_signals(self):
        """Route all collected signals through the verification pipeline.

        Note: With incremental routing enabled, many signals may already be routed.
        This method now only routes signals that weren't processed incrementally.

        Each signal goes through:
        1. Decider - Should we investigate?
        2. FamilyCoordinator - Which specialist? What context?
        3. Specialist - Is this technically a vulnerability?
        4. Triager - Final classification based on threat model
        """
        # Keep original findings until routing succeeds - don't lose data on failure
        original_signals = self.campaign_state.confirmed_findings.copy()

        # Filter out signals already routed incrementally during waves
        unrouted_signals = [s for s in original_signals if not s.get("_routed")]
        already_routed = len(original_signals) - len(unrouted_signals)

        # Also collect verified findings from incremental routing
        verified_from_incremental = [
            s.get("_verified_finding")
            for s in original_signals
            if s.get("_routed") and isinstance(s.get("_verified_finding"), dict) and s.get("_verified_finding")
        ]

        if already_routed > 0:
            await self.emit_log(f"Phase 4: {already_routed} signals already routed incrementally, {len(unrouted_signals)} remaining...")
            print(f"[Overseer] Skipping {already_routed} already-routed signals, processing {len(unrouted_signals)} remaining")

        signals = unrouted_signals

        if not signals:
            await self.emit_log("Phase 4: All signals already routed during waves. Skipping batch routing.")
            print(f"[Overseer] All signals already routed incrementally, skipping Phase 4 batch routing")
            # Update confirmed findings with verified ones from incremental routing
            if verified_from_incremental:
                self.campaign_state.confirmed_findings = verified_from_incremental
            return

        await self.emit_log(f"Phase 4: Routing {len(signals)} signals through verification pipeline...")
        print(f"[Overseer] Routing {len(signals)} signals through Decider → FamilyCoordinator → Specialist → Triager")

        # Emit phase start event for UI
        await self.emit(
            WSMessageType.PROGRESS,
            {
                "type": "phase_start",
                "phase": "routing",
                "phase_number": 4,
                "phase_name": "Signal Routing",
                "signals_total": len(signals),
                "time_remaining": self.campaign_state.time_remaining(),
            }
        )

        # Create flow node for routing phase
        routing_node = flow_service.add_node(
            self.id,
            node_type="analysis",
            label="Signal Routing",
            parent_id=None,
            data={"phase": "routing", "signals_count": len(signals)},
        )
        if routing_node:
            flow_service.update_node_status(self.id, routing_node.id, "running")
        await self.emit_flow_update()

        verified_findings = []
        dismissed_signal_ids = set()  # Track actually dismissed signals, not just count
        error_count = 0

        # Sort signals by severity: CRITICAL first, then HIGH, MEDIUM, LOW
        SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        signals.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "medium").lower(), 2))

        routing_start = time.time()
        phase_budget = self.campaign_state.time_remaining() * 0.8  # Reserve 20% for finalization

        for i, signal in enumerate(signals):
            # Check time budget — reserve time for finalization
            elapsed = time.time() - routing_start
            if elapsed > phase_budget or self.campaign_state.time_remaining() < 30:
                remaining = len(signals) - i
                await self.emit_log(f"Routing budget exhausted after {elapsed:.0f}s, {remaining} signals skipped (processed {i}/{len(signals)})")
                break

            signal_id = signal.get("signal_id", f"sig-{i}")
            await self.emit_log(f"Routing signal {i+1}/{len(signals)}: {signal_id}")

            # Emit progress event for UI
            await self.emit(
                WSMessageType.PROGRESS,
                {
                    "type": "signal_routing",
                    "signal_id": signal_id,
                    "signal_index": i + 1,
                    "signals_total": len(signals),
                    "signal_category": signal.get("category", "unknown"),
                    "signal_severity": signal.get("severity", "MEDIUM"),
                    "status": "routing",
                    "time_remaining": self.campaign_state.time_remaining(),
                }
            )

            try:
                finding = await self._route_signal_through_pipeline(signal)
                if finding:
                    verified_findings.append(finding)
                    await self.emit_log(f"  → Verified: {finding.get('title', 'Untitled')}")
                    # Persist finding immediately for UI visibility (survives refresh)
                    db_finding = await self._persist_finding_immediately(finding)
                    if db_finding:
                        await self.emit_finding(db_finding)
                    # Emit verified finding event
                    await self.emit(
                        WSMessageType.PROGRESS,
                        {
                            "type": "signal_verified",
                            "signal_id": signal_id,
                            "title": finding.get("title", "Untitled"),
                            "severity": finding.get("severity", "MEDIUM"),
                            "verified_count": len(verified_findings),
                        }
                    )
                else:
                    dismissed_signal_ids.add(signal_id)  # Track the actual signal ID
                    await self._persist_dismissal(signal)
                    await self.emit_log(f"  → Dismissed")
                    # Emit dismissed event
                    await self.emit(
                        WSMessageType.PROGRESS,
                        {
                            "type": "signal_dismissed",
                            "signal_id": signal_id,
                            "dismissed_count": len(dismissed_signal_ids),
                        }
                    )
            except Exception as e:
                error_count += 1
                print(f"[Overseer] Error routing signal {signal_id}: {e}")
                await self.emit_log(f"  → Error: {e}")

        # Update confirmed findings with verified ones
        # Combine: verified from batch routing + verified from incremental routing
        # Preserve errored signals as unverified to avoid data loss
        all_verified = verified_findings + verified_from_incremental
        verified_ids = {f.get("signal_id") for f in all_verified}

        if all_verified:
            # Include verified findings plus any errored signals (marked as unverified)
            # Errored signals = signals NOT verified AND NOT dismissed AND NOT already routed
            errored_signals = [
                s for s in signals  # Only check batch-routed signals
                if s.get("signal_id") not in verified_ids
                and s.get("signal_id") not in dismissed_signal_ids
            ]
            for sig in errored_signals:
                sig["unverified"] = True
                sig["routing_error"] = True
            self.campaign_state.confirmed_findings = all_verified + errored_signals
        elif error_count == len(signals) and len(signals) > 0:
            # All batch signals errored - keep originals marked as unverified
            for sig in signals:
                sig["unverified"] = True
                sig["routing_error"] = True
            self.campaign_state.confirmed_findings = verified_from_incremental + signals
            await self.emit_log("WARNING: All batch routing failed, keeping signals as unverified findings")
        elif error_count > 0:
            # Some dismissed, some errored, none verified in batch - preserve errored ones
            errored_signals = [
                s for s in signals
                if s.get("signal_id") not in verified_ids
                and s.get("signal_id") not in dismissed_signal_ids
            ]
            for sig in errored_signals:
                sig["unverified"] = True
                sig["routing_error"] = True
            await self.emit_log(f"WARNING: {len(errored_signals)} signals failed routing - preserving as unverified")
            self.campaign_state.confirmed_findings = verified_from_incremental + errored_signals
        else:
            # All batch signals intentionally dismissed - keep only incremental findings
            self.campaign_state.confirmed_findings = verified_from_incremental

        if routing_node:
            flow_service.update_node_status(self.id, routing_node.id, "completed")
        await self.emit_flow_update()

        dismissed_count = len(dismissed_signal_ids)
        await self.emit_log(f"Routing complete: {len(verified_findings)} verified, {dismissed_count} dismissed, {error_count} errors")
        print(f"[Overseer] Routing complete: {len(verified_findings)} verified, {dismissed_count} dismissed, {error_count} errors")

        # Emit phase complete event
        await self.emit(
            WSMessageType.PROGRESS,
            {
                "type": "phase_complete",
                "phase": "routing",
                "phase_number": 4,
                "phase_name": "Signal Routing",
                "verified_count": len(verified_findings),
                "dismissed_count": dismissed_count,
                "error_count": error_count,
                "time_remaining": self.campaign_state.time_remaining(),
            }
        )

    @staticmethod
    def _map_classification(raw: str) -> FindingClassification:
        """Map triager/pipeline classification strings to FindingClassification enum."""
        mapping = {
            "SECURITY_VULNERABILITY": FindingClassification.SECURITY_ISSUE,
            "SECURITY_ISSUE": FindingClassification.SECURITY_ISSUE,
            "security_issue": FindingClassification.SECURITY_ISSUE,
            "HARDENING": FindingClassification.HARDENING,
            "hardening": FindingClassification.HARDENING,
            "BUG": FindingClassification.BUG,
            "bug": FindingClassification.BUG,
            "MISCONFIGURATION": FindingClassification.MISCONFIGURATION,
            "misconfiguration": FindingClassification.MISCONFIGURATION,
        }
        return mapping.get(raw, FindingClassification.SECURITY_ISSUE)

    async def _persist_finding_immediately(self, finding: dict) -> "Finding | None":
        """Persist a verified finding to DB immediately (don't wait for _process_findings).

        This ensures findings survive page refreshes and server restarts even
        if the audit is still running or gets interrupted.
        """
        # Block unverified findings — these should never reach the database.
        # They are created when the triager fails (parse error, exception) and
        # carry classification="UNVERIFIED" with a fallback description from the
        # hunter's raw signal. Persisting them would mislabel them as SECURITY_ISSUE
        # (the FindingCreate default) and show phantom findings in the UI.
        if finding.get("classification") == "UNVERIFIED":
            print(f"[Overseer] Skipping unverified finding: {finding.get('title', '?')} (reason: {finding.get('unverified_reason', '?')})")
            self.signal_tracker.record_persist("unverified_blocked")
            return None

        try:
            location = finding.get("file_path") or finding.get("location", "")
            file_path = location.split(":")[0] if ":" in location else location
            line_start = finding.get("line_start") or self._extract_line_number(location) or 1

            severity = finding.get("severity", "medium")
            if isinstance(severity, str):
                severity = severity.lower()

            metadata = finding.get("metadata", {})
            signal_id = finding.get("signal_id")
            if signal_id:
                metadata["signal_id"] = signal_id
                metadata["category"] = finding.get("category", finding.get("vulnerability_type", "unknown"))
                metadata["why_suspicious"] = finding.get("why_suspicious", "")

            classification = self._map_classification(finding.get("classification", ""))

            # Normalize confidence: specialists return 0-100, FindingCreate expects 0.0-1.0
            raw_confidence = finding.get("confidence", 0.7)
            if isinstance(raw_confidence, (int, float)) and raw_confidence > 1.0:
                raw_confidence = raw_confidence / 100.0
            confidence = max(0.0, min(1.0, float(raw_confidence)))

            finding_create = FindingCreate(
                title=finding.get("title", "Untitled Finding"),
                description=finding.get("description", ""),
                severity=severity,
                classification=classification,
                vulnerability_type=finding.get("vulnerability_type", finding.get("category", "unknown")),
                file_path=file_path,
                line_start=line_start,
                line_end=line_start,
                code_snippet=finding.get("code_snippet"),
                recommended_fix=finding.get("remediation") or finding.get("recommendation"),
                cwe_id=finding.get("cwe_id"),
                confidence=confidence,
                metadata=metadata,
            )
            db_finding = self.add_finding(finding_create)
            if db_finding:
                try:
                    await findings_service.save_finding(db_finding)
                    self.signal_tracker.record_persist("saved")
                except Exception as db_err:
                    print(f"[Overseer] Failed to save finding to database: {db_err}")
                    self.signal_tracker.record_persist("db_error")
                return db_finding
            self.signal_tracker.record_persist("deduped")
            return None
        except Exception as e:
            print(f"[Overseer] Error persisting finding immediately: {e}")
            self.signal_tracker.record_persist("db_error")
            import traceback
            traceback.print_exc()
            return None

    async def _process_findings(self):
        """Convert campaign state findings to Finding objects."""
        print(f"[Overseer] Processing {len(self.campaign_state.confirmed_findings)} confirmed findings...")

        processed_count = 0
        error_count = 0
        skipped_count = 0

        for i, finding_data in enumerate(self.campaign_state.confirmed_findings):
            try:
                # Skip findings that were already routed through the pipeline
                # (persisted during incremental/batch routing, or dismissed by specialist/decider)
                if finding_data.get("_routed") or finding_data.get("_dismissed") or finding_data.get("dismissed_by_specialist"):
                    skipped_count += 1
                    continue

                # Block unverified findings — same guard as _persist_finding_immediately.
                # These are created when the triager fails and would be mislabeled as
                # SECURITY_ISSUE (FindingCreate default) if persisted.
                if finding_data.get("classification") == "UNVERIFIED":
                    print(f"[Overseer] _process_findings: Skipping unverified finding: {finding_data.get('title', '?')}")
                    skipped_count += 1
                    continue

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

                # Normalize severity to lowercase enum value (Severity enum uses lowercase: "critical", "high", etc.)
                severity = finding_data.get("severity", "medium")
                if isinstance(severity, str):
                    severity = severity.lower()

                # Preserve signal_id for traceability back to original hunter output
                signal_id = finding_data.get("signal_id")
                metadata = finding_data.get("metadata", {})
                if signal_id:
                    metadata["signal_id"] = signal_id
                    metadata["category"] = finding_data.get("category", "unknown")
                    metadata["why_suspicious"] = finding_data.get("why_suspicious", "")

                classification = self._map_classification(finding_data.get("classification", ""))

                # Normalize confidence: specialists return 0-100, FindingCreate expects 0.0-1.0
                raw_confidence = finding_data.get("confidence", 0.5)
                if isinstance(raw_confidence, (int, float)) and raw_confidence > 1.0:
                    raw_confidence = raw_confidence / 100.0
                confidence = max(0.0, min(1.0, float(raw_confidence)))

                finding_create = FindingCreate(
                    title=finding_data.get("title", "Untitled Finding"),
                    description=finding_data.get("description", ""),
                    severity=severity,
                    classification=classification,
                    vulnerability_type=finding_data.get("vulnerability_type", "unknown"),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_start,  # Same as start for single-line findings
                    code_snippet=finding_data.get("code_snippet"),
                    recommended_fix=finding_data.get("remediation") or finding_data.get("recommendation"),
                    confidence=confidence,
                    metadata=metadata,
                )
                finding = self.add_finding(finding_create)
                if finding:
                    # Save to database for persistence (critical for UI to show findings after refresh)
                    try:
                        await findings_service.save_finding(finding)
                    except Exception as db_err:
                        print(f"[Overseer] Failed to save finding to database: {db_err}")
                        # Continue even if DB save fails - finding is still in memory
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
