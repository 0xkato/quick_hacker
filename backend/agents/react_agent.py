"""
ReAct Security Research Agent

A proper agentic loop that investigates codebases like a human security researcher:
1. Explores the codebase structure
2. Identifies attack surfaces
3. Forms hypotheses about vulnerabilities
4. Uses tools to investigate and validate
5. Reports confirmed findings with proof

This is NOT dumb file-by-file analysis. It's a continuous investigation loop.
"""

import asyncio
import json
import os
import uuid
from datetime import datetime
from typing import Any, Callable, Optional
from dataclasses import dataclass, field

import re

from models.schemas import (
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    FindingCreate,
    Severity,
    WSMessage,
    WSMessageType,
    ScannerHandoffState,
    FileReadRecord,
    TechStack,
    EntryPoint,
    Sink,
    HandoffMode,
    ProviderConfig,
)
from models.turn_plan import TurnPlan, Hypothesis, HypothesisActivity, FocusGap
from agents.tools import ToolExecutor, AGENT_TOOLS, ToolResult
from agents.dual_model_config import DEFAULT_SCANNER_MODELS, resolve_dual_model_config, get_handoff_mode
from agents.prompts.scanner_prompt import format_scanner_prompt
from agents.prompts.analyzer_prompt import format_analyzer_prompt
from prompts.classification_gate import get_classification_gate_prompt
from prompting_loader import load_prompt, render_prompt
from providers import Message, get_provider
from services.attack_surface_service import attack_surface_service, AttackSurfaceTriageItem
from services.flow_service import flow_service
from services.investigation_queue_service import investigation_queue_service
from services.observability_service import observability_service
from services.code_graph_service import code_graph_service
from services.project_service import project_service
from services.sink_signal_service import sink_signal_service
from services.span_service import span_service
from models.sink_signals import SinkSignal, SinkSignalKind, SinkSignalStatus
from models.investigation_trace import SpanType, SpanState


# Security: Maximum length for custom prompts
MAX_CUSTOM_PROMPT_LENGTH = 2000

# Security: Patterns that could be used for prompt injection
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|rules)",
    r"disregard\s+(all\s+)?(previous|above|prior)",
    r"forget\s+(everything|all)",
    r"you\s+are\s+now",
    r"new\s+instructions?:",
    r"system\s*:",
    r"assistant\s*:",
    r"human\s*:",
    r"<\s*system\s*>",
    r"<\s*/?\s*instruction",
]


def sanitize_custom_prompt(prompt: Optional[str]) -> Optional[str]:
    """
    Sanitize custom prompt to prevent prompt injection attacks.

    - Limits length to MAX_CUSTOM_PROMPT_LENGTH
    - Removes potential injection patterns
    - Wraps in clear delimiters so LLM treats it as user data
    """
    if not prompt:
        return None

    # Truncate to max length
    prompt = prompt[:MAX_CUSTOM_PROMPT_LENGTH]

    # Check for injection patterns (case-insensitive)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            # Log the attempt and sanitize
            print(f"[SECURITY] Blocked potential prompt injection pattern: {pattern}")
            prompt = re.sub(pattern, "[BLOCKED]", prompt, flags=re.IGNORECASE)

    return prompt


@dataclass
class AgentThought:
    """A thought in the agent's reasoning chain."""
    thought: str
    action: Optional[str] = None
    action_input: Optional[dict] = None
    observation: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ReActSecurityAgent:
    """
    ReAct-style security research agent.

    Runs in a continuous loop:
    1. Think about current state
    2. Decide on action (use tool or report finding)
    3. Execute action
    4. Observe result
    5. Repeat until done
    """

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
        cache: Optional["ToolCache"] = None,
    ):
        self.id = str(uuid.uuid4())[:8]
        self.request = request  # Store for SDK mode fallback in to_schema()/get_state_snapshot()
        self.repo_id = request.repo_id
        self.repo_path = repo_path
        self.agent_type = request.agent_type
        self.scan_tier = request.scan_tier
        self.time_budget_seconds = request.time_budget_seconds
        self.name = request.name or f"react-{self.agent_type.value}-{self.id}"
        self.custom_prompt = request.custom_prompt
        self.focus_areas = request.focus_areas or []

        # Status
        self.status = AgentStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None

        # State
        self.findings: list[Finding] = []
        self.thoughts: list[AgentThought] = []
        self.investigation_notes: list[dict] = []
        self.files_examined: set[str] = set()

        # Duplicate detection - track recent tool calls to prevent loops
        self._recent_tool_calls: dict[str, int] = {}  # hash -> count
        self._max_duplicate_calls = 2  # Max times same call can be made
        self._consecutive_duplicates = 0  # Track consecutive duplicate iterations
        self._max_consecutive_duplicates = 3  # Force move on after this many

        # Turn planning and hypothesis tracking
        self._turn_counter = 0
        self._active_hypotheses: dict[str, Hypothesis] = {}

        # Control
        self._paused = asyncio.Event()
        self._paused.set()  # Not paused initially
        self._cancelled = False
        self._on_message = on_message

        # Tools and provider
        self.tool_executor = ToolExecutor(repo_path, project_id=self.repo_id, cache=cache)

        # Dual-model support
        self._scanner_config: Optional[ProviderConfig] = None
        self._analyzer_config: Optional[ProviderConfig] = None
        self._is_dual_mode: bool = False
        self._handoff_mode: HandoffMode = HandoffMode.SINK_IDENTIFICATION
        self._handoff_state: Optional[ScannerHandoffState] = None
        self._current_phase: str = "scanner"  # "scanner" or "analyzer"
        self._scanner_provider = None
        self._analyzer_provider = None

        # Resolve dual-model config
        self._scanner_config, self._analyzer_config, self._is_dual_mode = resolve_dual_model_config(request)
        self._handoff_mode = get_handoff_mode(request)

        # Deep audits default to dual-mode (cheap scanner + chosen analyzer) unless explicitly configured.
        if (
            not self._is_dual_mode
            and self.agent_type == AgentType.DEEP_AUDIT
            and request.provider_config is not None
        ):
            analyzer = request.provider_config
            scanner_model = DEFAULT_SCANNER_MODELS.get(analyzer.provider) or analyzer.model
            self._scanner_config = ProviderConfig(
                provider=analyzer.provider,
                model=scanner_model,
                api_key=analyzer.api_key,
                base_url=analyzer.base_url,
                temperature=0.0,
                max_tokens=4096,
            )
            self._analyzer_config = analyzer
            self._is_dual_mode = True

        # Check if using Claude SDK mode (provider creation handled separately)
        self._use_claude_sdk = getattr(request, 'use_claude_sdk', False)

        if self._use_claude_sdk:
            # SDK mode: provider creation is handled by ClaudeSDKProvider in orchestrator
            # We still need a placeholder provider reference
            self.provider = None
            self._scanner_provider = None
            self._analyzer_provider = None
        elif self._is_dual_mode:
            self._scanner_provider = get_provider(self._scanner_config)
            self._analyzer_provider = get_provider(self._analyzer_config)
            self.provider = self._scanner_provider  # Start with scanner
        else:
            if request.provider_config is None:
                raise ValueError("provider_config is required for single-model ReAct agents")
            self.provider = get_provider(request.provider_config)

        # Conversation history for the agent
        self.messages: list[dict] = []

        # Limits
        self.max_iterations = 100  # Safety limit (may be overridden by agent profile)
        self.max_tool_calls_per_iteration = 5
        self.max_runtime_seconds: Optional[int] = None
        self.min_runtime_seconds: Optional[int] = None

        # Attack-surface triage rendering/automation knobs (may be overridden by agent profile)
        self._triage_render_limit = 20
        self._triage_prompt_limit = 10
        self._auto_queue_limit = 3

        # Finding acceptance gates (may be overridden by agent profile)
        self._min_finding_confidence = 0.8
        self._require_strict_finding_fields = False
        self._require_ultra_verification = False

        # "Press harder" completion confirmation (may be overridden by agent profile)
        self._audit_complete_confirmations_required = 1
        self._audit_complete_confirmations_seen = 0

        # Rate limiting / throttling
        self.iteration_delay = 2.0  # Seconds to wait between iterations
        self.min_delay = 1.0  # Minimum delay
        self.max_delay = 60.0  # Maximum delay for backoff
        self.current_backoff = 0.0  # Current backoff (resets on success)
        self.backoff_multiplier = 2.0  # Exponential backoff factor

        # Attack-surface triage context (for tree + prompting)
        self._threat_model: str = "AB"
        self._attack_surface_triage: list[AttackSurfaceTriageItem] = []
        self._active_investigation_candidate_node_id: Optional[str] = None
        self._active_investigation_root_node_id: Optional[str] = None

        self._apply_agent_profile()
        self._apply_time_budget()

    def _apply_agent_profile(self) -> None:
        """Tune the ReAct loop behavior based on agent_type.

        The goal is to keep a consistent investigation engine (ReAct + tools),
        while allowing different "scan flavors" via conservative parameter changes.
        """
        if self.agent_type == AgentType.DEEP_AUDIT:
            # Long-running, coverage-oriented mode.
            self.max_runtime_seconds = 60 * 60  # 1 hour
            self.max_iterations = 10_000  # Time-boxed by max_runtime_seconds
            self.max_tool_calls_per_iteration = 8
            self.iteration_delay = 1.0
            self._triage_render_limit = 40
            self._triage_prompt_limit = 20
            self._auto_queue_limit = 8
            self._audit_complete_confirmations_required = 2
            return

        if self.agent_type == AgentType.STRICT_ANALYSIS:
            # Same engine, stricter finding acceptance.
            self.max_iterations = 150
            self._min_finding_confidence = 0.9
            self._require_strict_finding_fields = True
            self._auto_queue_limit = 3
            return

        if self.agent_type == AgentType.ULTRA_STRICT:
            # Strict + second-pass verifier gate.
            self.max_iterations = 200
            self._min_finding_confidence = 0.95
            self._require_strict_finding_fields = True
            self._require_ultra_verification = True
            self._auto_queue_limit = 4
            return

    def _apply_time_budget(self) -> None:
        """Apply a time budget from request.scan_tier/time_budget_seconds.

        The ReAct loop is time-boxed by `max_runtime_seconds`, but also has an iteration cap.
        This ensures the iteration cap cannot end the run early under a time-tiered scan.
        """
        if self.time_budget_seconds is None:
            return

        # Time-box the run.
        self.max_runtime_seconds = int(self.time_budget_seconds)
        if self.agent_type != AgentType.CUSTOM:
            # Time-tiered scans must not accept early completion.
            self.min_runtime_seconds = int(self.time_budget_seconds)

        # Ensure the iteration cap doesn't cut the run short.
        delay = float(self.iteration_delay) if self.iteration_delay else 1.0
        min_iterations = int(self.max_runtime_seconds / max(delay, 0.5)) + 50
        self.max_iterations = max(self.max_iterations, min_iterations)

    async def _build_time_floor_prompt(self, *, elapsed_seconds: float) -> str:
        """Prompt the model to continue investigating until the scan time floor is reached."""
        remaining = 0
        if self.min_runtime_seconds is not None:
            remaining = max(int(self.min_runtime_seconds - elapsed_seconds), 0)

        # Summarize what's still "cold" at a very coarse granularity (root-level coverage).
        unvisited_roots: list[str] = []
        try:
            listing = await self.tool_executor.execute(
                "list_directory",
                {"path": ".", "recursive": False},
            )
            if listing.success and isinstance(listing.data, dict):
                items = listing.data.get("items", [])
                roots = []
                for item in items:
                    if not isinstance(item, str):
                        continue
                    roots.append(item)

                # Mark any root dir as visited if any examined file falls under it.
                for root in roots:
                    if not root.endswith("/"):
                        continue
                    root_prefix = root
                    if not any(p.startswith(root_prefix) for p in self.files_examined):
                        unvisited_roots.append(root)
        except Exception:
            unvisited_roots = []

        pending_queue = 0
        try:
            pending_queue = await investigation_queue_service.size(self.id)
        except Exception:
            pending_queue = 0

        triage_remaining = []
        if self._attack_surface_triage:
            for item in self._attack_surface_triage:
                c = item.candidate
                if c.file_path and c.file_path not in self.files_examined:
                    triage_remaining.append(item)

        triage_hint_lines: list[str] = []
        for item in triage_remaining[:8]:
            c = item.candidate
            loc = f"{c.file_path}:{c.line_number}" if c.line_number else c.file_path
            triage_hint_lines.append(f"- score={item.confidence_score:.2f} {c.label} ({loc})")

        roots_hint = ", ".join(unvisited_roots[:10]) if unvisited_roots else "(none detected)"
        triage_hint = "\n".join(triage_hint_lines) if triage_hint_lines else "(none)"

        tier_label = self.scan_tier or "time-tiered"
        return render_prompt(
            "agents/time_floor_enforcement_prompt.md",
            remaining_s=str(remaining),
            tier_label=tier_label,
            files_examined=str(len(self.files_examined)),
            pending_queue=str(pending_queue),
            roots_hint=roots_hint,
            triage_hint=triage_hint,
        )

    def _profile_prompt_appendix(self) -> str:
        """Extra, profile-specific instructions appended to the system prompt."""
        if self.agent_type == AgentType.DEEP_AUDIT:
            return load_prompt("agents/profile_deep_audit_mode.md")

        if self.agent_type == AgentType.STRICT_ANALYSIS:
            return load_prompt("agents/profile_strict_mode.md")

        if self.agent_type == AgentType.ULTRA_STRICT:
            return load_prompt("agents/profile_ultra_strict_mode.md")

        return ""

    def _time_tier_prompt_appendix(self) -> str:
        """Instructions for time-tiered scans (enforces continued depth)."""
        if self.min_runtime_seconds is None:
            return ""
        tier_label = self.scan_tier or "time-tiered"
        return render_prompt("agents/time_tier_enforcement_appendix.md", tier_label=tier_label)

    def _audit_completion_confirmation_prompt(self) -> str:
        """Ask the model to do an extra pass before ending (used in deep audit mode)."""
        if self.agent_type == AgentType.DEEP_AUDIT:
            return load_prompt("agents/audit_completion_confirmation_deep_audit.md")

        return load_prompt("agents/audit_completion_confirmation_default.md")

    def _detect_category_from_focus_areas(self) -> Optional[str]:
        """Detect vulnerability category from focus_areas."""
        if not self.focus_areas:
            return None

        focus_text = " ".join(self.focus_areas).lower()

        # Check specific injection types first, THEN generic SQL/injection
        if "command" in focus_text and "injection" in focus_text:
            return "COMMAND_INJECTION"
        elif "code injection" in focus_text or ("code" in focus_text and "injection" in focus_text):
            return "CODE_INJECTION"
        elif "sql" in focus_text or "injection" in focus_text:
            return "SQL_INJECTION"
        elif "xss" in focus_text or "cross-site" in focus_text:
            return "XSS"
        elif "ssrf" in focus_text:
            return "SSRF"
        elif "path traversal" in focus_text or "directory traversal" in focus_text:
            return "PATH_TRAVERSAL"
        elif "deserial" in focus_text:
            return "DESERIALIZATION"
        elif "auth" in focus_text and "bypass" in focus_text:
            return "AUTH_BYPASS"
        elif "idor" in focus_text or "insecure direct object" in focus_text:
            return "IDOR"
        # Add more as needed

        return None

    def _build_system_prompt_with_checklist(self, category: Optional[str], repo_info: str) -> str:
        """
        Build system prompt with category-specific validity checklist.

        If category is provided, includes the relevant validity checklist.
        Otherwise, uses base prompts only.
        """
        from services.prompt_router import PromptRouter

        if category:
            router = PromptRouter()
            # Get modules for this category
            modules = router.route(category=category)
            # Assemble with repo info as task context
            base_prompt = router.assemble_from_paths(modules, task=f"Repository context:\n{repo_info}")

            return base_prompt
        else:
            # Legacy behavior: use old prompts if no category
            return render_prompt("agents/react_system_prompt.md", repo_info=repo_info)

    def _guess_language_from_path(self, file_path: str) -> str:
        ext = (file_path.rsplit(".", 1)[-1] if "." in file_path else "").lower()
        if ext in ("py",):
            return "python"
        if ext in ("js", "mjs", "cjs"):
            return "javascript"
        if ext in ("ts",):
            return "typescript"
        if ext in ("tsx",):
            return "tsx"
        if ext in ("jsx",):
            return "jsx"
        if ext in ("yml", "yaml"):
            return "yaml"
        if ext:
            return ext
        return "text"

    def _extract_json_object(self, text: str) -> dict[str, Any]:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("No JSON object found")
        raw = text[start : end + 1]
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Expected JSON object")
        return parsed

    def _validate_reported_finding(self, finding_data: Any) -> tuple[bool, str]:
        if not isinstance(finding_data, dict):
            return False, "Invalid finding payload (expected an object)."

        try:
            confidence = float(finding_data.get("confidence"))
        except Exception:
            return False, "Missing or invalid 'confidence' (expected number 0.0-1.0)."

        if confidence < self._min_finding_confidence:
            return (
                False,
                f"Confidence {confidence:.2f} is below the minimum threshold {self._min_finding_confidence:.2f}.",
            )

        if self._require_strict_finding_fields:
            missing: list[str] = []

            source_trace = finding_data.get("source_trace")
            if not isinstance(source_trace, list) or not any(str(x).strip() for x in source_trace):
                missing.append("source_trace (non-empty array)")

            attack_scenario = finding_data.get("attack_scenario")
            if not isinstance(attack_scenario, str) or not attack_scenario.strip():
                missing.append("attack_scenario")

            proof_of_concept = finding_data.get("proof_of_concept")
            if not isinstance(proof_of_concept, str) or not proof_of_concept.strip():
                missing.append("proof_of_concept")

            if missing:
                return False, "Missing required fields for strict mode: " + ", ".join(missing)

        return True, ""

    async def _ultra_strict_verify_finding(self, finding_data: dict[str, Any]) -> tuple[bool, str]:
        file_path = str(finding_data.get("file_path") or "").strip()
        language = self._guess_language_from_path(file_path)

        code = ""
        if file_path:
            try:
                line_start = int(finding_data.get("line_start") or 1)
                line_end = int(finding_data.get("line_end") or line_start)
                read_args = {
                    "path": file_path,
                    "start_line": max(1, line_start - 20),
                    "end_line": max(line_end + 20, line_start),
                }
                read_result = await self.tool_executor.execute("read_file", read_args)
                if read_result.success and isinstance(read_result.data, dict):
                    code = str(read_result.data.get("content") or "")
            except Exception:
                code = ""

        if not code:
            code = str(finding_data.get("vulnerable_code") or "")

        if not code.strip():
            return False, "Ultra-strict verification failed: no code snippet available."

        finding_blob = json.dumps(finding_data, indent=2, default=str)[:8000]
        code_blob = code[:8000]
        prompt = render_prompt(
            "agents/evidence_verification_prompt.md",
            finding=finding_blob,
            language=language,
            code=code_blob,
        )

        request_id = observability_service.log_llm_request(
            agent_id=self.id,
            messages=[{"role": "user", "content": prompt}],
            tools_available=None,
            model=self.provider.model,
            provider=self.provider.provider_type,
        )

        start_time = datetime.utcnow()
        try:
            raw = await self.provider.generate([Message(role="user", content=prompt)])
        except Exception as e:
            observability_service.log_llm_response(
                agent_id=self.id,
                request_id=request_id,
                content=str(e),
                tool_calls=None,
                usage=None,
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
                model=self.provider.model,
                provider=self.provider.provider_type,
            )
            return False, f"Ultra-strict verifier call failed: {e}"

        observability_service.log_llm_response(
            agent_id=self.id,
            request_id=request_id,
            content=raw,
            tool_calls=None,
            usage=None,
            duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
            model=self.provider.model,
            provider=self.provider.provider_type,
        )

        try:
            parsed = self._extract_json_object(raw)
        except Exception as e:
            return False, f"Ultra-strict verifier returned non-JSON output: {e}"

        verdict = str(parsed.get("verdict") or "").strip().upper()
        try:
            verifier_confidence = float(parsed.get("confidence") or 0.0)
        except Exception:
            verifier_confidence = 0.0

        if verdict != "CONFIRMED":
            assessment = str(parsed.get("final_assessment") or "").strip()
            concerns = parsed.get("concerns")
            concerns_str = ""
            if isinstance(concerns, list) and concerns:
                concerns_str = " Concerns: " + "; ".join(str(c) for c in concerns[:6] if str(c).strip())
            return (
                False,
                f"Verifier verdict={verdict or 'UNKNOWN'} (confidence={verifier_confidence:.2f}). {assessment}{concerns_str}".strip(),
            )

        if verifier_confidence < 0.85:
            return False, f"Verifier confidence {verifier_confidence:.2f} is below 0.85."

        for flag in ("source_verified", "path_verified", "sink_verified", "exploit_viable"):
            if parsed.get(flag) is not True:
                return False, f"Verifier did not confirm {flag}=true."

        return True, ""

    def _init_handoff_state(self) -> ScannerHandoffState:
        """Initialize empty handoff state."""
        return ScannerHandoffState(
            repo_path=self.repo_path,
            scanner_model=self._scanner_config.model if self._scanner_config else "",
        )

    def _add_entry_point(self, name: str, file_path: str, line_number: int,
                         code_snippet: str, method: str = None, route: str = None):
        """Add an entry point to handoff state."""
        if not self._handoff_state:
            return

        ep = EntryPoint(
            name=name,
            file_path=file_path,
            line_number=line_number,
            method=method,
            route=route,
            code_snippet=code_snippet
        )
        self._handoff_state.entry_points.append(ep)

    def _add_sink(self, sink_type: str, function_name: str, file_path: str,
                  line_number: int, code_snippet: str, context: str = None):
        """Add a dangerous sink to handoff state."""
        if not self._handoff_state:
            return

        sink = Sink(
            sink_type=sink_type,
            function_name=function_name,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            context=context
        )
        self._handoff_state.dangerous_sinks.append(sink)

    def _record_file_read(self, path: str, relevance_score: float = 0.0, summary: str = None):
        """Record a file read in handoff state."""
        if not self._handoff_state:
            return

        record = FileReadRecord(
            path=path,
            relevance_score=relevance_score,
            summary=summary
        )
        self._handoff_state.files_read.append(record)

    async def _build_attack_surface_tree(self) -> None:
        """Run an initial scan + conservative triage and render candidate branches in the flow."""
        try:
            project = await project_service.get_project(self.repo_id)
            if project and getattr(project, "threat_model", None):
                self._threat_model = project.threat_model
        except Exception:
            self._threat_model = "AB"

        scan_node = flow_service.add_node(
            self.id,
            "scan",
            f"Attack Surface Scan ({self._threat_model})",
            {"threat_model": self._threat_model},
        )
        flow_service.update_node_status(self.id, scan_node.id, "running")
        self._broadcast_flow_update()

        try:
            candidates = attack_surface_service.scan_candidates(repo_path=self.repo_path)
            triaged = await attack_surface_service.triage(
                agent_id=self.id,
                repo_path=self.repo_path,
                threat_model=self._threat_model,  # type: ignore[arg-type]
                provider=self.provider,
                candidates=candidates,
            )
            self._attack_surface_triage = triaged

            # Persist triaged candidates as sink signals (leads) for this project.
            try:
                signals: list[SinkSignal] = []
                for item in triaged:
                    c = item.candidate
                    kind = (
                        SinkSignalKind.ENTRY_POINT
                        if c.kind == "entry_point"
                        else SinkSignalKind.SINK
                    )
                    score = int(round(max(0.0, min(1.0, float(item.confidence_score))) * 100))
                    signals.append(
                        SinkSignal(
                            fingerprint=c.id,
                            kind=kind,
                            label=c.label,
                            file_path=c.file_path,
                            line_number=c.line_number,
                            status=SinkSignalStatus.UNREVIEWED,
                            source="attack_surface_triage",
                            llm_score=score,
                            llm_reasoning=item.reasoning,
                            metadata={
                                "exposure": item.exposure,
                                "candidate_kind": c.kind,
                                **(c.metadata or {}),
                            },
                        )
                    )
                if signals:
                    await sink_signal_service.upsert_signals(
                        project_id=self.repo_id,
                        signals=signals,
                    )
            except Exception as e:
                self._log(f"Failed to persist sink signals: {e}", "warning")

            flow_service.update_node_data(
                self.id,
                scan_node.id,
                {
                    "candidates_found": len(candidates),
                    "investigate_count": len(triaged),
                },
            )
            flow_service.update_node_status(self.id, scan_node.id, "completed")

            auto_queue_limit = self._auto_queue_limit
            for idx, item in enumerate(triaged[: self._triage_render_limit]):
                c = item.candidate
                node_type = "entry_point" if c.kind == "entry_point" else "dangerous_sink"
                exposure = item.exposure if item.exposure != "unknown" else ""
                label = f"[{exposure}] {c.label}" if exposure else c.label

                candidate_node = flow_service.add_node(
                    self.id,
                    node_type,  # type: ignore[arg-type]
                    label,
                    data={
                        "attack_surface_candidate_id": c.id,
                        "kind": c.kind,
                        "file_path": c.file_path,
                        "line_number": c.line_number,
                        "metadata": c.metadata,
                        "threat_model": self._threat_model,
                        "exposure": item.exposure,
                    },
                    parent_id=scan_node.id,
                    edge_label="candidate",
                    llm_reasoning=item.reasoning,
                    code_context=c.code_context,
                    confidence_score=item.confidence_score,
                    set_current=False,
                )

                # Fully automated mode: auto-queue a small number of top candidates.
                if idx < auto_queue_limit:
                    loc = f"{c.file_path}:{c.line_number}" if c.line_number else c.file_path
                    threat_model_line = f"\nThreat model: {self._threat_model}" if self._threat_model else ""

                    exposure = item.exposure if item.exposure != "unknown" else ""
                    exposure_line = f"\nExposure: {exposure}" if exposure else ""

                    location_line = f"\nLocation: {loc}" if loc else ""

                    triage_rationale = (item.reasoning or "").strip()
                    triage_rationale_line = f"\nTriage rationale: {triage_rationale}" if triage_rationale else ""

                    context = (c.code_context or "").strip()
                    code_context_block = f"\n\nCode context:\n{context[:4000]}" if context else ""

                    prompt = render_prompt(
                        "agents/investigation_task_prompt.md",
                        label=label,
                        node_type=node_type,
                        threat_model_line=threat_model_line,
                        exposure_line=exposure_line,
                        location_line=location_line,
                        triage_rationale_line=triage_rationale_line,
                        user_notes_block="",
                        metadata_block="",
                        code_context_block=code_context_block,
                    )

                    task = investigation_queue_service.new_task(
                        agent_id=self.id,
                        flow_node_id=candidate_node.id,
                        source="auto",
                        prompt=prompt,
                        metadata={
                            "node_type": node_type,
                            "label": label,
                            "file_path": c.file_path,
                            "line_number": c.line_number,
                            "threat_model": self._threat_model,
                            "exposure": item.exposure,
                        },
                    )
                    if await investigation_queue_service.enqueue(task):
                        flow_service.update_node_data(
                            self.id,
                            candidate_node.id,
                            {"queued": True, "queued_by": "auto", "task_id": task.id},
                        )
                        flow_service.add_node(
                            self.id,
                            "investigation",
                            "Queued investigation",
                            {"source": "auto", "task_id": task.id},
                            parent_id=candidate_node.id,
                            edge_label="queued",
                            set_current=False,
                        )

            self._broadcast_flow_update()
        except Exception as e:
            flow_service.update_node_data(self.id, scan_node.id, {"error": str(e)})
            flow_service.update_node_status(self.id, scan_node.id, "failed")
            self._broadcast_flow_update()

    async def _execute_handoff(self):
        """Execute handoff from scanner to analyzer."""
        if not self._is_dual_mode or not self._handoff_state:
            return

        # Record scanner metrics
        scanner_end_time = datetime.utcnow()
        if self.started_at:
            scanner_duration = int((scanner_end_time - self.started_at).total_seconds() * 1000)
        else:
            scanner_duration = 0
        self._handoff_state.scanner_duration_ms = scanner_duration

        # Get token usage for scanner
        usage = observability_service.get_token_usage(self.id)
        self._handoff_state.scanner_tokens_used = usage.prompt_tokens + usage.completion_tokens

        # Broadcast handoff event
        self._broadcast(WSMessageType.PHASE_HANDOFF, {
            "scanner_tokens": self._handoff_state.scanner_tokens_used,
            "scanner_duration_ms": scanner_duration,
            "entry_points_found": len(self._handoff_state.entry_points),
            "sinks_found": len(self._handoff_state.dangerous_sinks),
            "files_read": len(self._handoff_state.files_read),
            "handoff_reason": self._handoff_state.handoff_reason,
        })

        self._log(f"Handoff: {len(self._handoff_state.entry_points)} entry points, "
                  f"{len(self._handoff_state.dangerous_sinks)} sinks, "
                  f"{self._handoff_state.scanner_tokens_used} tokens")

        # Switch to analyzer
        self._current_phase = "analyzer"
        self.provider = self._analyzer_provider

        # Build analyzer prompt with handoff context
        analyzer_prompt = format_analyzer_prompt(self._handoff_state.model_dump())

        # Reset conversation for analyzer (fresh start with context)
        self.messages = [
            {"role": "system", "content": analyzer_prompt},
            {"role": "user", "content": load_prompt("agents/react_analyzer_initial_user_message.md")},
        ]

    def _broadcast(self, msg_type: WSMessageType, data: dict):
        """Send message via WebSocket."""
        if self._on_message:
            self._on_message(WSMessage(
                type=msg_type,
                agent_id=self.id,
                data=data,
            ))

    def _log(self, message: str, level: str = "info"):
        """Log agent activity."""
        self._broadcast(WSMessageType.LOG, {
            "level": level,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        })
        print(f"[{self.id}] {level.upper()}: {message}")

    async def run(self) -> list[Finding]:
        """Run the agent's investigation loop."""
        self.status = AgentStatus.RUNNING
        self.started_at = datetime.utcnow()
        self._broadcast(WSMessageType.AGENT_STATUS, {"status": "running"})

        # Initialize flow tracking
        flow_service.initialize_flow(self.id)
        start_node = flow_service.add_node(
            self.id, "user_input", "Start Investigation",
            {"agent_type": self.agent_type.value}
        )
        flow_service.update_node_status(self.id, start_node.id, "completed")
        await self._build_attack_surface_tree()

        # Initialize code graph for visualization
        try:
            await code_graph_service.initialize_graph(self.id, self.repo_path)
        except Exception as e:
            self._log(f"Failed to initialize code graph: {e}", "warning")

        try:
            await self._investigation_loop()
            self.status = AgentStatus.COMPLETED

            # Add completion node
            flow_service.add_node(
                self.id, "analysis", "Audit Complete",
                {"findings_count": len(self.findings)}
            )
        except asyncio.CancelledError:
            self.status = AgentStatus.CANCELLED
            self._log("Agent cancelled", "warning")
        except Exception as e:
            self.status = AgentStatus.FAILED
            self.error_message = str(e)
            self._log(f"Agent failed: {e}", "error")
            raise
        finally:
            self.completed_at = datetime.utcnow()
            self._broadcast(WSMessageType.AGENT_STATUS, {"status": self.status.value})
            self._broadcast_flow_update()

        return self.findings

    def _broadcast_flow_update(self):
        """Send flow update to WebSocket."""
        flow = flow_service.get_flow(self.id)
        if flow:
            self._broadcast(WSMessageType.PROGRESS, {
                "type": "flow_update",
                "flow": flow.to_dict()
            })

    async def _maybe_start_next_queued_investigation(self) -> None:
        """If idle, dequeue and start the next queued investigation task."""
        if self._active_investigation_candidate_node_id:
            return

        task = await investigation_queue_service.dequeue(self.id)
        if not task:
            return

        self._active_investigation_candidate_node_id = task.flow_node_id

        # Mark the candidate node as running and branch under it.
        flow_service.update_node_status(self.id, task.flow_node_id, "running")
        flow_service.update_node_data(
            self.id,
            task.flow_node_id,
            {"queued": False, "in_progress": True, "active_task_id": task.id},
        )
        inv_node = flow_service.add_node(
            self.id,
            "investigation",
            "Investigate",
            {"task_id": task.id, "source": task.source},
            parent_id=task.flow_node_id,
            edge_label="investigate",
        )
        flow_service.update_node_status(self.id, inv_node.id, "running")
        self._active_investigation_root_node_id = inv_node.id

        # Ensure subsequent tool nodes attach to this investigation branch.
        flow_service.branch_from(self.id, inv_node.id)
        self._broadcast_flow_update()

        # Inject the investigation task as the next user instruction.
        self.messages.append({"role": "user", "content": task.prompt})

    def _extract_investigation_complete_summary(self, content: str) -> Optional[str]:
        marker = "INVESTIGATION_COMPLETE"
        if marker not in content:
            return None
        tail = content.split(marker, 1)[1]
        if tail.startswith(":"):
            tail = tail[1:]
        summary = tail.strip()
        return summary[:800] if summary else ""

    def _complete_active_investigation(self, summary: str) -> None:
        """Mark the current investigation branch completed and attach a short summary."""
        candidate_id = self._active_investigation_candidate_node_id
        root_id = self._active_investigation_root_node_id
        if candidate_id:
            flow_service.update_node_status(self.id, candidate_id, "completed")
            flow_service.update_node_fields(self.id, candidate_id, tool_result_summary=summary)
            flow_service.update_node_data(
                self.id,
                candidate_id,
                {"investigation_complete": True, "in_progress": False, "investigation_summary": summary},
            )
        if root_id:
            flow_service.update_node_status(self.id, root_id, "completed")
            flow_service.update_node_fields(self.id, root_id, tool_result_summary=summary)

        self._active_investigation_candidate_node_id = None
        self._active_investigation_root_node_id = None
        self._broadcast_flow_update()

    def _emit_turn_plan_for_hypothesis(
        self,
        hypothesis_id: str,
        hypothesis_label: str,
        turn_id: str,
        focus_gap: str = "other",
        parent_hypothesis_id: Optional[str] = None
    ) -> str:
        """Emit a turn plan for the given hypothesis.

        Creates or reuses spans, builds turn plan, and emits to FlowService.

        Args:
            hypothesis_id: Unique identifier for this hypothesis
            hypothesis_label: Human-readable description
            turn_id: Current turn identifier
            focus_gap: Type of evidence gap (default: "other")
            parent_hypothesis_id: Optional parent hypothesis ID

        Returns:
            span_id: The span ID for this hypothesis
        """
        # Check if hypothesis already exists
        existing_hypothesis = self._active_hypotheses.get(hypothesis_id)

        if existing_hypothesis:
            # Continuing existing hypothesis
            activity = HypothesisActivity.CONTINUING
            span_id = existing_hypothesis.span_id
            parent_span_id = existing_hypothesis.parent_span_id
        else:
            # New hypothesis - create span
            activity = HypothesisActivity.NEW
            span_id = f"span_{hypothesis_id}"
            parent_span_id = None

            # Create span in SpanService
            span_service.create_span(
                agent_id=self.id,
                span_id=span_id,
                span_type=SpanType.HYPOTHESIS,
                hypothesis_id=hypothesis_id,
                label=hypothesis_label,
                state=SpanState.OPEN,
                parent_span_id=parent_span_id,
                focus_gap=FocusGap(focus_gap) if focus_gap else None,
                created_turn_id=int(turn_id) if turn_id.isdigit() else 0
            )

        # Create Hypothesis object
        hypothesis = Hypothesis(
            hypothesis_id=hypothesis_id,
            label=hypothesis_label,
            state="active",
            activity=activity,
            created_turn_id=turn_id,
            focus_gap=FocusGap(focus_gap) if focus_gap else FocusGap.OTHER,
            parent_hypothesis_id=parent_hypothesis_id,
            span_id=span_id,
            parent_span_id=parent_span_id
        )

        # Store in active hypotheses
        self._active_hypotheses[hypothesis_id] = hypothesis

        # Create TurnPlan with single hypothesis
        turn_plan = TurnPlan(
            turn_id=turn_id,
            goal=f"Investigate: {hypothesis_label}",
            hypotheses=[hypothesis],
            selected_hypothesis_id=hypothesis_id,
            selected_span_id=span_id
        )

        # Emit turn plan to FlowService
        flow_service.emit_turn_plan(self.id, turn_plan)

        return span_id

    async def _investigation_loop(self):
        """Main investigation loop."""
        # Build initial context
        repo_info = await self._get_repo_info()

        # Initialize handoff state if in dual mode
        if self._is_dual_mode:
            self._handoff_state = self._init_handoff_state()
            # Use scanner prompt in dual mode
            sanitized_prompt = sanitize_custom_prompt(self.custom_prompt)
            system_prompt = format_scanner_prompt(
                repo_info=repo_info,
                handoff_after=self._handoff_mode.value,
                custom_focus=sanitized_prompt
            )
            if self._attack_surface_triage:
                triage_items: list[str] = []
                for item in self._attack_surface_triage[: self._triage_prompt_limit]:
                    c = item.candidate
                    loc = f"{c.file_path}:{c.line_number}" if c.line_number else c.file_path
                    exposure = item.exposure if item.exposure != "unknown" else "?"
                    triage_items.append(
                        f"- [{exposure}] score={item.confidence_score:.2f} {c.label} ({loc}) — {item.reasoning}"
                    )

                system_prompt += "\n\n" + render_prompt(
                    "agents/attack_surface_triage_block.md",
                    threat_model=self._threat_model,
                    triage_items="\n".join(triage_items),
                )

            appendix = self._profile_prompt_appendix()
            if appendix:
                system_prompt += "\n\n" + appendix + "\n"

            # Inject classification gate prompt
            classification_prompt = get_classification_gate_prompt(self._threat_model)
            system_prompt += "\n\n" + classification_prompt + "\n"

            time_tier_appendix = self._time_tier_prompt_appendix()
            if time_tier_appendix:
                system_prompt += "\n\n" + time_tier_appendix + "\n"

            self.messages = [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": load_prompt("agents/react_initial_user_message.md"),
                }
            ]
        else:
            # Single model mode - detect category and use PromptRouter if available
            category = self._detect_category_from_focus_areas()
            system_prompt = self._build_system_prompt_with_checklist(category, repo_info)

            # Sanitize and add custom prompt if provided (security: prevent prompt injection)
            sanitized_prompt = sanitize_custom_prompt(self.custom_prompt)
            if sanitized_prompt and not category:
                # Only add custom prompt block if we didn't use PromptRouter
                # (PromptRouter already incorporates focus via category)
                system_prompt += "\n\n" + render_prompt("agents/user_focus_area.md", custom_focus=sanitized_prompt)

            if self._attack_surface_triage:
                triage_items: list[str] = []
                for item in self._attack_surface_triage[: self._triage_prompt_limit]:
                    c = item.candidate
                    loc = f"{c.file_path}:{c.line_number}" if c.line_number else c.file_path
                    exposure = item.exposure if item.exposure != "unknown" else "?"
                    triage_items.append(
                        f"- [{exposure}] score={item.confidence_score:.2f} {c.label} ({loc}) — {item.reasoning}"
                    )

                system_prompt += "\n\n" + render_prompt(
                    "agents/attack_surface_triage_block.md",
                    threat_model=self._threat_model,
                    triage_items="\n".join(triage_items),
                )

            appendix = self._profile_prompt_appendix()
            if appendix:
                system_prompt += "\n\n" + appendix + "\n"

            # Inject classification gate prompt
            classification_prompt = get_classification_gate_prompt(self._threat_model)
            system_prompt += "\n\n" + classification_prompt + "\n"

            time_tier_appendix = self._time_tier_prompt_appendix()
            if time_tier_appendix:
                system_prompt += "\n\n" + time_tier_appendix + "\n"

            self.messages = [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": load_prompt("agents/react_initial_user_message.md"),
                }
            ]

        iteration = 0
        consecutive_no_tool = 0

        while iteration < self.max_iterations and not self._cancelled:
            iteration += 1

            # Check if paused
            await self._paused.wait()

            if self._cancelled:
                break

            if self.max_runtime_seconds and self.started_at:
                elapsed = (datetime.utcnow() - self.started_at).total_seconds()
                if elapsed >= self.max_runtime_seconds:
                    self._log(f"Max runtime reached ({int(elapsed)}s). Stopping audit.")
                    break

            # Add phase label in dual mode
            phase_label = f"[{self._current_phase}] " if self._is_dual_mode else ""
            self._log(f"{phase_label}Investigation iteration {iteration}")
            self._broadcast(WSMessageType.PROGRESS, {
                "iteration": iteration,
                "max_iterations": self.max_iterations,
                "findings_count": len(self.findings),
                "files_examined": len(self.files_examined),
                "phase": self._current_phase if self._is_dual_mode else "single"
            })

            # If the user/LLM queued investigations, start them as discrete branches.
            await self._maybe_start_next_queued_investigation()

            # Get LLM response with tools
            try:
                response = await self._call_llm_with_tools()
                # Reset backoff on successful call
                self.current_backoff = 0.0
            except Exception as e:
                error_str = str(e).lower()

                # Check for rate limit errors (429)
                if "429" in error_str or "rate" in error_str or "limit" in error_str:
                    # Exponential backoff for rate limits
                    if self.current_backoff == 0:
                        self.current_backoff = self.iteration_delay
                    else:
                        self.current_backoff = min(
                            self.current_backoff * self.backoff_multiplier,
                            self.max_delay
                        )
                    self._log(f"Rate limited. Backing off for {self.current_backoff:.1f}s", "warning")
                    await asyncio.sleep(self.current_backoff)
                else:
                    self._log(f"LLM call failed: {e}", "error")
                    await asyncio.sleep(2)
                continue

            # Process response
            if response.get("tool_calls"):
                consecutive_no_tool = 0
                await self._process_tool_calls(response["tool_calls"])
            else:
                consecutive_no_tool += 1
                content = response.get("content", "")

                # Check for scanning complete signal in dual mode scanner phase
                if self._is_dual_mode and self._current_phase == "scanner" and "SCANNING_COMPLETE" in content:
                    self._log("Scanner signaled scanning complete, executing handoff")
                    self._handoff_state.handoff_reason = (
                        "exploration_complete" if self._handoff_mode == HandoffMode.EXPLORATION
                        else "sink_identification_complete"
                    )
                    await self._execute_handoff()
                    consecutive_no_tool = 0  # Reset for analyzer phase
                    continue

                # Check if audit is complete
                if "AUDIT_COMPLETE" in content:
                    elapsed = None
                    if self.started_at:
                        elapsed = (datetime.utcnow() - self.started_at).total_seconds()

                    if (
                        elapsed is not None
                        and self.min_runtime_seconds is not None
                        and elapsed < self.min_runtime_seconds
                    ):
                        self._log(
                            "Agent requested AUDIT_COMPLETE before time floor; steering to continue "
                            f"({int(elapsed)}s/{int(self.min_runtime_seconds)}s)"
                        )
                        self.messages.append({"role": "assistant", "content": content})
                        self.messages.append(
                            {
                                "role": "user",
                                "content": await self._build_time_floor_prompt(elapsed_seconds=elapsed),
                            }
                        )
                        consecutive_no_tool = 0
                        continue

                    self._audit_complete_confirmations_seen += 1
                    if self._audit_complete_confirmations_seen < self._audit_complete_confirmations_required:
                        self._log(
                            "Agent signaled audit complete; requesting another sweep "
                            f"({self._audit_complete_confirmations_seen}/{self._audit_complete_confirmations_required})"
                        )
                        self.messages.append({"role": "assistant", "content": content})
                        self.messages.append(
                            {
                                "role": "user",
                                "content": self._audit_completion_confirmation_prompt(),
                            }
                        )
                        consecutive_no_tool = 0
                        continue

                    self._log("Agent signaled audit complete")
                    break

                investigation_summary = self._extract_investigation_complete_summary(content)
                if investigation_summary is not None and self._active_investigation_candidate_node_id:
                    # Record completion, then immediately continue (next iteration can pick next queued task).
                    self._complete_active_investigation(investigation_summary)
                    consecutive_no_tool = 0
                    self.messages.append({"role": "assistant", "content": content})
                    self.messages.append({
                        "role": "user",
                        "content": (
                            "Continue.\n"
                            "- If there are more queued investigations, proceed to the next one.\n"
                            "- Otherwise, continue auditing using tools, or say AUDIT_COMPLETE when finished.\n"
                        ),
                    })
                    continue

                # Add assistant response
                self.messages.append({"role": "assistant", "content": content})

                # If no tools for a while, prompt to continue or finish
                if consecutive_no_tool >= 3:
                    if self._is_dual_mode and self._current_phase == "scanner":
                        self.messages.append({
                            "role": "user",
                            "content": "Please continue scanning using the tools, or if you've mapped the codebase and found entry points and sinks, say 'SCANNING_COMPLETE'."
                        })
                    else:
                        self.messages.append({
                            "role": "user",
                            "content": "Please continue investigating using the tools, or if you've completed the audit, say 'AUDIT_COMPLETE'."
                        })

            # Safety check on message length
            if len(self.messages) > 100:
                # Summarize and compact
                self._compact_messages()

            # Throttle: Wait before next iteration to avoid rate limits
            # This gives the API time to breathe and prevents spam
            await asyncio.sleep(self.iteration_delay)

        self._log(f"Investigation complete. {len(self.findings)} findings reported.")

    async def _get_repo_info(self) -> str:
        """Get repository information for context."""
        info_parts = [f"Repository path: {self.repo_path}"]

        # List root directory
        result = await self.tool_executor.execute("list_directory", {"path": ".", "recursive": False})
        if result.success:
            items = result.data.get("items", [])
            info_parts.append(f"Root contents: {', '.join(items[:30])}")

        # Detect technology
        tech_indicators = {
            "requirements.txt": "Python",
            "pyproject.toml": "Python",
            "package.json": "JavaScript/Node.js",
            "go.mod": "Go",
            "Cargo.toml": "Rust",
            "pom.xml": "Java/Maven",
            "build.gradle": "Java/Gradle",
            "Gemfile": "Ruby",
            "composer.json": "PHP",
        }

        detected_tech = []
        for file, tech in tech_indicators.items():
            check = await self.tool_executor.execute("read_file", {"path": file, "start_line": 1, "end_line": 1})
            if check.success:
                detected_tech.append(tech)

        if detected_tech:
            info_parts.append(f"Detected technologies: {', '.join(detected_tech)}")

        return "\n".join(info_parts)

    async def _call_llm_with_tools(self) -> dict:
        """Call LLM with tool use capability."""
        # Convert tools to provider format
        tools = self._format_tools_for_provider()
        tool_names = [t.get("function", {}).get("name", "") for t in tools]

        # Log the LLM request
        request_id = observability_service.log_llm_request(
            agent_id=self.id,
            messages=self.messages,
            tools_available=tool_names,
            model=self.provider.model,
            provider=self.provider.provider_type,
        )

        # Call provider and measure duration
        start_time = datetime.utcnow()
        response = await self.provider.chat_with_tools(
            messages=self.messages,
            tools=tools
        )
        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Log the LLM response
        observability_service.log_llm_response(
            agent_id=self.id,
            request_id=request_id,
            content=response.get("content", ""),
            tool_calls=response.get("tool_calls"),
            usage=response.get("usage"),
            duration_ms=duration_ms,
            model=self.provider.model,
            provider=self.provider.provider_type,
        )

        return response

    def _format_tools_for_provider(self) -> list[dict]:
        """Format tools for the provider's API."""
        # OpenAI format
        return [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["parameters"]
                }
            }
            for tool in AGENT_TOOLS
        ]

    def _hash_tool_call(self, tool_name: str, arguments: dict) -> str:
        """Create a hash of a tool call for duplicate detection."""
        import hashlib
        # Normalize arguments by sorting keys
        sorted_args = json.dumps(arguments, sort_keys=True, default=str)
        call_str = f"{tool_name}:{sorted_args}"
        return hashlib.md5(call_str.encode()).hexdigest()[:12]

    def _is_duplicate_call(self, tool_name: str, arguments: dict) -> tuple[bool, int]:
        """Check if this tool call is a duplicate. Returns (is_dup, count)."""
        call_hash = self._hash_tool_call(tool_name, arguments)
        count = self._recent_tool_calls.get(call_hash, 0)
        is_duplicate = count >= self._max_duplicate_calls
        return is_duplicate, count

    def _record_tool_call(self, tool_name: str, arguments: dict):
        """Record a tool call for duplicate detection."""
        call_hash = self._hash_tool_call(tool_name, arguments)
        self._recent_tool_calls[call_hash] = self._recent_tool_calls.get(call_hash, 0) + 1

    async def _process_tool_calls(self, tool_calls: list[dict]):
        """Process tool calls from LLM."""
        tool_results = []
        all_duplicates = True  # Track if ALL calls in this batch are duplicates

        for i, call in enumerate(tool_calls[:self.max_tool_calls_per_iteration]):
            tool_name = call.get("name") or call.get("function", {}).get("name")
            tool_call_id = call.get("id", f"call_{i}")

            # Parse arguments
            args_str = call.get("arguments") or call.get("function", {}).get("arguments", "{}")
            try:
                arguments = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                arguments = {}

            # Check for duplicate call
            is_duplicate, call_count = self._is_duplicate_call(tool_name, arguments)
            if is_duplicate:
                self._log(f"Skipping duplicate tool call: {tool_name} (called {call_count} times)", "warning")
                # Return a message telling the LLM to try something different
                tool_results.append({
                    "tool_call_id": tool_call_id,
                    "role": "tool",
                    "content": f"DUPLICATE CALL BLOCKED: You've already called {tool_name} with these exact arguments {call_count} times. The result won't change. Please try a DIFFERENT approach - use different arguments, a different tool, or move on to investigate other areas of the codebase."
                })
                continue
            else:
                all_duplicates = False

            # Record this call
            self._record_tool_call(tool_name, arguments)

            self._log(f"Tool: {tool_name}({list(arguments.keys())})")

            # Add flow node for tool call
            node_type = self._get_flow_node_type(tool_name)
            node_label = self._get_flow_node_label(tool_name, arguments)
            tool_node = flow_service.add_node(
                self.id, node_type, node_label,
                {"tool": tool_name, "args": arguments}
            )
            flow_service.update_node_status(self.id, tool_node.id, "running")
            self._broadcast_flow_update()

            start_time = datetime.utcnow()

            # Track files examined
            if tool_name == "read_file" and "path" in arguments:
                self.files_examined.add(arguments["path"])

            # FILE READ: Create file and function nodes
            if tool_name == "read_file":
                file_path = arguments.get("path", "")

                # Validate file path
                if not file_path:
                    self._log("read_file called with empty path", "warning")
                    # Skip file node creation, let tool execute normally
                    pass  # Fall through to normal execution
                else:
                    # Get or create file node
                    file_node = flow_service.get_or_create_file_node(self.id, file_path)

                    if not file_node:
                        # Create new file node
                        file_node = flow_service.add_node(
                            self.id,
                            "file",
                            f"📄 {os.path.basename(file_path)}",
                            {
                                "file_path": file_path,
                                "full_path": file_path,
                                "tool": "read_file"
                            },
                            auto_parent=True
                        )

                    # Update context
                    try:
                        flow_service.update_context(self.id, current_file=file_path)
                    except Exception as e:
                        self._log(f"Failed to update flow context: {e}", "warning")

                    try:
                        flow_service.update_node_status(self.id, file_node.id, "running")
                    except Exception as e:
                        self._log(f"Failed to update flow node status: {e}", "warning")

            # Execute tool
            result = await self.tool_executor.execute(tool_name, arguments)

            # Calculate duration
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            # Build code context for read_file
            code_context = None
            if tool_name == "read_file" and result.success:
                code_context = self._build_code_context(arguments, result)
                # Mark file as visited in code graph
                file_path = str(arguments.get("path") or "")
                try:
                    code_graph_service.mark_visited(self.id, file_path, duration_ms)
                except Exception as e:
                    self._log(f"Failed to mark file visited in code graph: {e}", "warning")

                # Complete file node and extract functions
                # file_node already exists from pre-execution logic
                # No need to call get_or_create_file_node again
                if file_path:
                    file_node = flow_service.get_or_create_file_node(self.id, file_path)
                    if file_node:
                        try:
                            flow_service.update_node_status(self.id, file_node.id, "completed")
                        except Exception as e:
                            self._log(f"Failed to update flow node status: {e}", "warning")

                        # Parse result to extract functions
                        try:
                            # read_file tool returns string directly as data
                            if not isinstance(result.data, str):
                                self._log(f"Unexpected data type from read_file: {type(result.data)}", "warning")
                                content = str(result.data)
                            else:
                                content = result.data

                            functions = self._extract_functions_from_code(content)
                            for func in functions[:10]:  # Limit to first 10 functions
                                try:
                                    func_node = flow_service.add_node(
                                        self.id,
                                        "function",
                                        f"⚡ {func['name']}()",
                                        {
                                            "function_name": func["name"],
                                            "line_number": func.get("line_number"),
                                            "signature": func.get("signature"),
                                        },
                                        parent_id=file_node.id,
                                        auto_parent=False,
                                        set_current=False
                                    )
                                except Exception as e:
                                    self._log(f"Failed to add function node: {e}", "warning")
                        except Exception as e:
                            self._log(f"Failed to extract functions from {file_path}: {e}", "debug")
                            # Continue without function nodes - this is non-critical

                        try:
                            self._broadcast_flow_update()
                        except Exception as e:
                            self._log(f"Failed to broadcast flow update: {e}", "warning")

            tool_success = result.success
            tool_error = result.error

            # Handle special case: finding reported (with strict/ultra gates)
            if tool_name == "report_finding" and result.success:
                finding_data = result.data.get("finding", {}) if isinstance(result.data, dict) else {}
                ok, reason = self._validate_reported_finding(finding_data)
                if not ok:
                    tool_success = False
                    tool_error = reason
                    result_str = (
                        "REJECTED report_finding: "
                        + reason
                        + "\nStrictness rule: do NOT report uncertain issues. Keep investigating or say AUDIT_COMPLETE."
                    )[:4000]
                    flow_service.update_node_data(self.id, tool_node.id, {"rejected": True, "reason": reason})
                else:
                    if self._require_ultra_verification:
                        verified, verify_reason = await self._ultra_strict_verify_finding(finding_data)
                        if not verified:
                            tool_success = False
                            tool_error = verify_reason
                            result_str = ("REJECTED report_finding (verifier): " + verify_reason)[:4000]
                            flow_service.update_node_data(
                                self.id,
                                tool_node.id,
                                {"rejected": True, "reason": verify_reason, "verification": "failed"},
                            )
                        else:
                            await self._create_finding(finding_data)
                            result_str = "Finding reported successfully."

                            # Add finding node to flow
                            flow_service.add_node(
                                self.id, "finding", finding_data.get("title", "Finding"),
                                {"severity": finding_data.get("severity", "medium")}
                            )
                            flow_service.update_node_data(self.id, tool_node.id, {"verification": "passed"})
                    else:
                        await self._create_finding(finding_data)
                        result_str = "Finding reported successfully."

                        # Add finding node to flow
                        flow_service.add_node(
                            self.id, "finding", finding_data.get("title", "Finding"),
                            {"severity": finding_data.get("severity", "medium")}
                        )
            else:
                # Format result for LLM
                if result.success:
                    if isinstance(result.data, dict):
                        result_str = json.dumps(result.data, indent=2, default=str)[:4000]
                    else:
                        result_str = str(result.data)[:4000]
                else:
                    result_str = f"Error: {result.error}"

            # Update flow node status
            status = "completed" if tool_success else "failed"
            flow_service.update_node_status(self.id, tool_node.id, status, duration_ms)
            self._broadcast_flow_update()

            # Log tool execution to observability service
            observability_service.log_tool_execution(
                agent_id=self.id,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                arguments=arguments,
                result=result.data if tool_success else tool_error,
                success=tool_success,
                duration_ms=duration_ms,
                error_message=tool_error if not tool_success else None,
                code_context=code_context,
            )

            # Record in handoff state if in scanner phase
            if self._is_dual_mode and self._current_phase == "scanner" and result.success:
                if tool_name == "read_file":
                    self._record_file_read(
                        path=arguments.get("path", ""),
                        relevance_score=0.5  # Could enhance with actual scoring
                    )

            tool_results.append({
                "tool_call_id": tool_call_id,
                "role": "tool",
                "content": result_str
            })

            # Record thought
            self.thoughts.append(AgentThought(
                thought=f"Using {tool_name}",
                action=tool_name,
                action_input=arguments,
                observation=result_str[:500]
            ))

        # Add results to conversation
        # First add the assistant message with tool calls
        self.messages.append({
            "role": "assistant",
            "content": "",  # OpenAI requires non-null content
            "tool_calls": tool_calls[:self.max_tool_calls_per_iteration]
        })

        # Then add tool results
        self.messages.extend(tool_results)

        # Track consecutive duplicate iterations
        if all_duplicates and len(tool_calls) > 0:
            self._consecutive_duplicates += 1
            self._log(f"Consecutive duplicate iterations: {self._consecutive_duplicates}", "warning")

            if self._consecutive_duplicates >= self._max_consecutive_duplicates:
                # Force the LLM to change strategy
                self._log("Forcing strategy change due to repeated duplicates", "warning")
                self.messages.append({
                    "role": "user",
                    "content": "IMPORTANT: You appear to be stuck in a loop, repeatedly trying the same tool calls. This is not productive. Please:\n1. Review what you've already discovered\n2. Choose a COMPLETELY DIFFERENT investigation approach\n3. Try different files, different search patterns, or different tools\n4. If you've found no vulnerabilities after thorough investigation, say 'AUDIT_COMPLETE'\n\nDo NOT repeat the same tool calls again."
                })
                self._consecutive_duplicates = 0  # Reset after intervention
        else:
            self._consecutive_duplicates = 0  # Reset on successful unique calls

    def _build_code_context(self, arguments: dict, result: ToolResult) -> Optional[dict]:
        """Build code context from a read_file result for observability."""
        if not result.success or not result.data:
            return None

        file_path = arguments.get("path", "")
        content = result.data.get("content", "") if isinstance(result.data, dict) else str(result.data)
        start_line = arguments.get("start_line", 1)
        end_line = arguments.get("end_line")

        # Split content into lines
        lines = content.split("\n")

        # Calculate context (10 lines before/after the requested range)
        context_lines = 10
        before_start = max(0, 0)  # We only have what was returned
        after_end = len(lines)

        # For now, return the content with metadata
        return {
            "file_path": file_path,
            "line_range": [start_line, end_line or (start_line + len(lines) - 1)],
            "content": content[:5000] if len(content) > 5000 else content,
            "total_lines": len(lines),
        }

    def _get_flow_node_type(self, tool_name: str) -> str:
        """Map tool name to flow node type."""
        type_map = {
            "read_file": "code_read",
            "search_code": "search",
            "grep_search": "search",
            "list_directory": "tool_call",
            "run_semgrep": "scan",
            "pattern_scan": "scan",
            "report_finding": "finding",
        }
        return type_map.get(tool_name, "tool_call")

    def _get_flow_node_label(self, tool_name: str, args: dict) -> str:
        """Create a readable label for the flow node."""
        if tool_name == "read_file":
            return f"Read: {args.get('path', 'file')}"
        elif tool_name in ("search_code", "grep_search"):
            pattern = args.get("pattern", args.get("query", "pattern"))
            return f"Search: {pattern[:30]}"
        elif tool_name == "list_directory":
            return f"List: {args.get('path', '.')}"
        elif tool_name == "run_semgrep":
            return f"Semgrep: {args.get('scope', '.')}"
        elif tool_name == "pattern_scan":
            return f"Pattern scan"
        elif tool_name == "report_finding":
            return "Report finding"
        return tool_name

    async def _create_finding(self, data: dict):
        """Create a Finding from reported data."""
        try:
            finding = Finding(
                id=str(uuid.uuid4())[:8],
                agent_id=self.id,
                repo_id=self.repo_id,
                severity=Severity(data.get("severity", "medium")),
                title=data.get("title", "Untitled Finding"),
                description=data.get("description", ""),
                file_path=data.get("file_path", ""),
                line_start=data.get("line_start", 0),
                line_end=data.get("line_end"),
                code_snippet=data.get("vulnerable_code"),
                vulnerable_code=data.get("vulnerable_code"),
                vulnerability_type=data.get("vulnerability_type", "Unknown"),
                cwe_id=data.get("cwe_id"),
                attack_scenario=data.get("attack_scenario"),
                proof_of_concept=data.get("proof_of_concept"),
                recommended_fix=data.get("recommended_fix"),
                confidence=data.get("confidence", 0.8),
                source_trace=data.get("source_trace"),
                created_at=datetime.utcnow(),
                metadata={"agent_type": self.agent_type.value}
            )

            self.findings.append(finding)
            self._broadcast(WSMessageType.FINDING, finding.model_dump(mode='json'))
            self._log(f"Finding reported: {finding.title} ({finding.severity.value})")

        except Exception as e:
            self._log(f"Failed to create finding: {e}", "error")

    def _compact_messages(self):
        """Compact conversation history to stay within limits.

        IMPORTANT: Must preserve complete turns to avoid OpenAI error:
        "messages with role 'tool' must be a response to a preceeding message with 'tool_calls'"
        """
        if len(self.messages) <= 25:
            return

        system_msg = self.messages[0]

        # Find complete turns from recent messages
        # A complete turn is either:
        # 1. A user message
        # 2. An assistant message (with or without tool_calls)
        # 3. Tool results (must follow their assistant message)
        recent_messages = []
        i = len(self.messages) - 1
        target_count = 15  # Keep fewer messages to leave room for new ones

        while i > 0 and len(recent_messages) < target_count:
            msg = self.messages[i]

            if msg.get("role") == "tool":
                # This is a tool result - find its corresponding assistant message with tool_calls
                tool_results = [msg]
                j = i - 1

                # Collect all consecutive tool results
                while j > 0 and self.messages[j].get("role") == "tool":
                    tool_results.insert(0, self.messages[j])
                    j -= 1

                # The message before tool results should be assistant with tool_calls
                if j > 0 and self.messages[j].get("role") == "assistant" and self.messages[j].get("tool_calls"):
                    recent_messages = [self.messages[j]] + tool_results + recent_messages
                    i = j - 1
                else:
                    # Skip orphaned tool results
                    i -= 1
            elif msg.get("role") == "assistant" and msg.get("tool_calls"):
                # Assistant with tool_calls - need to include subsequent tool results
                # But we process from the end, so this shouldn't happen often
                # Skip it - we'll catch it when we see the tool results
                i -= 1
            else:
                # User message or assistant without tool_calls - safe to include
                recent_messages.insert(0, msg)
                i -= 1

        # Add summary
        summary = {
            "role": "user",
            "content": f"[Previous investigation summarized: Examined {len(self.files_examined)} files, found {len(self.findings)} vulnerabilities. Continue investigation.]"
        }

        self.messages = [system_msg, summary] + recent_messages
        self._log(f"Conversation history compacted to {len(self.messages)} messages")

    def pause(self):
        """Pause the agent."""
        self._paused.clear()
        self.status = AgentStatus.PAUSED
        self._broadcast(WSMessageType.AGENT_STATUS, {"status": "paused"})

    def resume(self):
        """Resume the agent."""
        self._paused.set()
        self.status = AgentStatus.RUNNING
        self._broadcast(WSMessageType.AGENT_STATUS, {"status": "running"})

    def cancel(self):
        """Cancel the agent."""
        self._cancelled = True
        self._paused.set()  # Unpause to allow loop to exit

    def request_pause(self):
        """Request the agent to pause at the next safe point (for session hibernation)."""
        self.pause()

    def is_pausable(self) -> bool:
        """Check if agent can be paused."""
        return self.status == AgentStatus.RUNNING

    def get_pause_state(self) -> dict:
        """Get current state for snapshot."""
        return {
            "processed_files": list(self.files_examined),
            "pending_files": [],  # ReAct agent doesn't track pending files the same way
            "current_file": None,
        }

    def to_schema(self):
        """Convert to API schema."""
        from models.schemas import Agent, ProviderConfig
        # Build provider_config - use request config for SDK mode (provider is None)
        if self.provider is not None:
            provider_config = ProviderConfig(
                provider=self.provider.provider_type,
                model=self.provider.model
            )
        elif self.request.provider_config is not None:
            # SDK mode: use the original request config
            provider_config = self.request.provider_config
        else:
            # Fallback
            provider_config = ProviderConfig(provider="anthropic", model="claude-sonnet-4-20250514")

        return Agent(
            id=self.id,
            repo_id=self.repo_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
            provider_config=provider_config,
            scan_tier=self.scan_tier,
            time_budget_seconds=self.time_budget_seconds,
            custom_prompt=self.custom_prompt,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            files_analyzed=len(self.files_examined),
            findings_count=len(self.findings),
            error_message=self.error_message
        )

    def get_state_snapshot(self) -> "AgentStateSnapshot":
        """Create a complete snapshot of agent state for persistence."""
        from models.observability import AgentStateSnapshot

        # Get flow data
        flow = flow_service.get_flow(self.id)
        flow_nodes = [n.to_dict() for n in flow.nodes] if flow else []
        flow_edges = [e.to_dict() for e in flow.edges] if flow else []
        current_flow_node_id = flow.current_node_id if flow else None

        # Get token usage
        usage = observability_service.get_token_usage(self.id)

        # Build provider_config dict - handle SDK mode where provider is None
        if self.provider is not None:
            provider_config_dict = {
                "provider": self.provider.provider_type,
                "model": self.provider.model,
            }
        elif self.request.provider_config is not None:
            provider_config_dict = {
                "provider": self.request.provider_config.provider.value if hasattr(self.request.provider_config.provider, 'value') else str(self.request.provider_config.provider),
                "model": self.request.provider_config.model,
            }
        else:
            provider_config_dict = {"provider": "anthropic", "model": "claude-sonnet-4-20250514"}

        return AgentStateSnapshot(
            id=str(uuid.uuid4())[:12],
            agent_id=self.id,
            repo_id=self.repo_id,
            repo_path=self.repo_path,
            agent_type=self.agent_type.value,
            provider_config=provider_config_dict,
            custom_prompt=self.custom_prompt,
            status=self.status.value,
            files_analyzed=len(self.files_examined),
            total_files=0,  # Not tracked currently
            current_file=None,
            findings=[f.model_dump(mode='json') for f in self.findings],
            conversation_history=self.messages.copy(),
            llm_interactions=[i.model_dump(mode="json", exclude_none=True) for i in observability_service.get_interactions(self.id)],
            tool_details=[d.model_dump(mode="json", exclude_none=True) for d in observability_service.get_tool_details(self.id)],
            flow_nodes=flow_nodes,
            flow_edges=flow_edges,
            current_flow_node_id=current_flow_node_id,
            investigation_context={
                "files_examined": list(self.files_examined),
                "thoughts_count": len(self.thoughts),
            },
            total_prompt_tokens=usage.prompt_tokens,
            total_completion_tokens=usage.completion_tokens,
            total_api_calls=observability_service.get_stats(self.id).get("response_count", 0),
            last_error=self.error_message,
        )

    def restore_from_snapshot(self, snapshot: "AgentStateSnapshot") -> None:
        """Restore agent state from a snapshot."""
        from models.observability import AgentStateSnapshot, LLMInteraction, ToolDetail

        # Restore conversation history
        self.messages = snapshot.conversation_history.copy()

        # Restore files examined
        if snapshot.investigation_context:
            self.files_examined = set(snapshot.investigation_context.get("files_examined", []))

        # Restore findings
        for finding_data in snapshot.findings:
            try:
                finding = Finding(**finding_data)
                self.findings.append(finding)
            except Exception as e:
                print(f"[{self.id}] Failed to restore finding: {e}")

        # Restore LLM interactions to observability service
        if snapshot.llm_interactions:
            for interaction_data in snapshot.llm_interactions:
                try:
                    interaction = LLMInteraction(**interaction_data)
                    observability_service._interactions[self.id].append(interaction)
                except Exception as e:
                    print(f"[{self.id}] Failed to restore LLM interaction: {e}")

        # Restore tool details to observability service
        if snapshot.tool_details:
            for tool_data in snapshot.tool_details:
                try:
                    tool_detail = ToolDetail(**tool_data)
                    observability_service._tool_details[self.id].append(tool_detail)
                except Exception as e:
                    print(f"[{self.id}] Failed to restore tool detail: {e}")

        # Restore flow visualization
        if snapshot.flow_nodes or snapshot.flow_edges:
            flow_service.restore_flow(
                self.id,
                nodes=snapshot.flow_nodes or [],
                edges=snapshot.flow_edges or [],
                current_node_id=snapshot.current_flow_node_id,
            )

        self._log(f"Restored from snapshot: {len(self.files_examined)} files, {len(self.findings)} findings, {len(snapshot.llm_interactions or [])} interactions")

    def _extract_functions_from_code(self, code: str) -> list[dict]:
        """Extract function definitions from code.

        Supports: Python, JavaScript, TypeScript (arrow functions, methods, decorators)
        """
        if not code or not isinstance(code, str):
            return []

        functions = []
        lines = code.split('\n')

        # Python pattern
        python_pattern = r'^\s*(?:async\s+)?def\s+(\w+)\s*\('

        # JavaScript/TypeScript patterns
        js_function_pattern = r'^\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\('
        arrow_pattern = r'^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>'
        method_pattern = r'^\s*(?:public|private|protected|static)?\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*[:{]'
        decorator_pattern = r'^\s*@\w+(?:\([^)]*\))?$'

        i = 0
        while i < len(lines):
            line = lines[i]
            line_num = i + 1

            # Check for decorated method (TypeScript)
            if re.match(decorator_pattern, line) and i + 1 < len(lines):
                next_line = lines[i + 1]
                method_match = re.match(method_pattern, next_line)
                if method_match:
                    functions.append({
                        "name": method_match.group(1),
                        "signature": f"{line.strip()} {next_line.strip()}",
                        "line_number": line_num,
                        "language": "typescript"
                    })
                    i += 2
                    continue

            # Try Python pattern
            match = re.match(python_pattern, line)
            if match:
                functions.append({
                    "name": match.group(1),
                    "signature": match.group(0).strip(),
                    "line_number": line_num,
                    "language": "python"
                })
                i += 1
                continue

            # Try JS function pattern
            match = re.match(js_function_pattern, line)
            if match:
                functions.append({
                    "name": match.group(1),
                    "signature": match.group(0).strip(),
                    "line_number": line_num,
                    "language": "javascript"
                })
                i += 1
                continue

            # Try arrow function pattern
            match = re.match(arrow_pattern, line)
            if match:
                functions.append({
                    "name": match.group(1),
                    "signature": match.group(0).strip(),
                    "line_number": line_num,
                    "language": "typescript"
                })
                i += 1
                continue

            # Try method pattern
            match = re.match(method_pattern, line)
            if match:
                functions.append({
                    "name": match.group(1),
                    "signature": match.group(0).strip(),
                    "line_number": line_num,
                    "language": "typescript"
                })
                i += 1
                continue

            i += 1

        return functions

    def _extract_calls_from_analysis(self, analysis: str) -> list[dict]:
        """Extract function calls from LLM analysis.

        Returns list of dicts with: target_function, call_type
        """
        if not analysis or not isinstance(analysis, str):
            return []

        calls = []

        # Look for patterns like "calls functionName()" or "invokes X.Y()"
        pattern = r'(?:calls?|invokes?|executes?)\s+([a-zA-Z_][\w\.]*)\s*\('
        for match in re.finditer(pattern, analysis, re.IGNORECASE):
            calls.append({
                "target_function": match.group(1),
                "call_type": "internal"
            })

        return calls
