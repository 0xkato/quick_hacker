"""
Deep Audit Agent - Uses 3-layer prompt architecture with AUDIT_JSONL logging.

This agent implements:
- Continuous stateful review across turns
- AUDIT_JSONL logging contract
- Sink-first harvesting discipline
- Depth/coverage metrics
- Skeptic pass validation

Layer 1: Hard Rules (safety + output contract)
Layer 2: Workflow Engine (state machine + metrics)
Layer 3: Run Config (per-audit scope)
"""

import asyncio
import json
import hashlib
from datetime import datetime
from typing import Callable, Optional
from dataclasses import dataclass, field

from models.schemas import (
    Agent,
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    Finding,
    FindingCreate,
    Severity,
    WSMessage,
    WSMessageType,
)
from agents.tools import ToolExecutor, AGENT_TOOLS, ToolResult
from providers import get_provider
from prompts import (
    get_hard_rules_prompt,
    get_developer_prompt,
    get_classification_gate_prompt,
)
from services.attack_surface_service import attack_surface_service
from services.flow_service import flow_service
from services.project_service import project_service
from services.coverage_tracker import CoverageTracker, PathStatus
from agents.depth_enforcement import (
    DepthEnforcementConfig,
    validate_completion_request,
)


@dataclass
class AuditCandidate:
    """A candidate vulnerability under investigation."""
    id: str
    vuln_class: str
    component: str
    file_path: str
    line_start: int
    line_end: int
    sink_symbol: str
    status: str = "pending"  # pending, investigating, validated, hardening, cleared, deferred
    trace_depth: int = 0
    validators_reviewed: list = field(default_factory=list)
    variants_checked: int = 0
    evidence: dict = field(default_factory=dict)


@dataclass
class AuditState:
    """Continuous state maintained across turns."""
    run_id: str
    seq: int = 0
    iteration: int = 0
    budgets: dict = field(default_factory=dict)
    candidate_backlog: dict = field(default_factory=dict)  # id -> AuditCandidate
    coverage_matrix: dict = field(default_factory=dict)  # component -> metrics
    open_questions: list = field(default_factory=list)
    repo_map: dict = field(default_factory=dict)
    evidence_by_seq: dict = field(default_factory=dict)  # audit seq -> evidence item (wire)
    evidence_seq_order: list[int] = field(default_factory=list)
    audit_log: list = field(default_factory=list)  # AUDIT_JSONL events

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq


def generate_candidate_id(vuln_class: str, file_path: str, line_start: int, line_end: int, sink: str) -> str:
    """Generate deterministic candidate ID."""
    hash_input = f"{vuln_class}|{file_path}|{line_start}-{line_end}|{sink}"
    return f"CAND-{hashlib.sha256(hash_input.encode()).hexdigest()[:8]}"


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stable_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _lang_from_path(path: str) -> str:
    suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return {
        "py": "py",
        "ts": "ts",
        "tsx": "tsx",
        "js": "js",
        "jsx": "jsx",
        "json": "json",
        "yml": "yaml",
        "yaml": "yaml",
        "md": "md",
    }.get(suffix, suffix[:16] if suffix else "")


class DeepAuditAgent:
    """
    Deep security audit agent with 3-layer prompt architecture.

    Uses AUDIT_JSONL logging for machine-readable audit trail.
    Implements sink-first harvesting and skeptic pass validation.
    """

    def __init__(
        self,
        request: AgentCreateRequest,
        repo_path: str,
        on_message: Optional[Callable[[WSMessage], None]] = None,
    ):
        self.id = request.repo_id[:8] + "-" + str(hash(str(request)))[-6:]
        self.repo_id = request.repo_id
        self.repo_path = repo_path
        self.name = request.name or f"deep_audit_{self.id}"
        self.agent_type = AgentType.DEEP_AUDIT
        self.status = AgentStatus.PENDING
        self.provider_config = request.provider_config
        self.custom_prompt = request.custom_prompt
        self.target_files = request.target_files
        self.focus_areas = request.focus_areas

        # Timestamps
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.files_analyzed = 0
        self.error_message: Optional[str] = None

        # Callbacks
        self.on_message = on_message

        # State
        self.state: Optional[AuditState] = None
        self.findings: list[Finding] = []
        self.files_examined: set[str] = set()

        # Control
        self._cancelled = False
        self._paused = asyncio.Event()
        self._paused.set()

        # Provider
        self.provider = get_provider(self.provider_config)
        self.tool_executor = ToolExecutor(self.repo_path)

        # Coverage tracking
        self.coverage_tracker = CoverageTracker(self.id)
        self.depth_config = DepthEnforcementConfig()
        self._completion_approved = False

        # Config
        self.max_iterations = 50
        self.max_tool_calls_per_iteration = 5

        # Rate limiting / throttling
        self.iteration_delay = 2.0  # Seconds to wait between iterations
        self.min_delay = 1.0  # Minimum delay
        self.max_delay = 60.0  # Maximum delay for backoff
        self.current_backoff = 0.0  # Current backoff (resets on success)
        self.backoff_multiplier = 2.0  # Exponential backoff factor

    def _log(self, message: str, level: str = "info"):
        """Log message to WebSocket."""
        self._broadcast(WSMessageType.LOG, {"message": message, "level": level})

    def _broadcast(self, msg_type: WSMessageType, data: dict):
        """Broadcast message to connected clients."""
        if self.on_message:
            message = WSMessage(
                type=msg_type,
                agent_id=self.id,
                data=data,
                timestamp=datetime.utcnow().isoformat(),
            )
            self.on_message(message)

    def _broadcast_flow_update(self) -> None:
        """Send flow update to WebSocket (for the investigation diagram)."""
        flow = flow_service.get_flow(self.id)
        if flow:
            self._broadcast(WSMessageType.PROGRESS, {"type": "flow_update", "flow": flow.to_dict()})

    async def _build_attack_surface_tree(self) -> None:
        """Run an initial scan + conservative triage and render candidate branches in the flow."""
        threat_model = "AB"
        try:
            project = await project_service.get_project(self.repo_id)
            if project and getattr(project, "threat_model", None):
                threat_model = project.threat_model
        except Exception:
            threat_model = "AB"

        scan_node = flow_service.add_node(
            self.id,
            "scan",
            f"Attack Surface Scan ({threat_model})",
            {"threat_model": threat_model},
        )
        flow_service.update_node_status(self.id, scan_node.id, "running")
        self._broadcast_flow_update()

        try:
            candidates = attack_surface_service.scan_candidates(repo_path=self.repo_path)
            triaged = await attack_surface_service.triage(
                agent_id=self.id,
                repo_path=self.repo_path,
                threat_model=threat_model,  # type: ignore[arg-type]
                provider=self.provider,
                candidates=candidates,
            )

            flow_service.update_node_data(
                self.id,
                scan_node.id,
                {
                    "candidates_found": len(candidates),
                    "investigate_count": len(triaged),
                },
            )
            flow_service.update_node_status(self.id, scan_node.id, "completed")

            for item in triaged[:20]:
                c = item.candidate
                node_type = "entry_point" if c.kind == "entry_point" else "dangerous_sink"
                exposure = item.exposure if item.exposure != "unknown" else ""
                label = f"[{exposure}] {c.label}" if exposure else c.label

                flow_service.add_node(
                    self.id,
                    node_type,  # type: ignore[arg-type]
                    label,
                    data={
                        "attack_surface_candidate_id": c.id,
                        "kind": c.kind,
                        "file_path": c.file_path,
                        "line_number": c.line_number,
                        "metadata": c.metadata,
                        "threat_model": threat_model,
                        "exposure": item.exposure,
                    },
                    parent_id=scan_node.id,
                    edge_label="candidate",
                    llm_reasoning=item.reasoning,
                    code_context=c.code_context,
                    confidence_score=item.confidence_score,
                    set_current=False,
                )

            self._broadcast_flow_update()
        except Exception as e:
            flow_service.update_node_data(self.id, scan_node.id, {"error": str(e)})
            flow_service.update_node_status(self.id, scan_node.id, "failed")
            self._broadcast_flow_update()

    def _log_audit_event(self, event_type: str, data: dict) -> Optional[dict]:
        """Log event to AUDIT_JSONL format."""
        if not self.state:
            return None

        event = {
            "type": event_type,
            "run_id": self.state.run_id,
            "ts": datetime.utcnow().isoformat(),
            "seq": self.state.next_seq(),
            "data": data,
        }
        self.state.audit_log.append(event)

        # Broadcast as progress update
        self._broadcast(WSMessageType.PROGRESS, {
            "audit_event": event,
            "candidates_count": len(self.state.candidate_backlog),
            "coverage": self.state.coverage_matrix,
        })
        return event

    def _run_config_wire(self) -> dict:
        return {
            "v": 1,
            "run_id": self.state.run_id if self.state else "unknown",
            "repo_id": self.repo_id,
            "repo_root": self.repo_path,
            "focus_areas": self.focus_areas or [],
            "target_files": self.target_files or [],
            "constraints": {
                "non_destructive_only": True,
                "network_allowed": False,
                "audit_jail": "./audit/",
            },
        }

    async def run(self):
        """Execute the deep audit."""
        self.status = AgentStatus.RUNNING
        self._broadcast(WSMessageType.AGENT_STATUS, {"status": "running"})

        # Initialize investigation flow (diagram)
        flow_service.initialize_flow(self.id)
        start_node = flow_service.add_node(
            self.id,
            "user_input",
            "Start Deep Audit",
            {"agent_type": self.agent_type.value},
        )
        flow_service.update_node_status(self.id, start_node.id, "completed")
        self._broadcast_flow_update()
        await self._build_attack_surface_tree()

        # Initialize state
        import uuid
        self.state = AuditState(
            run_id=str(uuid.uuid4())[:8],
            budgets={
                "tc_rem": self.max_iterations * self.max_tool_calls_per_iteration,
                "lr_max": 180,
                "sr_max": 40,
                "ev_max": 3,
                "tok_max": int(getattr(self.provider, "max_tokens", 3500)),
            },
        )

        # Log context
        self._log_audit_event("context", {
            "repo_id": self.repo_id,
            "repo_path": self.repo_path,
            "focus_areas": self.focus_areas or [],
            "target_files": self.target_files or [],
        })

        try:
            await self._audit_loop()
            self.status = AgentStatus.COMPLETED
            flow_service.add_node(
                self.id,
                "analysis",
                "Audit Complete",
                {"findings_count": len(self.findings)},
            )
            self._broadcast_flow_update()
        except asyncio.CancelledError:
            self.status = AgentStatus.CANCELLED
        except Exception as e:
            self.status = AgentStatus.FAILED
            self._log(f"Audit failed: {e}", "error")
            self._log_audit_event("error", {"message": str(e)})
        finally:
            self._broadcast(WSMessageType.AGENT_STATUS, {"status": self.status.value})

        return self.findings

    async def _audit_loop(self):
        """Main audit loop implementing the workflow engine."""
        # Get threat model from project (default to AB)
        threat_model = "AB"
        try:
            project = await project_service.get_project(self.repo_id)
            if project and getattr(project, "threat_model", None):
                threat_model = project.threat_model
        except Exception:
            threat_model = "AB"

        # Build system prompt with classification gate
        system_prompt = get_hard_rules_prompt() + "\n\n" + get_developer_prompt()

        # Inject classification gate prompt
        classification_prompt = get_classification_gate_prompt(threat_model)
        system_prompt += "\n\n" + classification_prompt

        self._log_audit_event("plan", {
            "action": "initialize_audit",
            "layers": ["hard_rules", "workflow_engine", "run_config_wire"],
        })

        while self.state and self.state.iteration < self.max_iterations and not self._cancelled:
            self.state.iteration += 1

            # Check if paused
            await self._paused.wait()
            if self._cancelled:
                break

            self._log(f"Audit iteration {self.state.iteration}")

            # Get LLM response
            try:
                phase = self._derive_phase()
                objective = self._derive_objective(phase)
                run_state_json = self._build_run_state_json(phase, objective)
                evidence_pack = self._build_evidence_pack()
                run_state_json["ptr"]["a_tail"] = [
                    item.get("src_seq")
                    for item in evidence_pack.get("items", [])
                    if isinstance(item.get("src_seq"), int)
                ][:6]
                user_prompt = self._format_user_prompt(run_state_json, evidence_pack, objective)

                response = await self._call_llm_with_tools(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
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
                    self._log_audit_event("error", {"message": f"LLM call failed: {e}"})
                    await asyncio.sleep(2)
                continue

            # Process tool calls
            if response.get("tool_calls"):
                await self._process_tool_calls(response["tool_calls"])
            else:
                content = response.get("content", "")

                # Check for completion signals
                if "FINAL OUTCOME" in content or "Case A:" in content or "Case B:" in content or "Case C:" in content:
                    self._log("Audit complete - final outcome reached")
                    self._log_audit_event("note", {"message": "Final outcome reached"})
                    break

                # Parse AUDIT_JSONL from response
                self._parse_audit_jsonl(content)

            # Update coverage
            self._update_coverage_metrics()

            # Throttle: Wait before next iteration to avoid rate limits
            await asyncio.sleep(self.iteration_delay)

        # Final coverage log
        self._log_audit_event("coverage", {
            "final": True,
            "matrix": self.state.coverage_matrix,
            "candidates_resolved": len([c for c in self.state.candidate_backlog.values() if c.status not in ["pending", "investigating"]]),
            "candidates_total": len(self.state.candidate_backlog),
        })

    def _parse_audit_jsonl(self, content: str):
        """Parse AUDIT_JSONL events from LLM response."""
        # Look for AUDIT_JSONL code block
        import re
        jsonl_match = re.search(r'```(?:jsonl|json)?\s*\n(.*?)\n```', content, re.DOTALL)
        if jsonl_match:
            jsonl_block = jsonl_match.group(1)
            for line in jsonl_block.strip().split('\n'):
                try:
                    event = json.loads(line)
                    if event.get("type") in ["candidate", "decision", "validated", "hardening", "coverage"]:
                        self._process_audit_event(event)
                except json.JSONDecodeError:
                    pass

    def _process_audit_event(self, event: dict):
        """Process a parsed AUDIT_JSONL event."""
        event_type = event.get("type")
        data = event.get("data", {})

        if event_type == "candidate":
            # New candidate
            cand_id = data.get("id", generate_candidate_id(
                data.get("class", "unknown"),
                data.get("file", "unknown"),
                data.get("lines", "0-0").split("-")[0],
                data.get("lines", "0-0").split("-")[-1],
                data.get("sink", "unknown")
            ))
            self.state.candidate_backlog[cand_id] = AuditCandidate(
                id=cand_id,
                vuln_class=data.get("class", "unknown"),
                component=data.get("risk_cluster") or data.get("component") or "unknown",
                file_path=data.get("file", "unknown"),
                line_start=int(data.get("lines", "0-0").split("-")[0]),
                line_end=int(data.get("lines", "0-0").split("-")[-1]),
                sink_symbol=data.get("sink", "unknown"),
            )
            self._log_audit_event("candidate", data)

        elif event_type == "decision":
            cand_id = data.get("id")
            if cand_id and cand_id in self.state.candidate_backlog:
                self.state.candidate_backlog[cand_id].status = data.get("outcome", "unknown")
            self._log_audit_event("decision", data)

        elif event_type == "validated":
            # Create finding from validated event
            self._create_finding_from_validated(data)
            self._log_audit_event("validated", data)

        elif event_type == "coverage":
            # Update coverage matrix
            component = data.get("component", "global")
            self.state.coverage_matrix[component] = data
            self._log_audit_event("coverage", data)

    def _create_finding_from_validated(self, data: dict):
        """Create a Finding from a validated AUDIT_JSONL event."""
        where = data.get("where", {})

        finding = Finding(
            id=data.get("vuln_id", f"VULN-{len(self.findings)+1}"),
            agent_id=self.id,
            repo_id=self.repo_id,
            severity=self._map_cvss_to_severity(data.get("cvss", "0.0")),
            title=data.get("class", "Vulnerability"),
            description=data.get("impact", ""),
            file_path=where.get("file", "unknown"),
            line_start=where.get("line_start", 0),
            line_end=where.get("line_end"),
            code_snippet=data.get("evidence_snippet", ""),
            vulnerability_type=data.get("cwe", ""),
            attack_scenario=json.dumps(data.get("source_to_sink_path", [])),
            recommended_fix=data.get("fix_plan", ""),
            confidence=float(data.get("confidence", 0.8)),
            created_at=datetime.utcnow().isoformat(),
            metadata={
                "validators": data.get("validators", []),
                "preconditions": data.get("preconditions", ""),
                "cvss": data.get("cvss", ""),
                "cwe": data.get("cwe", ""),
            }
        )

        self.findings.append(finding)
        self._broadcast(WSMessageType.FINDING, finding.model_dump())

    def _map_cvss_to_severity(self, cvss: str) -> Severity:
        """Map CVSS score to severity level."""
        try:
            score = float(cvss)
            if score >= 9.0:
                return Severity.CRITICAL
            elif score >= 7.0:
                return Severity.HIGH
            elif score >= 4.0:
                return Severity.MEDIUM
            elif score >= 0.1:
                return Severity.LOW
        except (ValueError, TypeError):
            pass
        return Severity.INFO

    def _update_coverage_metrics(self):
        """Update coverage metrics based on current state."""
        if not self.state:
            return

        # Calculate overall coverage
        total_candidates = len(self.state.candidate_backlog)
        resolved = len([c for c in self.state.candidate_backlog.values()
                       if c.status not in ["pending", "investigating"]])

        self.state.coverage_matrix["_global"] = {
            "candidates_total": total_candidates,
            "candidates_resolved": resolved,
            "resolution_rate": resolved / total_candidates if total_candidates > 0 else 0,
            "files_examined": len(self.files_examined),
        }

    def _format_tools_for_provider(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["parameters"],
                },
            }
            for tool in AGENT_TOOLS
        ]

    async def _call_llm_with_tools(self, system_prompt: str, user_prompt: str) -> dict:
        """Call LLM with tool definitions (stateless turn)."""
        response = await self.provider.chat_with_tools(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            tools=self._format_tools_for_provider(),
        )
        return response

    def _derive_phase(self) -> str:
        if not self.state or not self.state.candidate_backlog:
            return "index" if (self.state and self.state.iteration <= 2) else "harvest"

        wire_statuses = [self._wire_candidate_status(c.status) for c in self.state.candidate_backlog.values()]
        if "def" in wire_statuses:
            return "trace"
        if "open" in wire_statuses:
            return "trace"
        return "coverage"

    def _derive_objective(self, phase: str) -> str:
        if not self.state:
            return "Initialize audit state and begin investigation."

        top_candidates = self._select_top_candidates(limit=3)
        if top_candidates:
            ids = ", ".join(c.id for c in top_candidates)
            return (
                f"Advance phase={phase}. Close or downgrade top candidates ({ids}) by tracing attacker-controlled "
                f"sources to sinks, enumerating validators, and scanning for close variants. Request minimal slices."
            )

        return f"Advance phase={phase}. Harvest missing sink families and create candidates before deep tracing."

    def _wire_candidate_status(self, status: str) -> str:
        normalized = (status or "").lower()
        if normalized in {"validated", "val"}:
            return "val"
        if normalized in {"hardening", "hard"}:
            return "hard"
        if normalized in {"cleared", "clr"}:
            return "clr"
        if normalized in {"deferred", "def"}:
            return "def"
        return "open"

    def _candidate_counts(self) -> dict:
        if not self.state:
            return {"open": 0, "val": 0, "hard": 0, "clr": 0, "def": 0}

        counts = {"open": 0, "val": 0, "hard": 0, "clr": 0, "def": 0}
        for candidate in self.state.candidate_backlog.values():
            counts[self._wire_candidate_status(candidate.status)] += 1
        return counts

    def _select_top_candidates(self, limit: int = 10) -> list[AuditCandidate]:
        if not self.state:
            return []

        status_weight = {"open": 0, "def": 1, "val": 2, "hard": 3, "clr": 4}

        def candidate_sort_key(candidate: AuditCandidate) -> tuple[int, str]:
            wire_status = self._wire_candidate_status(candidate.status)
            return (status_weight.get(wire_status, 99), candidate.id)

        candidates_sorted = sorted(self.state.candidate_backlog.values(), key=candidate_sort_key)
        return candidates_sorted[:limit]

    def _build_run_state_json(self, phase: str, objective: str) -> dict:
        budgets = self.state.budgets if self.state else {}
        max_lines = int(budgets.get("lr_max", 180)) if budgets else 180
        top_candidates = self._select_top_candidates(limit=10)

        top_cards = []
        for index, candidate in enumerate(top_candidates):
            wire_status = self._wire_candidate_status(candidate.status)
            bounded_end = candidate.line_end
            if isinstance(candidate.line_start, int) and isinstance(candidate.line_end, int):
                bounded_end = min(candidate.line_end, candidate.line_start + max_lines - 1)
            need = f"read_file {candidate.file_path} {candidate.line_start}-{bounded_end}"
            where = f"{candidate.file_path}:{candidate.line_start}-{candidate.line_end}"
            top_cards.append({
                "id": candidate.id,
                "cls": candidate.vuln_class[:64],
                "comp": (candidate.component or "unknown")[:80],
                "st": wire_status,
                "pri": index,
                "need": need[:240],
                "where": where[:120],
            })

        open_questions = []
        for index, candidate in enumerate(top_candidates[:12]):
            wire_status = self._wire_candidate_status(candidate.status)
            if wire_status not in {"open", "def"}:
                continue
            open_questions.append({
                "k": "need_slice",
                "txt": f"Need code slice for {candidate.id} at {candidate.file_path}:{candidate.line_start}-{candidate.line_end}",
                "pri": index,
                "ref": candidate.id,
            })

        return {
            "v": 1,
            "run": self.state.run_id,
            "it": self.state.iteration,
            "ph": phase,
            "obj": objective[:600],
            "bud": {
                "tc_rem": int(budgets.get("tc_rem", 0)),
                "lr_max": int(budgets.get("lr_max", 180)),
                "sr_max": int(budgets.get("sr_max", 40)),
                "ev_max": int(budgets.get("ev_max", 3)),
                "tok_max": int(budgets.get("tok_max", 3500)),
            },
            "cand": {
                "cnt": self._candidate_counts(),
                "top": top_cards,
            },
            "cov": self._build_coverage_summary(),
            "q": open_questions,
            "flg": {"dflt": 1, "net": 0, "jail": 1},
            "ptr": {
                "a_seq": int(self.state.seq),
                "a_tail": self._evidence_tail(limit=min(6, int(budgets.get("ev_max", 3)))),
            },
        }

    def _evidence_tail(self, limit: int = 6) -> list[int]:
        if not self.state:
            return []
        return list(self.state.evidence_seq_order[-limit:])

    def _build_coverage_summary(self) -> list[dict]:
        if not self.state:
            return []

        def parse_pct(value: object) -> int:
            if isinstance(value, (int, float)):
                return max(0, min(100, int(value)))
            if isinstance(value, str):
                cleaned = value.strip().rstrip("%")
                try:
                    return max(0, min(100, int(float(cleaned))))
                except ValueError:
                    return 0
            return 0

        rows: list[dict] = []
        for component, data in self.state.coverage_matrix.items():
            if component == "_global" or not isinstance(data, dict):
                continue

            metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
            sinks_pct = metrics.get("sinks_coverage_pct") or data.get("sinks_coverage_pct") or 0
            entry_pct = metrics.get("entry_coverage_pct") or data.get("entry_coverage_pct") or 0
            missing = data.get("miss") or data.get("missing") or []
            status = data.get("status") if data.get("status") in {"ok", "insufficient_depth"} else None

            row = {
                "c": str(component)[:80],
                "p": str(data.get("class") or data.get("profile") or "unknown")[:80],
                "s": parse_pct(sinks_pct),
                "e": parse_pct(entry_pct),
                "miss": [str(m)[:60] for m in (missing if isinstance(missing, list) else [])][:8],
            }
            if status:
                row["st"] = status
            rows.append(row)

        return rows[:12]

    def _build_evidence_pack(self) -> dict:
        budgets = self.state.budgets if self.state else {}
        max_items = int(budgets.get("ev_max", 3)) if budgets else 3
        src_seqs = self._evidence_tail(limit=max_items)

        items = []
        for src_seq in src_seqs:
            evidence = self.state.evidence_by_seq.get(src_seq) if self.state else None
            if evidence:
                items.append(evidence)

        return {"v": 1, "items": items}

    def _format_user_prompt(self, run_state_json: dict, evidence_pack: dict, objective: str) -> str:
        return (
            "STATEFUL AUDIT TURN (stateless prompt; rely only on the blocks below)\n\n"
            "<RUN_CONFIG_JSON>\n"
            f"{json.dumps(self._run_config_wire(), ensure_ascii=False)}\n"
            "</RUN_CONFIG_JSON>\n\n"
            "<RUN_STATE_JSON>\n"
            f"{json.dumps(run_state_json, ensure_ascii=False)}\n"
            "</RUN_STATE_JSON>\n\n"
            "<EVIDENCE_PACK>\n"
            f"{json.dumps(evidence_pack, ensure_ascii=False)}\n"
            "</EVIDENCE_PACK>\n\n"
            "<OBJECTIVE>\n"
            f"{objective}\n"
            "</OBJECTIVE>\n"
        )

    async def _process_tool_calls(self, tool_calls: list[dict]):
        """Process tool calls from LLM."""
        if not self.state:
            return

        calls_remaining = int(self.state.budgets.get("tc_rem", 0))
        allowed = min(self.max_tool_calls_per_iteration, calls_remaining, len(tool_calls))

        for call in tool_calls[:allowed]:
            tool_name = call.get("name") or call.get("function", {}).get("name")
            args_str = call.get("arguments") or call.get("function", {}).get("arguments", "{}")

            try:
                arguments = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                arguments = {}

            tool_name = str(tool_name or "")

            # Handle trace_path_verdict specially (coverage tracking)
            if tool_name == "trace_path_verdict":
                from agents.tools import handle_trace_path_verdict

                def broadcast_coverage(event_type: str, data: dict):
                    self._broadcast(WSMessageType.PROGRESS, {"type": event_type, **data})

                result_msg = handle_trace_path_verdict(
                    arguments,
                    self.coverage_tracker,
                    broadcast_coverage
                )

                # Log the verdict
                self._log_audit_event("path_verdict", {
                    "entry": f"{arguments.get('entry_point_file')}:{arguments.get('entry_point_line')}",
                    "sink": f"{arguments.get('sink_file')}:{arguments.get('sink_line')}",
                    "verdict": arguments.get("verdict"),
                    "reasoning": arguments.get("reasoning")
                })

                # Update budgets
                self.state.budgets["tc_rem"] = max(0, int(self.state.budgets.get("tc_rem", 0)) - 1)
                continue  # Skip normal tool execution

            # Handle complete_audit with validation
            if tool_name == "complete_audit":
                # Count pending investigations (paths discovered but not traced)
                unexplored = self.coverage_tracker.get_unexplored_paths()
                pending_count = len(unexplored)

                # Validate completion request
                validation_result = validate_completion_request(
                    coverage_tracker=self.coverage_tracker,
                    config=self.depth_config,
                    files_examined=self.files_examined,
                    iteration_count=self.state.iteration,
                    pending_investigations=pending_count
                )

                if validation_result.can_complete:
                    self._completion_approved = True
                    self._log_audit_event("completion_approved", {
                        "outcome": arguments.get("outcome"),
                        "summary": arguments.get("summary"),
                        "coverage_stats": validation_result.coverage_stats
                    })
                    self._log(f"Audit completion approved: {arguments.get('summary')}")
                else:
                    # Rejection - tell LLM what's missing
                    self._log_audit_event("completion_rejected", {
                        "reason": validation_result.rejection_reason,
                        "guidance": validation_result.guidance,
                        "coverage_stats": validation_result.coverage_stats
                    })
                    self._log(f"Completion rejected: {validation_result.rejection_reason}", "warning")

                    # Add rejection to evidence so LLM sees it
                    rejection_event = {
                        "id": f"REJECT-{self.state.seq}",
                        "k": "rejection",
                        "reason": validation_result.rejection_reason,
                        "guidance": validation_result.guidance,
                    }
                    self._store_evidence(self.state.seq, rejection_event)

                self.state.budgets["tc_rem"] = max(0, int(self.state.budgets.get("tc_rem", 0)) - 1)
                continue  # Skip normal tool execution

            arguments = self._apply_tool_budgets(tool_name, arguments)

            # Log tool call
            self._log_audit_event("tool_call", {
                "tool": tool_name,
                "args": arguments,
            })

            # Execute tool
            result = await self.tool_executor.execute(tool_name, arguments)
            self.state.budgets["tc_rem"] = max(0, int(self.state.budgets.get("tc_rem", 0)) - 1)

            # Track files examined
            if tool_name == "read_file" and result.success and "path" in arguments:
                self.files_examined.add(str(arguments["path"]))

            # Log tool result
            result_payload = result.data if result.success else {"error": result.error}
            result_hash = _sha256_hex(_stable_json(result_payload))
            tool_result_event = self._log_audit_event("tool_result", {
                "tool": tool_name,
                "success": result.success,
                "result_size": len(str(result_payload)) if result_payload else 0,
                "h": f"sha256:{result_hash}",
            })

            if tool_result_event:
                evidence_item = self._tool_result_to_evidence(
                    tool_name=tool_name,
                    arguments=arguments,
                    result=result,
                    src_seq=int(tool_result_event["seq"]),
                    result_hash=result_hash,
                )
                if evidence_item:
                    self._store_evidence(int(tool_result_event["seq"]), evidence_item)

    def _apply_tool_budgets(self, tool_name: str, arguments: dict) -> dict:
        budgets = self.state.budgets if self.state else {}
        max_lines = int(budgets.get("lr_max", 180)) if budgets else 180
        max_results = int(budgets.get("sr_max", 40)) if budgets else 40

        clamped = dict(arguments or {})

        if tool_name == "read_file":
            start_line = clamped.get("start_line")
            end_line = clamped.get("end_line")

            if start_line is None and end_line is None:
                clamped["start_line"] = 1
                clamped["end_line"] = max_lines
                return clamped

            if start_line is None and isinstance(end_line, int):
                clamped["start_line"] = max(1, end_line - max_lines + 1)
                return clamped

            if end_line is None and isinstance(start_line, int):
                clamped["end_line"] = start_line + max_lines - 1
                return clamped

            if isinstance(start_line, int) and isinstance(end_line, int):
                if end_line - start_line + 1 > max_lines:
                    clamped["end_line"] = start_line + max_lines - 1
                return clamped

        if tool_name == "search_code":
            requested = clamped.get("max_results")
            if isinstance(requested, int):
                clamped["max_results"] = max(1, min(requested, max_results))
            else:
                clamped["max_results"] = max(1, min(50, max_results))
            return clamped

        return clamped

    def _store_evidence(self, src_seq: int, evidence_item: dict):
        if not self.state:
            return

        self.state.evidence_by_seq[src_seq] = evidence_item
        self.state.evidence_seq_order.append(src_seq)

        while len(self.state.evidence_seq_order) > 200:
            old_seq = self.state.evidence_seq_order.pop(0)
            self.state.evidence_by_seq.pop(old_seq, None)

    def _tool_result_to_evidence(
        self,
        tool_name: str,
        arguments: dict,
        result: ToolResult,
        src_seq: int,
        result_hash: str,
    ) -> Optional[dict]:
        if tool_name == "read_file":
            path = str(arguments.get("path", ""))[:220]
            start_line = int(arguments.get("start_line") or 1)
            end_line = int(arguments.get("end_line") or start_line)
            line_range = f"{start_line}-{end_line}"
            content = result.data if result.success and isinstance(result.data, str) else (result.error or "")
            evidence_id = _sha256_hex(f"{src_seq}|fs|{path}|{line_range}|")[:8]
            return {
                "id": f"EVID-{evidence_id}",
                "k": "fs",
                "src_seq": src_seq,
                "p": path,
                "r": line_range,
                "lang": _lang_from_path(path),
                "h": f"sha256:{result_hash}",
                "t": content[:35000],
                "tool": tool_name,
            }

        if tool_name in {"search_code", "find_definition", "find_usages"}:
            query_value = arguments.get("pattern") if tool_name == "search_code" else arguments.get("name")
            query = str(query_value or tool_name)[:200]
            raw_matches = (result.data or {}).get("matches", []) if result.success and isinstance(result.data, dict) else []
            hits = []
            for match in raw_matches[:10]:
                hits.append({
                    "p": str(match.get("file", ""))[:220],
                    "l": int(match.get("line", 0)) or 1,
                    "x": str(match.get("content", "")).strip()[:200],
                })
            evidence_id = _sha256_hex(f"{src_seq}|sh|||{query}")[:8]
            return {
                "id": f"EVID-{evidence_id}",
                "k": "sh",
                "src_seq": src_seq,
                "tool": tool_name,
                "q": query,
                "h": f"sha256:{result_hash}",
                "hits": hits,
                "meta": {
                    "truncated": len(raw_matches) > 10,
                },
            }

        if tool_name == "get_entry_points":
            query = str(arguments.get("framework", "") or "entry_points")[:200]
            raw_entries = (result.data or {}).get("entry_points", []) if result.success and isinstance(result.data, dict) else []
            hits = []
            for entry in raw_entries[:10]:
                hits.append({
                    "p": str(entry.get("file", ""))[:220],
                    "l": int(entry.get("line", 0)) or 1,
                    "x": str(entry.get("content", "")).strip()[:200],
                })
            evidence_id = _sha256_hex(f"{src_seq}|sh|||{query}")[:8]
            return {
                "id": f"EVID-{evidence_id}",
                "k": "sh",
                "src_seq": src_seq,
                "tool": tool_name,
                "q": query,
                "h": f"sha256:{result_hash}",
                "hits": hits,
                "meta": {
                    "truncated": len(raw_entries) > 10,
                },
            }

        if tool_name == "list_directory":
            path = str(arguments.get("path", ""))[:220]
            payload = result.data if result.success else {"error": result.error}
            text = _stable_json(payload)[:35000]
            evidence_id = _sha256_hex(f"{src_seq}|sc|{path}||")[:8]
            return {
                "id": f"EVID-{evidence_id}",
                "k": "sc",
                "src_seq": src_seq,
                "p": path,
                "h": f"sha256:{result_hash}",
                "t": text,
                "tool": tool_name,
            }

        if tool_name in {"get_file_structure", "trace_data_flow"}:
            path = str(arguments.get("path") or arguments.get("file_path") or "")[:220]
            payload = result.data if result.success else {"error": result.error}
            text = _stable_json(payload)[:35000]
            evidence_id = _sha256_hex(f"{src_seq}|sc|{path}||{tool_name}")[:8]
            return {
                "id": f"EVID-{evidence_id}",
                "k": "sc",
                "src_seq": src_seq,
                "p": path,
                "h": f"sha256:{result_hash}",
                "t": text,
                "tool": tool_name,
            }

        return None

    # Control methods
    def pause(self):
        """Pause the audit."""
        self._paused.clear()
        self.status = AgentStatus.PAUSED
        self._broadcast(WSMessageType.AGENT_STATUS, {"status": "paused"})

    def resume(self):
        """Resume the audit."""
        self._paused.set()
        self.status = AgentStatus.RUNNING
        self._broadcast(WSMessageType.AGENT_STATUS, {"status": "running"})

    def cancel(self):
        """Cancel the audit."""
        self._cancelled = True
        self._paused.set()
        self.status = AgentStatus.CANCELLED
        self._broadcast(WSMessageType.AGENT_STATUS, {"status": "cancelled"})

    def request_pause(self):
        """Request the agent to pause at the next safe point (for session hibernation)."""
        self.pause()

    def is_pausable(self) -> bool:
        """Check if agent can be paused."""
        return self.status == AgentStatus.RUNNING

    def get_pause_state(self) -> dict:
        """Get current state for snapshot."""
        return {
            "processed_files": [],
            "pending_files": self.target_files or [],
            "current_file": None,
        }

    def to_schema(self) -> Agent:
        """Convert to Agent schema."""
        return Agent(
            id=self.id,
            repo_id=self.repo_id,
            name=self.name,
            agent_type=self.agent_type,
            status=self.status,
            provider_config=self.provider_config,
            custom_prompt=self.custom_prompt,
            target_files=self.target_files,
            focus_areas=self.focus_areas,
            created_at=self.created_at,
            started_at=self.started_at,
            completed_at=self.completed_at,
            files_analyzed=self.files_analyzed,
            findings_count=len(self.findings),
            error_message=self.error_message,
        )

    def get_audit_log(self) -> list[dict]:
        """Get the full AUDIT_JSONL log."""
        return self.state.audit_log if self.state else []

    def get_audit_jsonl(self) -> str:
        """Get AUDIT_JSONL as string."""
        if not self.state:
            return ""
        return "\n".join(json.dumps(e) for e in self.state.audit_log)
