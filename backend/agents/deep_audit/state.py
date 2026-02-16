# backend/agents/deep_audit/state.py
"""Campaign state for Deep Agents orchestration."""

from datetime import datetime
from enum import Enum
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from agents.deep_audit.foundation import (
    FoundationContext,
    SuspiciousSignal,
)


class CampaignPhase(str, Enum):
    """Current phase of the campaign."""
    FOUNDATION = "foundation"  # Building context
    HUNTING = "hunting"        # Finding signals
    ROUTING = "routing"        # Assigning to specialists
    VERIFICATION = "verification"  # Specialists analyzing
    RESOLUTION = "resolution"  # Final triage


class SignalStatus(str, Enum):
    """Status of a suspicious signal in the pipeline."""
    NEW = "new"                    # Just discovered by Hunter
    ROUTED = "routed"              # Assigned to family by Decider
    ASSIGNED = "assigned"          # Assigned to specialist by Family Coordinator
    ANALYZING = "analyzing"        # Specialist working on it
    DISPUTED = "disputed"          # Specialists disagree, needs Arbiter
    VERIFIED = "verified"          # Confirmed by specialist
    DISMISSED = "dismissed"        # Not a vulnerability
    TRIAGED = "triaged"           # Final classification made


class SignalState(BaseModel):
    """Tracking state for a suspicious signal through the pipeline."""
    signal: SuspiciousSignal
    status: SignalStatus = SignalStatus.NEW
    assigned_family: Optional[str] = None
    assigned_specialists: list[str] = Field(default_factory=list)
    specialist_reports: dict[str, dict] = Field(default_factory=dict)  # specialist_id -> report
    arbiter_verdict: Optional[dict] = None
    final_disposition: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(arbitrary_types_allowed=True)


class HypothesisStatus(str, Enum):
    """Status of a hypothesis in the investigation lifecycle."""
    NEW = "NEW"                # SinkHunter found a signal
    TRIAGED = "TRIAGED"        # Triager evaluated, worth pursuing
    TRACING = "TRACING"        # DataflowTracer working
    AUDITING = "AUDITING"      # Auditor deep-dive
    CONFIRMED = "CONFIRMED"    # Verified vulnerability
    DISMISSED = "DISMISSED"    # Not exploitable / false positive


class Severity(str, Enum):
    """Severity level for findings and hypotheses."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """Confidence level for findings and hypotheses."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ScopeDepth(int, Enum):
    """Depth level of investigation for a scope."""
    UNTOUCHED = 0   # Not yet analyzed
    MAPPED = 1      # ScopeMapper ran
    HUNTED = 2      # SinkHunter ran
    TRACED = 3      # DataflowTracer ran on signals
    AUDITED = 4     # Auditor deep-dive completed


class Hypothesis(BaseModel):
    """A candidate vulnerability being investigated."""
    id: str
    signal_type: str  # sql_injection_candidate, xss_candidate, etc.
    status: HypothesisStatus = HypothesisStatus.NEW
    confidence: Confidence = Confidence.LOW
    severity: Severity = Severity.MEDIUM
    location: str  # file:line
    scope_id: Optional[str] = None
    description: str = ""
    evidence_paths: list[str] = Field(default_factory=list)  # Paths in /memories/
    assigned_agent: Optional[str] = None
    notes: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ScopeStatus(BaseModel):
    """Status tracking for a scope (directory/module)."""
    scope_id: str
    path: str
    depth: ScopeDepth = ScopeDepth.UNTOUCHED
    summary_path: Optional[str] = None  # /memories/scopes/{id}/summary.md
    entrypoints_path: Optional[str] = None
    signals_path: Optional[str] = None
    notes: str = ""


class Entrypoint(BaseModel):
    """An externally reachable entry point."""
    id: str
    type: str  # http_route, cli_handler, message_consumer, graphql, rpc
    method: Optional[str] = None  # GET, POST, etc. for HTTP
    path: Optional[str] = None  # Route path
    handler: str  # Function/method name
    file_path: str
    line_number: int
    parameters: list[str] = Field(default_factory=list)
    auth_required: Optional[bool] = None
    scope_id: Optional[str] = None


class Dismissal(BaseModel):
    """A dismissed hypothesis with reasoning."""
    hypothesis_id: str
    signal_type: str
    location: str
    reason: str  # Why it's not exploitable
    evidence_paths: list[str] = Field(default_factory=list)
    dismissed_at: datetime = Field(default_factory=datetime.utcnow)
    dismissed_by: str = ""  # Agent that dismissed it


class WaveTask(BaseModel):
    """A single task dispatched in a wave."""
    task_id: str
    agent_type: str
    objective: str
    scope: str
    inputs: list[str] = Field(default_factory=list)
    deliverable: str
    success_criteria: str = ""
    time_budget: int = 300  # Seconds
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class WaveRecord(BaseModel):
    """Record of a completed wave."""
    wave_id: int
    tasks: list[WaveTask] = Field(default_factory=list)
    started_at: datetime
    completed_at: Optional[datetime] = None
    synthesis_path: Optional[str] = None  # /memories/overseer/wave_N_synthesis.md
    dispatch_path: Optional[str] = None  # /memories/overseer/wave_N_dispatch.json
    hypotheses_added: int = 0
    hypotheses_resolved: int = 0


class CampaignState(BaseModel):
    """
    Cumulative state for Deep Agents campaign.

    This is the central state object that the Overseer maintains
    across all waves, tracking the complete investigation context.

    Attributes:
        project_id: Unique identifier for the project/repository
        scan_tier: Time budget tier (quick/medium/advanced/pro/ultra/evil)
        deadline: Unix timestamp when time budget expires
        phase: Current campaign phase (FOUNDATION -> HUNTING -> VERIFICATION -> RESOLUTION)
        foundation_context: Built during Foundation Phase, injected into all agents
        hypotheses: Legacy tracking structure for candidate vulnerabilities
        signals: New signal tracking (NEW -> ROUTED -> VERIFIED/DISMISSED)
        confirmed_findings: Verified vulnerabilities to report
        dismissed: False positives with reasoning
        current_wave: Current wave number (0 = Foundation)
        wave_history: Record of all completed waves

    Phase Transitions:
        FOUNDATION: Build context with RepoProfiler, ScopeMapper, ThreatModeler
        HUNTING: Find signals with SinkHunter, EntrypointHunter
        ROUTING: Assign signals to specialist families (via Decider)
        VERIFICATION: Specialists analyze assigned signals
        RESOLUTION: Final triage and report generation

    The state is persisted to /memories/overseer/campaign_state.json.
    """

    # Project context
    project_id: str
    scan_tier: str  # quick/medium/advanced/pro/ultra/evil
    deadline: float  # Unix timestamp when budget expires
    started_at: datetime = Field(default_factory=datetime.utcnow)

    # Foundation Context (NEW)
    foundation_context: Optional[FoundationContext] = None
    phase: CampaignPhase = CampaignPhase.FOUNDATION

    # From repo profiling
    repo_profile: Optional[dict] = None
    repo_profile_path: str = "/memories/repo_profile.json"

    # Scope tracking
    scopes: dict[str, ScopeStatus] = Field(default_factory=dict)  # scope_id -> ScopeStatus

    # Entrypoints discovered
    entrypoints: list[Entrypoint] = Field(default_factory=list)

    # Hypotheses (the core tracking structure)
    hypotheses: list[Hypothesis] = Field(default_factory=list)

    # Signals tracking (NEW - replaces hypotheses for new flow)
    signals: dict[str, SignalState] = Field(default_factory=dict)  # signal_id -> SignalState

    # Results
    confirmed_findings: list[dict] = Field(default_factory=list)  # Finding dicts
    _signal_fingerprints: set = PrivateAttr(default_factory=set)  # Dedup: (file_path, line_start, category)
    dismissed: list[Dismissal] = Field(default_factory=list)

    # Wave tracking
    current_wave: int = 0
    wave_history: list[WaveRecord] = Field(default_factory=list)

    # Coverage tracking
    coverage_map: dict[str, ScopeDepth] = Field(default_factory=dict)  # file_path -> depth

    # Threat model (populated by ThreatModeler)
    threat_model_path: Optional[str] = None

    # Auth boundary map (populated by AuthBoundaryMapper)
    authz_map_path: Optional[str] = None

    # Limits
    max_hypotheses: int = 200
    max_findings: int = 50

    model_config = ConfigDict(use_enum_values=True, arbitrary_types_allowed=True)

    # Helper methods

    def get_hypotheses_by_status(self, status: HypothesisStatus) -> list[Hypothesis]:
        """Get all hypotheses with a given status."""
        return [h for h in self.hypotheses if h.status == status]

    def get_pending_hypotheses(self) -> list[Hypothesis]:
        """Get hypotheses that need work (not CONFIRMED or DISMISSED)."""
        terminal = {HypothesisStatus.CONFIRMED, HypothesisStatus.DISMISSED}
        return [h for h in self.hypotheses if h.status not in terminal]

    def get_scope_by_path(self, path: str) -> Optional[ScopeStatus]:
        """Find a scope by its path."""
        for scope in self.scopes.values():
            if scope.path == path:
                return scope
        return None

    def time_remaining(self) -> float:
        """Get seconds remaining until deadline."""
        return max(0, self.deadline - datetime.utcnow().timestamp())

    def time_exhausted(self) -> bool:
        """Check if time budget is exhausted."""
        return datetime.utcnow().timestamp() >= self.deadline

    def add_hypothesis(self, hypothesis: Hypothesis) -> bool:
        """Add a hypothesis if under limit. Returns True if added."""
        if len(self.hypotheses) >= self.max_hypotheses:
            return False
        self.hypotheses.append(hypothesis)
        return True

    def update_hypothesis_status(self, hypothesis_id: str, status: HypothesisStatus, notes: str = "") -> bool:
        """Update a hypothesis status. Returns True if found and updated."""
        for h in self.hypotheses:
            if h.id == hypothesis_id:
                h.status = status
                h.updated_at = datetime.utcnow()
                if notes:
                    h.notes = notes
                return True
        return False

    # Phase transition methods

    def set_phase(self, phase: CampaignPhase) -> None:
        """Set the current campaign phase."""
        self.phase = phase

    def advance_to_hunting(self) -> bool:
        """Advance to hunting phase if foundation is complete."""
        if self.foundation_context is None:
            return False
        self.phase = CampaignPhase.HUNTING
        return True

    def advance_to_routing(self) -> bool:
        """Advance to routing phase if signals exist."""
        if not self.signals:
            return False
        self.phase = CampaignPhase.ROUTING
        return True

    def advance_to_verification(self) -> bool:
        """Advance to verification phase if signals are routed."""
        routed = [s for s in self.signals.values() if s.status in (SignalStatus.ROUTED, SignalStatus.ASSIGNED)]
        if not routed:
            return False
        self.phase = CampaignPhase.VERIFICATION
        return True

    def advance_to_resolution(self) -> bool:
        """Advance to resolution phase for final triage."""
        self.phase = CampaignPhase.RESOLUTION
        return True

    def is_phase(self, phase: CampaignPhase) -> bool:
        """Check if currently in a specific phase."""
        return self.phase == phase

    # Signal tracking methods

    def add_signal(self, signal: SuspiciousSignal) -> SignalState:
        """Add a new signal to tracking."""
        state = SignalState(signal=signal)
        self.signals[signal.signal_id] = state
        return state

    def get_signal(self, signal_id: str) -> Optional[SignalState]:
        """Get a signal by ID."""
        return self.signals.get(signal_id)

    def update_signal_status(self, signal_id: str, status: SignalStatus) -> bool:
        """Update a signal's status."""
        if signal_id not in self.signals:
            return False
        self.signals[signal_id].status = status
        self.signals[signal_id].updated_at = datetime.utcnow()
        return True

    def assign_signal_to_family(self, signal_id: str, family: str) -> bool:
        """Assign a signal to a specialist family."""
        if signal_id not in self.signals:
            return False
        self.signals[signal_id].assigned_family = family
        self.signals[signal_id].status = SignalStatus.ROUTED
        self.signals[signal_id].updated_at = datetime.utcnow()
        return True

    def assign_signal_to_specialists(self, signal_id: str, specialist_ids: list[str]) -> bool:
        """Assign a signal to specific specialists."""
        if signal_id not in self.signals:
            return False
        self.signals[signal_id].assigned_specialists = specialist_ids
        self.signals[signal_id].status = SignalStatus.ASSIGNED
        self.signals[signal_id].updated_at = datetime.utcnow()
        return True

    def get_signals_by_status(self, status: SignalStatus) -> list[SignalState]:
        """Get all signals with a given status."""
        return [s for s in self.signals.values() if s.status == status]


# Backward compatibility alias
SupervisorState = CampaignState
