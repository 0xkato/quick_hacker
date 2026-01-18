"""Pydantic schemas for quick_hack API."""

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, field_validator

from services.redaction_service import redaction_service


# === Enums ===

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentType(str, Enum):
    QUICK_AUDIT = "quick_audit"
    CUSTOM = "custom"
    STRICT_ANALYSIS = "strict_analysis"  # Zero false positive tolerance
    ULTRA_STRICT = "ultra_strict"  # Double verification, maximum precision
    DEEP_AUDIT = "deep_audit"  # Long-running, coverage-oriented deep audit (ReAct)


class ProviderType(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    CODEX_CLI = "codex_cli"


class ThinkingMode(str, Enum):
    """How to invoke extended thinking."""
    NATIVE = "native"      # Use provider's native extended thinking (Claude)
    SIMULATED = "simulated"  # Simulate via chain-of-thought prompting (GPT-4)
    STRUCTURED = "structured"  # Structured reasoning prompts (open source)
    AUTO = "auto"          # Auto-detect based on model


class UltrathinkGate(str, Enum):
    """Gates in the hierarchical verification cascade."""
    TRIAGE = "triage"
    DEEP_ANALYSIS = "deep_analysis"
    DEVILS_ADVOCATE = "devils_advocate"
    PROOF_GENERATOR = "proof_generator"
    FINAL_GATE = "final_gate"


class HandoffMode(str, Enum):
    EXPLORATION = "exploration"
    SINK_IDENTIFICATION = "sink_identification"


class FindingClassification(str, Enum):
    """Classification of a finding for gate filtering."""
    SECURITY_ISSUE = "security_issue"
    BUG = "bug"
    MISCONFIGURATION = "misconfiguration"
    HARDENING = "hardening"


# Type alias for fix types
FixType = Literal["code", "config", "docs", "warning"]


class Disposition(str, Enum):
    """Triage disposition for findings."""
    VALID_SECURITY_ISSUE = "valid_security_issue"
    BUG = "bug"
    HARDENING = "hardening"
    MISCONFIGURATION = "misconfiguration"
    BY_DESIGN = "by_design"
    SPECULATIVE = "speculative"


class ChecklistStatus(str, Enum):
    """Tri-state status for proof checklist items."""
    PROVEN = "proven"
    DISPROVEN = "disproven"
    UNKNOWN = "unknown"


class VulnerabilityCategory(str, Enum):
    """Normalized vulnerability categories."""
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    SQL_INJECTION = "sql_injection"
    SSRF = "ssrf"
    CSWSH = "cswsh"
    DESERIALIZATION = "deserialization"
    HARDCODED_SECRET = "hardcoded_secret"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    CSRF = "csrf"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DOS = "dos"
    RACE_CONDITION = "race_condition"
    INTEGER_OVERFLOW = "integer_overflow"
    GENERIC = "generic"


class SubmissionDecision(str, Enum):
    """Protocol evaluation decision for reportability."""
    SUBMIT = "submit"
    DONT_SUBMIT = "dont_submit"
    NEEDS_MORE_INFO = "needs_more_info"


class InputChannel(str, Enum):
    """
    Input channels represent where attacker-controlled data originates.

    Attacker-control is derived by: (deterministic channel + threat model profile)
    """
    network = "network"
    file_input = "file_input"
    web_content = "web_content"

    # High-noise channels (only attacker-controlled if enabled by profile)
    repo_checkout = "repo_checkout"
    ci_artifact = "ci_artifact"
    local_unprivileged = "local_unprivileged"

    unknown = "unknown"


class PathClassification(str, Enum):
    """File path classification for scope filtering."""
    runtime = "runtime"          # Production code
    tooling = "tooling"          # Developer tools, may run on CI
    third_party = "third_party"  # Vendored dependencies
    unknown = "unknown"


class PolicyDecision(str, Enum):
    """Policy evaluation decision for VRP reporting."""
    REPORT_SECURITY_VRP = "report_security_vrp"           # High confidence, VRP-reportable
    REPORT_SECURITY_LOW_CONFIDENCE = "report_security_low" # Valid but needs review
    HARDENING_ONLY = "hardening_only"                     # Not security issue, hardening opp
    DO_NOT_REPORT = "do_not_report"                       # Filtered out


class PathClassificationConfig(BaseModel):
    """Path classification rules for scope filtering."""
    runtime_roots: list[str] = Field(
        default_factory=lambda: ["src/", "app/", "backend/", "frontend/", "lib/", "libs/"]
    )
    tooling_roots: list[str] = Field(
        default_factory=lambda: ["tools/", "scripts/", "examples/", "samples/"]
    )
    third_party_roots: list[str] = Field(
        default_factory=lambda: [
            "third_party/", "vendor/", "node_modules/",
            ".venv/", "site-packages/", "dist/", "build/",
            "target/", "out/"
        ]
    )
    test_roots: list[str] = Field(
        default_factory=lambda: ["test/", "tests/", "__tests__/"]
    )
    ci_roots: list[str] = Field(
        default_factory=lambda: [".github/", ".gitlab/", "ci/"]
    )
    docs_roots: list[str] = Field(
        default_factory=lambda: ["docs/", "documentation/"]
    )
    migration_roots: list[str] = Field(
        default_factory=lambda: ["migrations/", "migrate/"]
    )

    @field_validator('runtime_roots', 'tooling_roots', 'third_party_roots', 'test_roots', 'ci_roots', 'docs_roots', 'migration_roots')
    @classmethod
    def validate_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Path roots cannot be empty")
        return v

    @field_validator('runtime_roots', 'tooling_roots', 'third_party_roots', 'test_roots', 'ci_roots', 'docs_roots', 'migration_roots')
    @classmethod
    def validate_trailing_slash(cls, v: list[str]) -> list[str]:
        for path in v:
            if not path.endswith('/'):
                raise ValueError(f"Path must end with '/': {path}")
        return v


class CommandInjectionGate(BaseModel):
    """Evidence requirements for command injection to be VRP-reportable."""
    require_shell_execution: bool = True  # shell=True or os.system
    require_attacker_controls_shell_string: bool = True  # Not just arguments
    credible_boundaries: list[str] = Field(
        default_factory=lambda: ["network", "ci_artifact", "repo_checkout", "file_input"]
    )


class IntegerOverflowGate(BaseModel):
    """Evidence requirements for integer overflow to be VRP-reportable."""
    require_attacker_controlled_operands: bool = True
    require_overflow_prone_operation: bool = True  # Multiplication or unchecked addition
    require_allocation_or_bounds_use: bool = True  # malloc, array index, buffer size
    require_proven_mismatch: bool = True  # 32-bit calc → 64-bit size, etc.


class MemoryCorruptionGate(BaseModel):
    """Evidence requirements for memory corruption to be VRP-reportable."""
    require_asan_trace: bool = False  # Prefer but don't require
    require_release_config: bool = True  # Must trigger in NDEBUG/release
    require_untrusted_input_path: bool = True


class DosGate(BaseModel):
    """Evidence requirements for DoS to be VRP-reportable."""
    require_service_boundary: bool = True  # Network service, not local script


class EvidenceGates(BaseModel):
    """Per-vulnerability-type evidence requirements."""
    command_injection: CommandInjectionGate = Field(default_factory=CommandInjectionGate)
    integer_overflow: IntegerOverflowGate = Field(default_factory=IntegerOverflowGate)
    memory_corruption: MemoryCorruptionGate = Field(default_factory=MemoryCorruptionGate)
    dos: DosGate = Field(default_factory=DosGate)


class DeduplicationConfig(BaseModel):
    """Deduplication strategy configuration."""
    enabled: bool = True
    strategy: Literal["exact", "fuzzy", "symbol"] = "exact"
    exact_match_fields: list[str] = Field(
        default_factory=lambda: ["file_path", "line_start", "vulnerability_type", "title"]
    )


class TriagePolicy(BaseModel):
    """
    VRP triage policy configuration.

    Encodes "what do we bother reporting given strictness, scope, and evidence?"
    Separate from ThreatModelProfile (attacker capabilities).
    """
    name: str  # e.g., "vrp-google-oss-strict", "internal-audit"

    # Path classification and filtering
    path_classification: PathClassificationConfig = Field(
        default_factory=PathClassificationConfig
    )
    filter_third_party: bool = True  # Drop findings from third_party_roots
    filter_tests: bool = True  # Drop findings from test_roots
    filter_ci: bool = True  # Drop findings from ci_roots
    filter_docs: bool = True  # Drop findings from docs_roots
    filter_migrations: bool = True  # Drop findings from migration_roots

    # Tooling findings require stronger boundary (not auto-filtered)
    tooling_requires_ci_boundary: bool = True

    # Evidence gates per vulnerability type
    evidence_gates: EvidenceGates = Field(default_factory=EvidenceGates)

    # Deduplication
    deduplication: DeduplicationConfig = Field(default_factory=DeduplicationConfig)

    # Disposition overrides
    report_hardening: bool = False  # Default: don't report HARDENING findings
    report_by_design: bool = False  # Default: don't report BY_DESIGN findings


class PolicyEvaluationResult(BaseModel):
    """Result from policy evaluation."""
    decision: PolicyDecision
    path_classification: PathClassification
    gate_results: dict[str, bool]  # Which gates passed/failed
    reasoning: list[str]  # Why this decision was made
    original_disposition: Disposition  # From StrictClassifier
    overridden: bool  # True if policy changed the classification


# === Phase 4: Project Scope ===

class ProjectScope(BaseModel):
    """
    Scope configuration for First-Party Focus.

    Defines which code paths are "product code" vs "library code".
    """
    primary_code_roots: list[str] = Field(
        default_factory=lambda: ["src/", "app/", "backend/", "frontend/"]
    )

    excluded_roots: list[str] = Field(
        default_factory=lambda: [
            "vendor/", "third_party/", "node_modules/",
            ".venv/", "site-packages/", "dist/", "build/",
            "target/", "out/"
        ]
    )

    treat_excluded_as_supporting_evidence_only: bool = True


# === Repository ===

class RepoCloneRequest(BaseModel):
    url: str = Field(..., description="Git repository URL")
    branch: Optional[str] = Field(None, description="Branch to clone")


class RepoInfo(BaseModel):
    id: str
    url: str
    name: str
    branch: str
    path: str
    cloned_at: datetime
    languages: list[str] = []
    file_count: int = 0


# === File System ===

class FileNode(BaseModel):
    name: str
    path: str
    is_dir: bool
    children: Optional[list["FileNode"]] = None
    size: Optional[int] = None
    extension: Optional[str] = None


class FileContent(BaseModel):
    path: str
    content: str
    language: Optional[str] = None
    line_count: int


# === Agent ===

class ProviderConfig(BaseModel):
    provider: ProviderType
    model: str
    api_key: Optional[str] = Field(None, description="API key (uses env if not provided)")
    base_url: Optional[str] = None
    codex_path: Optional[str] = Field(
        None,
        description="Optional path to the local Codex CLI binary (provider=codex_cli only).",
    )
    temperature: float = 0.0
    max_tokens: int = 4096


class AgentCreateRequest(BaseModel):
    repo_id: str
    agent_type: AgentType
    provider_config: Optional[ProviderConfig] = None  # Change to Optional for backwards compat

    # Time-tiered scan configuration (new)
    scan_tier: Optional[str] = Field(
        None,
        description="Time-based scan tier: quick|medium|advanced|pro|ultra|evil. Defaults to quick.",
    )
    time_budget_seconds: Optional[int] = Field(
        None,
        ge=60,
        le=60 * 60 * 24,
        description="Optional override for scan duration in seconds (enables custom timing).",
    )

    # Dual-model configuration
    scanner_config: Optional[ProviderConfig] = None
    analyzer_config: Optional[ProviderConfig] = None
    handoff_after: HandoffMode = HandoffMode.SINK_IDENTIFICATION

    name: Optional[str] = None
    custom_prompt: Optional[str] = None
    target_files: Optional[list[str]] = Field(
        None, description="Specific files to analyze (None = all)"
    )
    focus_areas: Optional[list[str]] = Field(
        None, description="Specific vulnerability types to focus on"
    )
    use_claude_sdk: bool = Field(
        False,
        description="Use Claude Agent SDK for native tool loop (Anthropic only)"
    )


class Agent(BaseModel):
    id: str
    repo_id: str
    name: str
    agent_type: AgentType
    status: AgentStatus
    provider_config: ProviderConfig
    scan_tier: Optional[str] = None
    time_budget_seconds: Optional[int] = None
    custom_prompt: Optional[str] = None
    target_files: Optional[list[str]] = None
    focus_areas: Optional[list[str]] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    files_analyzed: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None


class AgentUpdate(BaseModel):
    status: Optional[AgentStatus] = None
    custom_prompt: Optional[str] = None
    target_files: Optional[list[str]] = None


# === Triage Models ===

class ChecklistItem(BaseModel):
    """A single item in the proof checklist with tri-state status."""
    value: bool  # KEEP - existing field for stored JSON compatibility
    status: ChecklistStatus  # PROVEN | DISPROVEN | UNKNOWN
    reason: str  # Human-readable explanation
    tool_calls: list[str] = Field(default_factory=list)  # Tool calls that contributed to this determination

    # Phase 3 addition (backward-compatible)
    reason_code: str | None = None  # Machine-readable code (e.g., "disabled_by_profile")


class ProofChecklist(BaseModel):
    """Tri-state proof checklist for vulnerability validation."""
    source_controlled_input: ChecklistItem
    sink_present: ChecklistItem
    dataflow_evidenced: ChecklistItem
    reachable: ChecklistItem
    boundary_crossed: ChecklistItem
    not_only_misconfig: ChecklistItem
    security_control_bypassed: Optional[ChecklistItem] = None

    # Exec/eval specific reasoning (for auditable filtering)
    exec_sink_reason: Optional[str] = None
    feature_intent_reason: Optional[str] = None
    auth_bypass_reason: Optional[str] = None


class SubmissionResult(BaseModel):
    """
    Protocol-aware reportability evaluation result.

    Represents the 'worth submitting' decision for a finding based on
    protocol-specific rules (VRP, bug bounty, internal disclosure, etc.).
    """
    protocol_id: str  # e.g., "osvrp_strict", "hackerone_strict", "internal"
    decision: SubmissionDecision
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons for the decision (2-4 bullets)"
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific evidence gaps if decision=needs_more_info"
    )
    suggested_next_steps: list[str] = Field(
        default_factory=list,
        description="Actionable steps to resolve evidence gaps"
    )

    # Quest tracking
    quest_run: bool = False
    quest_id: Optional[str] = None
    quest_findings: Optional[dict] = None

    # Disposition override
    disposition_modified: bool = False
    disposition_reason: Optional[str] = None


class ProtocolPolicy(BaseModel):
    """Protocol-specific submission rules."""
    id: str = Field(..., description="Unique protocol identifier")
    display_name: str = Field(..., description="Human-readable protocol name")

    # Threat model defaults
    default_threat_model_preset: str = Field("AB", description="Default threat model preset (e.g., 'AB', 'ABC')")

    # Disposition gates
    min_disposition_to_submit: set[Disposition] = Field(
        default_factory=lambda: {Disposition.VALID_SECURITY_ISSUE}
    )

    # Submission heuristics
    require_cross_boundary_for_local_bugs: bool = True
    reject_social_engineering_only: bool = True
    require_repro_steps: bool = True
    require_impact_statement: bool = True
    require_realistic_attacker_model: bool = True

    # Category-specific rules
    category_rules: dict[VulnerabilityCategory, dict[str, Any]] = Field(
        default_factory=dict
    )

    # Evidence quality gates
    min_checklist_proven_count: int = 4
    allow_unknown_in_checklist: bool = False

    # Quest behavior
    enable_evidence_quests: bool = True
    quest_categories: list[VulnerabilityCategory] = Field(default_factory=list)


class EvidenceQuest(BaseModel):
    """Configuration for autonomous evidence gathering agent."""
    id: str = Field(..., description="Unique quest identifier")
    finding_id: str = Field(..., description="ID of the finding this quest is gathering evidence for")
    category: VulnerabilityCategory

    # What evidence is missing
    missing_items: list[str]

    # Quest prompt template
    quest_type: str = Field(..., description="Type of evidence quest to run")

    # Status
    status: AgentStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Results
    evidence_found: dict[str, Any] = Field(default_factory=dict)
    new_checklist_items: dict[str, ChecklistItem] = Field(default_factory=dict)
    success: bool = False
    error_message: Optional[str] = None


class EvidenceBlob(BaseModel):
    """Evidence snippet gathered during triage."""
    id: str
    finding_id: str
    evidence_type: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    match_type: Optional[str] = None
    created_at: datetime


class Evidence(BaseModel):
    """
    Evidence bundle for triage classification.

    Consolidates data from EvidenceGatherer (code snippets, symbol info, framework detection)
    with input channel inference metadata. Persisted to evidence_json in database.
    """
    # Core identification
    finding_id: str

    # Code context (from EvidenceGatherer)
    snippet: str | None = None  # ±30 lines around reported line
    handler_snippet: str | None = None  # Enclosing function/class code
    symbol_info: dict | None = None  # Enclosing symbol metadata
    framework: str | None = None  # Detected framework (fastapi, flask, django, etc.)

    # Triage evidence (source/sink/dataflow)
    route_registration: str | None = None  # @app.route(...) or similar
    auth_gates: list[str] = Field(default_factory=list)  # Auth decorators/checks
    dataflow_snippet: str | None = None  # Variable flow evidence
    matches: list[dict] = Field(default_factory=list)  # EvidenceMatch as dicts

    # SSRF-specific analysis
    ssrf_analysis: dict | None = None  # SSRFAnalysis as dict

    # Budget tracking
    timed_out: bool = False

    # Phase 3 additions (input channel inference)
    input_channel: InputChannel = InputChannel.unknown
    input_channel_deterministic: bool = False

    # Auditable inference metadata (like checklist reason)
    input_channel_signals: list[str] = Field(default_factory=list)  # Signal types that contributed
    input_channel_reason: str = ""  # Human-readable inference explanation


class TriageMetrics(BaseModel):
    """Metrics from a triage batch."""
    raw_count: int
    triaged_count: int
    reportable_count: int
    by_disposition: dict[str, int]
    timeout_count: int
    timeout_rate: float


class TriageResult(BaseModel):
    """Result from triage service."""
    triaged_findings: list["Finding"]
    reportable_findings: list["Finding"]
    metrics: TriageMetrics
    batch_id: str

    @property
    def triaged_count(self) -> int:
        return self.metrics.triaged_count

    @property
    def reportable_count(self) -> int:
        return self.metrics.reportable_count

    @property
    def raw_count(self) -> int:
        return self.metrics.raw_count


# === Findings ===

class Finding(BaseModel):
    id: str
    agent_id: str
    repo_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    vulnerable_code: Optional[str] = None  # The exact vulnerable code snippet
    vulnerability_type: str
    cwe_id: Optional[str] = None  # CWE identifier (e.g., "CWE-89")
    attack_scenario: Optional[str] = None
    proof_of_concept: Optional[str] = None  # PoC command or payload
    recommended_fix: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    source_trace: Optional[list[str]] = None  # Source-to-sink trace steps
    created_at: datetime
    metadata: dict[str, Any] = {}
    # Classification gate fields
    classification: FindingClassification = FindingClassification.SECURITY_ISSUE
    config_dependent: bool = False
    config_flag: Optional[str] = None
    default_secure: Optional[bool] = None
    contradiction_present: bool = False
    fix_type: FixType = "code"
    classification_reasoning: str = ""
    # Triage fields
    batch_id: Optional[str] = None
    disposition: Optional[Disposition] = None
    classification_confidence: Optional[int] = Field(None, ge=0, le=100)
    exploit_confidence: Optional[int] = Field(None, ge=0, le=100)
    proof_checklist: Optional[ProofChecklist] = None
    reasoning: Optional[list[str]] = None
    triage_policy_version: Optional[str] = None
    triaged_at: Optional[datetime] = None
    category: Optional[VulnerabilityCategory] = None

    # Protocol evaluation result
    submission_result: Optional[SubmissionResult] = None

    # Quest tracking (also stored in submission_result.quest_id if quest ran during protocol evaluation)
    evidence_quest_id: Optional[str] = None
    evidence_quest_completed: bool = False

    # Path classification (for pre-triage filtering)
    path_classification: Optional[PathClassification] = None

    # Policy evaluation results
    policy_decision: Optional[PolicyDecision] = None
    policy_reasoning: Optional[list[str]] = None

    @field_validator(
        "description",
        "code_snippet",
        "vulnerable_code",
        "attack_scenario",
        "proof_of_concept",
        "recommended_fix",
        mode="before",
    )
    @classmethod
    def _redact_text_fields(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        return redaction_service.redact(value)

    @field_validator("source_trace", mode="before")
    @classmethod
    def _redact_source_trace(cls, value: Any) -> Any:
        if value is None or not isinstance(value, list):
            return value
        return [redaction_service.redact(str(item)) for item in value]


class FindingCreate(BaseModel):
    severity: Severity
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    vulnerable_code: Optional[str] = None  # The exact vulnerable code snippet
    vulnerability_type: str
    cwe_id: Optional[str] = None  # CWE identifier (e.g., "CWE-89")
    attack_scenario: Optional[str] = None
    proof_of_concept: Optional[str] = None  # PoC command or payload
    recommended_fix: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    source_trace: Optional[list[str]] = None  # Source-to-sink trace steps
    metadata: dict[str, Any] = {}
    # Classification gate fields
    classification: FindingClassification = FindingClassification.SECURITY_ISSUE
    config_dependent: bool = False
    config_flag: Optional[str] = None
    default_secure: Optional[bool] = None
    contradiction_present: bool = False
    fix_type: FixType = "code"
    classification_reasoning: str = ""

    @field_validator(
        "description",
        "code_snippet",
        "vulnerable_code",
        "attack_scenario",
        "proof_of_concept",
        "recommended_fix",
        mode="before",
    )
    @classmethod
    def _redact_text_fields(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        return redaction_service.redact(value)

    @field_validator("source_trace", mode="before")
    @classmethod
    def _redact_source_trace(cls, value: Any) -> Any:
        if value is None or not isinstance(value, list):
            return value
        return [redaction_service.redact(str(item)) for item in value]


# === Dual-Model Handoff ===

class FileReadRecord(BaseModel):
    """Record of a file read during scanning."""
    path: str
    relevance_score: float = 0.0
    summary: Optional[str] = None
    read_at: datetime = Field(default_factory=datetime.utcnow)


class TechStack(BaseModel):
    """Detected technology stack."""
    languages: list[str] = []
    frameworks: list[str] = []
    dependencies: list[str] = []


class EntryPoint(BaseModel):
    """An entry point discovered during scanning."""
    name: str
    file_path: str
    line_number: int
    method: Optional[str] = None  # HTTP method if route
    route: Optional[str] = None   # Route path if applicable
    code_snippet: str             # ~20 lines of context


class Sink(BaseModel):
    """A dangerous sink discovered during scanning."""
    sink_type: str  # sql, exec, eval, file_write, etc.
    function_name: str
    file_path: str
    line_number: int
    code_snippet: str  # ~20 lines of context
    context: Optional[str] = None  # Additional context


class ScannerHandoffState(BaseModel):
    """State passed from scanner to analyzer."""
    repo_path: str
    files_read: list[FileReadRecord] = []
    tech_stack: TechStack = Field(default_factory=TechStack)
    entry_points: list[EntryPoint] = []
    dangerous_sinks: list[Sink] = []
    file_map: dict[str, dict] = {}  # path -> {relevance, summary}

    # Metadata
    scanner_model: str = ""
    scanner_tokens_used: int = 0
    scanner_duration_ms: int = 0
    handoff_reason: str = ""  # "exploration_complete", "sink_identification_complete", "limit_reached"


# === WebSocket Messages ===

class WSMessageType(str, Enum):
    AGENT_STATUS = "agent_status"
    FINDING = "finding"
    PROGRESS = "progress"
    ERROR = "error"
    LOG = "log"
    PHASE_HANDOFF = "phase_handoff"  # Scanner -> Analyzer transition
    # Observability message types
    LLM_REQUEST = "llm_request"  # Prompt being sent to LLM
    LLM_RESPONSE = "llm_response"  # Response received from LLM
    TOOL_DETAIL = "tool_detail"  # Detailed tool execution info
    STATE_SYNC = "state_sync"  # Full state snapshot on pause/stop
    REPORT_READY = "report_ready"  # Report generated, ready for download
    # Session hibernation events
    SESSION_PAUSING = "session_pausing"
    SESSION_PAUSED = "session_paused"
    SESSION_RESUMED = "session_resumed"


class WSMessage(BaseModel):
    type: WSMessageType
    agent_id: str
    data: dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# === Sandbox ===

class CodeExecutionRequest(BaseModel):
    code: str
    language: str
    timeout: int = Field(30, le=60)


class CodeExecutionResult(BaseModel):
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: int


# === API Responses ===

class APIResponse(BaseModel):
    success: bool
    message: Optional[str] = None
    data: Optional[Any] = None


# === Session Hibernation ===

class SessionSnapshotAgent(BaseModel):
    """Agent state within a session snapshot."""
    id: str
    agent_type: str
    status: str  # 'running' | 'paused' | 'completed'
    target_files: list[str] = []
    processed_files: list[str] = []
    pending_files: list[str] = []
    current_file: Optional[str] = None
    config: dict[str, Any] = {}


class SessionSnapshotLLMContext(BaseModel):
    """LLM conversation context for an agent."""
    agent_id: str
    messages: list[dict[str, Any]] = []


class SessionSnapshotUIState(BaseModel):
    """UI state to restore."""
    active_view: str
    selected_file: Optional[str] = None
    open_panels: list[str] = []
    selected_agent_id: Optional[str] = None


class SessionSnapshot(BaseModel):
    """Full session snapshot for hibernation."""
    version: int = 1
    timestamp: datetime
    project_id: str
    agents: list[SessionSnapshotAgent] = []
    findings: list[dict[str, Any]] = []  # Finding dicts
    llm_context: list[SessionSnapshotLLMContext] = []
    ui_state: SessionSnapshotUIState


class SnapshotInfo(BaseModel):
    """Metadata about a snapshot (for conflict dialog)."""
    timestamp: datetime
    agent_count: int
    findings_count: int
    pending_files: int


# === Triage API Models ===

class TriageRequest(BaseModel):
    """Request to triage findings."""
    finding_ids: Optional[list[str]] = Field(
        None,
        description="Specific finding IDs to triage (None = all for agent)"
    )
    force_retriage: bool = Field(
        default=False,
        description="Re-run triage even if already triaged"
    )
    budget_override_ms: Optional[int] = Field(
        None,
        ge=1000,
        le=300000,
        description="Override batch budget in milliseconds"
    )


class TriageResponse(BaseModel):
    """Response from triage endpoint."""
    batch_id: str
    metrics: TriageMetrics


class BudgetConfig(BaseModel):
    """Budget configuration for triage."""
    batch_ms: int = 15000
    per_finding_ms: int = 300
    max_evidence_bytes: int = 10000
    max_snippet_lines: int = 200


# Enable forward references
FileNode.model_rebuild()
TriageResult.model_rebuild()
