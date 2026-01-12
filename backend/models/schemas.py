"""Pydantic schemas for quick_hack API."""

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field


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
    GENERIC = "generic"


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
    value: bool
    status: ChecklistStatus
    reason: str


class ProofChecklist(BaseModel):
    """Tri-state proof checklist for vulnerability validation."""
    source_controlled_input: ChecklistItem
    sink_present: ChecklistItem
    dataflow_evidenced: ChecklistItem
    reachable: ChecklistItem
    boundary_crossed: ChecklistItem
    not_only_misconfig: ChecklistItem
    security_control_bypassed: Optional[ChecklistItem] = None


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
