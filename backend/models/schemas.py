"""Pydantic schemas for quick_hack API."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
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
    DEEP_SCAN = "deep_scan"
    QUICK_AUDIT = "quick_audit"
    CUSTOM = "custom"
    STRICT_ANALYSIS = "strict_analysis"  # Zero false positive tolerance
    ULTRA_STRICT = "ultra_strict"  # Double verification, maximum precision
    DEEP_AUDIT = "deep_audit"  # 3-layer prompt architecture with AUDIT_JSONL logging
    ULTRATHINK = "ultrathink"  # Maximum cognitive depth with hierarchical cascade


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
    provider_config: ProviderConfig
    name: Optional[str] = None
    custom_prompt: Optional[str] = None
    target_files: Optional[list[str]] = Field(
        None, description="Specific files to analyze (None = all)"
    )
    focus_areas: Optional[list[str]] = Field(
        None, description="Specific vulnerability types to focus on"
    )


class Agent(BaseModel):
    id: str
    repo_id: str
    name: str
    agent_type: AgentType
    status: AgentStatus
    provider_config: ProviderConfig
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


# === WebSocket Messages ===

class WSMessageType(str, Enum):
    AGENT_STATUS = "agent_status"
    FINDING = "finding"
    PROGRESS = "progress"
    ERROR = "error"
    LOG = "log"
    PIPELINE_STAGE = "pipeline_stage"  # Multi-stage prompt pipeline events
    # Observability message types
    LLM_REQUEST = "llm_request"  # Prompt being sent to LLM
    LLM_RESPONSE = "llm_response"  # Response received from LLM
    TOOL_DETAIL = "tool_detail"  # Detailed tool execution info
    STATE_SYNC = "state_sync"  # Full state snapshot on pause/stop
    REPORT_READY = "report_ready"  # Report generated, ready for download
    # Ultrathink events
    ULTRATHINK_CASCADE_START = "ultrathink_cascade_start"
    ULTRATHINK_GATE_START = "ultrathink_gate_start"
    ULTRATHINK_GATE_COMPLETE = "ultrathink_gate_complete"
    ULTRATHINK_THINKING_UPDATE = "ultrathink_thinking_update"
    ULTRATHINK_CASCADE_COMPLETE = "ultrathink_cascade_complete"


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


# Enable forward references
FileNode.model_rebuild()
