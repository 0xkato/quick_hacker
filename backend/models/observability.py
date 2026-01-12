"""Data models for agent observability and state management."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class LLMInteractionType(str, Enum):
    """Type of LLM interaction."""
    REQUEST = "request"
    RESPONSE = "response"


class LLMInteraction(BaseModel):
    """
    Captures a single LLM interaction (request or response).

    Used for debugging and understanding agent decision-making.
    """
    id: str
    agent_id: str
    interaction_type: LLMInteractionType
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Summary for quick display (first 200 chars)
    summary: str

    # Full content for expanded view
    full_content: str

    # For requests: the messages array sent to LLM
    messages: Optional[list[dict[str, Any]]] = None

    # For requests: tools available
    tools_available: Optional[list[str]] = None

    # For responses: tool calls made
    tool_calls: Optional[list[dict[str, Any]]] = None

    # Token usage (response only)
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    # Timing
    duration_ms: Optional[int] = None

    # Model info
    model: Optional[str] = None
    provider: Optional[str] = None

    # Request/response pair linking
    request_id: Optional[str] = None  # For responses, links to the request


class ToolDetail(BaseModel):
    """
    Detailed information about a tool execution.

    Captures full arguments, results, and context for debugging.
    """
    id: str
    agent_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Tool identification
    tool_name: str
    tool_call_id: str

    # Arguments (full, not truncated)
    arguments: dict[str, Any]
    arguments_summary: str  # Human-readable summary

    # Result
    result: Any
    result_summary: str  # Human-readable summary
    success: bool
    error_message: Optional[str] = None

    # For file reads: code context (lines before/after)
    code_context: Optional[dict[str, Any]] = None  # {before: str, content: str, after: str, file_path: str, line_range: [start, end]}

    # Timing
    duration_ms: int

    # LLM reasoning that led to this tool call
    llm_reasoning: Optional[str] = None

    # Confidence score if parseable from LLM response
    confidence_score: Optional[float] = None


class AgentStateSnapshot(BaseModel):
    """
    Complete snapshot of agent state for persistence and resumption.

    Saved on pause/stop for later resumption.
    """
    id: str
    agent_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    # Agent configuration
    repo_id: str
    repo_path: str
    agent_type: str
    provider_config: dict[str, Any]
    custom_prompt: Optional[str] = None
    target_files: Optional[list[str]] = None
    focus_areas: Optional[list[str]] = None

    # Progress state
    status: str
    files_analyzed: int
    total_files: int
    current_file: Optional[str] = None

    # Findings so far
    findings: list[dict[str, Any]]

    # LLM conversation history for resumption
    conversation_history: list[dict[str, Any]]

    # Observability history (for refresh/restart resilience)
    llm_interactions: list[dict[str, Any]] = Field(default_factory=list)
    tool_details: list[dict[str, Any]] = Field(default_factory=list)

    # Flow visualization state
    flow_nodes: list[dict[str, Any]]
    flow_edges: list[dict[str, Any]]
    current_flow_node_id: Optional[str] = None

    # Investigation context
    investigation_context: Optional[dict[str, Any]] = None  # ReAct agent's accumulated context

    # Token usage totals
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_api_calls: int = 0

    # Error recovery info
    last_error: Optional[str] = None
    retry_count: int = 0


class FindingSummary(BaseModel):
    """Summary of a finding for reports."""
    id: str
    severity: str
    title: str
    file_path: str
    line_start: int
    vulnerability_type: str
    confidence: float


class TimelineEvent(BaseModel):
    """Event in the investigation timeline."""
    timestamp: datetime
    event_type: str  # 'started', 'file_analyzed', 'finding_reported', 'tool_called', 'paused', 'completed'
    description: str
    data: Optional[dict[str, Any]] = None


class InvestigationReport(BaseModel):
    """
    Comprehensive report generated on agent completion.

    Includes executive summary, findings, timeline, and stats.
    """
    id: str
    agent_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    # Executive summary
    executive_summary: str

    # Agent info
    agent_name: str
    agent_type: str
    repo_id: str
    repo_name: str

    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None

    # Findings summary
    findings_summary: list[FindingSummary]
    findings_by_severity: dict[str, int]  # {critical: 2, high: 5, ...}
    findings_by_type: dict[str, int]  # {sql_injection: 3, xss: 2, ...}

    # Files analyzed
    total_files: int
    files_with_findings: list[str]

    # Timeline
    timeline: list[TimelineEvent]

    # Token usage
    total_prompt_tokens: int
    total_completion_tokens: int
    total_api_calls: int
    estimated_cost: Optional[float] = None  # Estimated $ cost

    # Flow visualization export paths
    flow_json_path: Optional[str] = None
    flow_svg_path: Optional[str] = None

    # Markdown report path
    markdown_path: Optional[str] = None


class TokenUsage(BaseModel):
    """Token usage from a single LLM call."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )
