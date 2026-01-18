"""Types for ReAct agent."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any


@dataclass
class AgentThought:
    """A thought in the agent's reasoning chain."""
    thought: str
    action: Optional[str] = None
    action_input: Optional[dict] = None
    observation: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DuplicateTrackingState:
    """State for tracking duplicate tool calls."""
    recent_tool_calls: dict[str, int] = field(default_factory=dict)  # hash -> count
    max_duplicate_calls: int = 2  # Max times same call can be made
    consecutive_duplicates: int = 0  # Track consecutive duplicate iterations
    max_consecutive_duplicates: int = 3  # Force move on after this many


@dataclass
class TurnPlanningState:
    """State for turn planning and hypothesis tracking."""
    turn_counter: int = 0
    active_hypotheses: dict[str, Any] = field(default_factory=dict)


@dataclass
class TriageState:
    """State for attack-surface triage context."""
    threat_model: str = "AB"
    attack_surface_triage: list = field(default_factory=list)
    active_investigation_candidate_node_id: Optional[str] = None
    active_investigation_root_node_id: Optional[str] = None


@dataclass
class RateLimitState:
    """State for rate limiting and throttling."""
    iteration_delay: float = 2.0  # Seconds to wait between iterations
    min_delay: float = 1.0  # Minimum delay
    max_delay: float = 60.0  # Maximum delay for backoff
    current_backoff: float = 0.0  # Current backoff (resets on success)
    backoff_multiplier: float = 2.0  # Exponential backoff factor


@dataclass
class AgentLimits:
    """Limits and thresholds for agent execution."""
    max_iterations: int = 100  # Safety limit
    max_tool_calls_per_iteration: int = 5
    max_runtime_seconds: Optional[int] = None
    min_runtime_seconds: Optional[int] = None

    # Attack-surface triage rendering/automation knobs
    triage_render_limit: int = 20
    triage_prompt_limit: int = 10
    auto_queue_limit: int = 3

    # Finding acceptance gates
    min_finding_confidence: float = 0.8
    require_strict_finding_fields: bool = False
    require_ultra_verification: bool = False

    # "Press harder" completion confirmation
    audit_complete_confirmations_required: int = 1
    audit_complete_confirmations_seen: int = 0
