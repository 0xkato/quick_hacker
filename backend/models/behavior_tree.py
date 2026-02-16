"""Data models for the LLM Behavior Tree visualization system.

Tracks every LLM action (prompts, responses, tool calls, tool results)
in a hierarchical tree structure for real-time visualization.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class BTNodeType(str, Enum):
    """Type of node in the behavior tree."""
    SESSION = "session"            # Root: one per agent run
    PHASE = "phase"                # Pipeline phase (Foundation, Hunting, etc.)
    WAVE = "wave"                  # Hunting/routing wave
    SIGNAL = "signal"              # Signal being routed through pipeline
    AGENT = "agent"                # A specific LLM sub-agent invocation
    TURN = "turn"                  # One LLM turn (prompt -> response cycle)
    LLM_REQUEST = "llm_request"    # Prompt sent to LLM
    LLM_RESPONSE = "llm_response"  # Text response from LLM
    LLM_THINKING = "llm_thinking"  # Extended thinking block
    TOOL_CALL = "tool_call"        # Tool invocation
    TOOL_RESULT = "tool_result"    # Tool return value
    FINDING = "finding"            # Finding reported
    ERROR = "error"                # Error occurred


class BTNodeStatus(str, Enum):
    """Status of a behavior tree node."""
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"


class BTNode(BaseModel):
    """A single node in the behavior tree."""
    id: str
    agent_id: str                                  # Parent agent (overseer) ID
    parent_id: Optional[str] = None                # Parent node ID (None for root)
    node_type: BTNodeType
    label: str                                     # Short display text (≤80 chars)
    status: BTNodeStatus = BTNodeStatus.PENDING
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: dict[str, Any] = Field(default_factory=dict)  # Full payload
    children_count: int = 0                        # For UI collapse indicators
    depth: int = 0                                 # Pre-computed for layout


class BTNodeUpdate(BaseModel):
    """Partial update to an existing behavior tree node."""
    id: str
    agent_id: str
    status: Optional[BTNodeStatus] = None
    label: Optional[str] = None
    data_merge: Optional[dict[str, Any]] = None    # Merged into existing data
    children_count: Optional[int] = None
