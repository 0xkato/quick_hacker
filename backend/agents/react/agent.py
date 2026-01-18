"""Main ReAct security agent implementation.

This module provides the main ReAct agent that coordinates the investigation loop.
It uses the helper modules for state management, handoff, dual-model config, and tool execution.

Note: This is currently a thin wrapper around the original implementation to maintain
backward compatibility while establishing the module structure. Future iterations can
gradually extract more functionality into the specialized modules.
"""

# Re-export the main agent from the original module
# This allows the new package structure while maintaining full compatibility
from agents.react_agent import (
    ReActSecurityAgent,
    AgentThought,
    sanitize_custom_prompt,
    MAX_CUSTOM_PROMPT_LENGTH,
    INJECTION_PATTERNS,
)

# Import the helper modules to make them available
from agents.react.types import (
    AgentLimits,
    DuplicateTrackingState,
    TurnPlanningState,
    TriageState,
    RateLimitState,
)
from agents.react.dual_model import DualModelState
from agents.react.handoff import HandoffManager
from agents.react.tool_executor import ToolCallTracker, ToolArgumentParser
from agents.react.state_machine import (
    AgentProfileManager,
    TimeBudgetManager,
    PromptBuilder,
    detect_category_from_focus_areas,
)

__all__ = [
    "ReActSecurityAgent",
    "AgentThought",
    "sanitize_custom_prompt",
    "MAX_CUSTOM_PROMPT_LENGTH",
    "INJECTION_PATTERNS",
    # Helper modules
    "AgentLimits",
    "DuplicateTrackingState",
    "TurnPlanningState",
    "TriageState",
    "RateLimitState",
    "DualModelState",
    "HandoffManager",
    "ToolCallTracker",
    "ToolArgumentParser",
    "AgentProfileManager",
    "TimeBudgetManager",
    "PromptBuilder",
    "detect_category_from_focus_areas",
]
