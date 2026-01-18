"""ReAct security agent module.

This module provides a structured implementation of the ReAct (Reasoning and Acting)
security research agent. The agent investigates codebases like a human security
researcher:

1. Explores the codebase structure
2. Identifies attack surfaces
3. Forms hypotheses about vulnerabilities
4. Uses tools to investigate and validate
5. Reports confirmed findings with proof

Architecture:
- agent.py: Main ReAct agent coordinator
- state_machine.py: State management and configuration
- handoff.py: Scanner → Analyzer phase handoff
- dual_model.py: Dual-model configuration (scanner/analyzer)
- tool_executor.py: Tool execution orchestration
- types.py: Common types and data structures

Usage:
    from agents.react import ReActSecurityAgent

    agent = ReActSecurityAgent(request, repo_path)
    findings = await agent.run()
"""

from agents.react.agent import (
    ReActSecurityAgent,
    AgentThought,
    sanitize_custom_prompt,
    MAX_CUSTOM_PROMPT_LENGTH,
    INJECTION_PATTERNS,
)

from agents.react.types import (
    AgentLimits,
    DuplicateTrackingState,
    TurnPlanningState,
    TriageState,
    RateLimitState,
)

from agents.react.dual_model import DualModelState

from agents.react.handoff import HandoffManager

from agents.react.tool_executor import (
    ToolCallTracker,
    ToolArgumentParser,
)

from agents.react.state_machine import (
    AgentProfileManager,
    TimeBudgetManager,
    PromptBuilder,
    detect_category_from_focus_areas,
)

__all__ = [
    # Main agent
    "ReActSecurityAgent",
    "AgentThought",
    "sanitize_custom_prompt",
    "MAX_CUSTOM_PROMPT_LENGTH",
    "INJECTION_PATTERNS",
    # Types
    "AgentLimits",
    "DuplicateTrackingState",
    "TurnPlanningState",
    "TriageState",
    "RateLimitState",
    # Dual model
    "DualModelState",
    # Handoff
    "HandoffManager",
    # Tool execution
    "ToolCallTracker",
    "ToolArgumentParser",
    # State machine
    "AgentProfileManager",
    "TimeBudgetManager",
    "PromptBuilder",
    "detect_category_from_focus_areas",
]
