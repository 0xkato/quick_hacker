"""ReAct state machine for investigation management.

This module provides state management helpers for the ReAct agent,
including profile application, time budgets, and configuration.
"""

from typing import Optional
from models.schemas import AgentType, AgentCreateRequest
from agents.react.types import AgentLimits


class AgentProfileManager:
    """Manages agent profile configuration based on agent type."""

    @staticmethod
    def apply_agent_profile(
        agent_type: AgentType, limits: AgentLimits
    ) -> AgentLimits:
        """
        Apply agent profile to configure limits based on agent type.

        Args:
            agent_type: Type of agent
            limits: Current agent limits

        Returns:
            Updated agent limits
        """
        if agent_type == AgentType.DEEP_AUDIT:
            # Long-running, coverage-oriented mode
            limits.max_runtime_seconds = 60 * 60  # 1 hour
            limits.max_iterations = 10_000  # Time-boxed by max_runtime_seconds
            limits.max_tool_calls_per_iteration = 8
            limits.triage_render_limit = 40
            limits.triage_prompt_limit = 20
            limits.auto_queue_limit = 8
            limits.audit_complete_confirmations_required = 2
            return limits

        # NOTE: STRICT_ANALYSIS, ULTRA_STRICT, TARGETED_SCAN, and QUICK_SCAN
        # agent types have been removed. All agents now use deep_audit which
        # provides proper diagramming support and better investigation capabilities.

        # Default: keep current limits (effectively deep_audit behavior)
        return limits


class TimeBudgetManager:
    """Manages time budget configuration for agents."""

    @staticmethod
    def apply_time_budget(
        time_budget_seconds: Optional[int],
        scan_tier: Optional[str],
        limits: AgentLimits,
    ) -> AgentLimits:
        """
        Apply time budget to agent limits.

        Args:
            time_budget_seconds: Explicit time budget in seconds
            scan_tier: Scan tier (fast/thorough/exhaustive)
            limits: Current agent limits

        Returns:
            Updated agent limits
        """
        # Explicit time budget takes precedence
        if time_budget_seconds is not None and time_budget_seconds > 0:
            limits.max_runtime_seconds = time_budget_seconds
            limits.min_runtime_seconds = None
            return limits

        # Tier-based defaults
        if scan_tier == "fast":
            limits.max_runtime_seconds = 5 * 60  # 5 minutes
            limits.max_iterations = 50
            return limits
        elif scan_tier == "thorough":
            limits.max_runtime_seconds = 15 * 60  # 15 minutes
            limits.min_runtime_seconds = 5 * 60  # Force at least 5 minutes
            limits.max_iterations = 200
            return limits
        elif scan_tier == "exhaustive":
            limits.max_runtime_seconds = 60 * 60  # 1 hour
            limits.min_runtime_seconds = 15 * 60  # Force at least 15 minutes
            limits.max_iterations = 1000
            return limits

        # No changes
        return limits


class PromptBuilder:
    """Builds prompts with agent-specific appendixes."""

    @staticmethod
    def profile_prompt_appendix(agent_type: AgentType) -> str:
        """Get profile-specific prompt appendix."""
        # All agents now use deep_audit - no special appendix needed
        # The deep_audit profile is loaded from profile_deep_audit_mode.md
        return ""

    @staticmethod
    def time_tier_prompt_appendix(scan_tier: Optional[str]) -> str:
        """Get tier-specific prompt appendix."""
        if scan_tier == "fast":
            return "\n\nTime Budget: FAST scan - prioritize breadth over depth."
        elif scan_tier == "thorough":
            return "\n\nTime Budget: THOROUGH scan - balance breadth and depth."
        elif scan_tier == "exhaustive":
            return "\n\nTime Budget: EXHAUSTIVE scan - maximize coverage and depth."
        return ""

    @staticmethod
    def audit_completion_confirmation_prompt(confirmations_required: int) -> str:
        """Get audit completion confirmation prompt."""
        if confirmations_required > 1:
            return (
                "\n\nBefore saying AUDIT_COMPLETE, make sure you've:\n"
                "1. Thoroughly explored the codebase\n"
                "2. Investigated all suspicious patterns\n"
                "3. Validated or ruled out potential vulnerabilities\n"
                "If you have more to investigate, continue working."
            )
        return ""


def detect_category_from_focus_areas(focus_areas: list[str]) -> Optional[str]:
    """
    Detect vulnerability category from focus areas.

    Args:
        focus_areas: List of focus areas

    Returns:
        Detected category or None
    """
    if not focus_areas:
        return None

    focus_text = " ".join(focus_areas).lower()

    if any(
        kw in focus_text
        for kw in ["sql", "injection", "sqli", "command injection", "code injection"]
    ):
        return "injection"
    elif any(kw in focus_text for kw in ["xss", "cross-site", "script injection"]):
        return "xss"
    elif any(
        kw in focus_text for kw in ["auth", "authentication", "authorization", "access control"]
    ):
        return "auth"
    elif any(kw in focus_text for kw in ["crypto", "encryption", "hash", "password"]):
        return "crypto"
    elif any(kw in focus_text for kw in ["path traversal", "directory traversal", "lfi"]):
        return "path_traversal"

    return None
