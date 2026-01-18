"""Agent orchestration services.

This package provides focused modules for agent management:
- orchestrator: Main coordinator for agent execution
- lifecycle: Agent creation, pause, resume, cancel
- broadcaster: WebSocket event broadcasting
- tool_cache: Shared tool result caching (from services.tool_cache)
- budget_manager: Tool budget management (from services.tool_budget_manager)
"""

# For now, import from the original location to maintain backward compatibility
# The refactoring will be done incrementally in future phases
from services.agent_orchestrator import AgentOrchestrator, orchestrator

# Import the new focused modules
from .broadcaster import AgentBroadcaster
from .lifecycle import AgentLifecycleManager, AGENT_CLASSES

# Re-export from services for convenience
from services.tool_cache import ToolCache
from services.tool_budget_manager import ToolBudgetManager

__all__ = [
    "AgentOrchestrator",
    "orchestrator",
    "AgentBroadcaster",
    "AgentLifecycleManager",
    "AGENT_CLASSES",
    "ToolCache",
    "ToolBudgetManager",
]
