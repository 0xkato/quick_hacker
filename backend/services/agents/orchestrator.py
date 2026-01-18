"""Main agent orchestration coordinator."""

import warnings

# Import from old location with deprecation warning suppressed
# (We'll add deprecation to the old file later)
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    # Import the entire AgentOrchestrator class from the original file
    # This maintains 100% backward compatibility while we migrate
    from services.agent_orchestrator import AgentOrchestrator as _LegacyAgentOrchestrator


# For now, just re-export the legacy orchestrator
# In a future phase, we can progressively refactor the _run_sdk_agent and _run_codex_cli_agent methods
AgentOrchestrator = _LegacyAgentOrchestrator


__all__ = ["AgentOrchestrator"]
