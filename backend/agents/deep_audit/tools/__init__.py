"""Overseer tools for Deep Agents orchestration."""

from agents.deep_audit.tools.dispatch import dispatch_wave, dispatch_agent
from agents.deep_audit.tools.memories import read_memories, write_synthesis, list_memories, write_artifact
from agents.deep_audit.tools.finalize import finalize_report, update_campaign_state

# Re-export legacy signal tools for backward compatibility
from agents.deep_audit.signal_tools import upsert_sink_signals, promote_finding

__all__ = [
    # Overseer tools
    "dispatch_wave",
    "dispatch_agent",
    "read_memories",
    "write_synthesis",
    "list_memories",
    "write_artifact",
    "finalize_report",
    "update_campaign_state",
    # Legacy signal tools
    "upsert_sink_signals",
    "promote_finding",
]
