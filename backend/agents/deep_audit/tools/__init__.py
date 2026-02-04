"""Overseer tools for Deep Agents orchestration.

Tool Categories:

Dispatch Tools (dispatch.py):
- dispatch_foundation_phase(): Run Foundation Phase (MUST be called first)
- dispatch_wave(): Dispatch a wave of parallel sub-agents
- dispatch_agent(): Dispatch a single sub-agent

Memory Tools (memories.py):
- read_memories(): Read artifacts from /memories/
- list_memories(): List directory contents in /memories/
- write_synthesis(): Write wave synthesis document
- write_artifact(): Write arbitrary artifact to /memories/

Finalize Tools (finalize.py):
- update_campaign_state(): Update CampaignState with new data
- finalize_report(): Generate final report at end of campaign

Tool Registration:
Tools are registered with the Overseer via _init_tools() which sets:
- Dispatcher reference for dispatch tools
- Filesystem reference for memory and finalize tools
- CampaignState reference for finalize tools
"""

from agents.deep_audit.tools.dispatch import dispatch_wave, dispatch_agent, dispatch_foundation_phase
from agents.deep_audit.tools.memories import read_memories, write_synthesis, list_memories, write_artifact
from agents.deep_audit.tools.finalize import finalize_report, update_campaign_state

# Re-export legacy signal tools for backward compatibility
from agents.deep_audit.signal_tools import upsert_sink_signals, promote_finding

__all__ = [
    # Overseer tools
    "dispatch_wave",
    "dispatch_agent",
    "dispatch_foundation_phase",
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
