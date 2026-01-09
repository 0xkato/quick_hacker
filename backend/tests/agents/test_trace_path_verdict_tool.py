import pytest
from agents.tools import AGENT_TOOLS

def test_trace_path_verdict_in_agent_tools():
    """trace_path_verdict should be in AGENT_TOOLS list."""
    tool_names = [t["name"] for t in AGENT_TOOLS]
    assert "trace_path_verdict" in tool_names
