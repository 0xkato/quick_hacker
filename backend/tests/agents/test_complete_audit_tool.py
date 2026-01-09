import pytest
from agents.tools import AGENT_TOOLS, COMPLETE_AUDIT_SCHEMA

def test_complete_audit_schema_exists():
    """complete_audit tool should be in AGENT_TOOLS."""
    tool_names = [t["name"] for t in AGENT_TOOLS]
    assert "complete_audit" in tool_names

def test_complete_audit_schema_structure():
    """complete_audit schema should have required parameters."""
    schema = COMPLETE_AUDIT_SCHEMA
    assert schema["name"] == "complete_audit"
    params = schema["parameters"]["properties"]
    assert "outcome" in params
    assert "summary" in params
    assert "coverage_acknowledgment" in params
