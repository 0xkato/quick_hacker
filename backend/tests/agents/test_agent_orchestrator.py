import pytest
from models.schemas import AgentType
from services.agents import AGENT_CLASSES
from agents.deep_audit import DeepAuditSupervisor


def test_deep_audit_mapped_to_supervisor():
    """Test DEEP_AUDIT agent type maps to DeepAuditSupervisor."""
    agent_class = AGENT_CLASSES.get(AgentType.DEEP_AUDIT)
    assert agent_class is DeepAuditSupervisor


def test_custom_mapped_to_supervisor():
    """Test CUSTOM agent type maps to DeepAuditSupervisor (simplified agent system)."""
    agent_class = AGENT_CLASSES.get(AgentType.CUSTOM)
    assert agent_class is DeepAuditSupervisor


def test_only_two_agent_types():
    """Test that only DEEP_AUDIT and CUSTOM agent types are supported."""
    assert len(AGENT_CLASSES) == 2
    assert AgentType.DEEP_AUDIT in AGENT_CLASSES
    assert AgentType.CUSTOM in AGENT_CLASSES
