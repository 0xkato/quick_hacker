import pytest
from models.schemas import AgentType
from services.agents import AGENT_CLASSES
from agents.deep_audit.overseer import Overseer


def test_deep_audit_mapped_to_overseer():
    """Test DEEP_AUDIT agent type maps to Overseer."""
    agent_class = AGENT_CLASSES.get(AgentType.DEEP_AUDIT)
    assert agent_class is Overseer


def test_custom_mapped_to_overseer():
    """Test CUSTOM agent type maps to Overseer."""
    agent_class = AGENT_CLASSES.get(AgentType.CUSTOM)
    assert agent_class is Overseer


def test_only_two_agent_types():
    """Test that only DEEP_AUDIT and CUSTOM agent types are supported."""
    assert len(AGENT_CLASSES) == 2
    assert AgentType.DEEP_AUDIT in AGENT_CLASSES
    assert AgentType.CUSTOM in AGENT_CLASSES
