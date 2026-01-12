import pytest
from models.schemas import AgentType
from services.agent_orchestrator import AGENT_CLASSES
from agents.deep_audit import DeepAuditSupervisor


def test_deep_audit_mapped_to_supervisor():
    """Test DEEP_AUDIT agent type maps to DeepAuditSupervisor."""
    agent_class = AGENT_CLASSES.get(AgentType.DEEP_AUDIT)
    assert agent_class is DeepAuditSupervisor


def test_strict_analysis_mapped_to_supervisor():
    """Test STRICT_ANALYSIS maps to DeepAuditSupervisor."""
    agent_class = AGENT_CLASSES.get(AgentType.STRICT_ANALYSIS)
    assert agent_class is DeepAuditSupervisor


def test_ultra_strict_mapped_to_supervisor():
    """Test ULTRA_STRICT maps to DeepAuditSupervisor."""
    agent_class = AGENT_CLASSES.get(AgentType.ULTRA_STRICT)
    assert agent_class is DeepAuditSupervisor
