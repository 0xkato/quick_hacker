import pytest
from unittest.mock import Mock, AsyncMock, patch
from agents.deep_audit_agent import DeepAuditAgent
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig, ProviderType
from services.coverage_tracker import CoverageTracker

def test_agent_has_coverage_tracker():
    """DeepAuditAgent should initialize a CoverageTracker."""
    request = AgentCreateRequest(
        repo_id="test-repo",
        name="test-audit",
        agent_type=AgentType.DEEP_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-sonnet-4-20250514",
            api_key="test-key"
        )
    )
    with patch('agents.deep_audit_agent.get_provider') as mock_get_provider:
        mock_get_provider.return_value = Mock()
        agent = DeepAuditAgent(request, "/tmp/test-repo")

    assert hasattr(agent, 'coverage_tracker')
    assert isinstance(agent.coverage_tracker, CoverageTracker)
