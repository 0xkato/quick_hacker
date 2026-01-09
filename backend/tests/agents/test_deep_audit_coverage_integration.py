import json
import pytest
from unittest.mock import Mock, AsyncMock, patch
from agents.deep_audit_agent import DeepAuditAgent, AuditState
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


@pytest.mark.asyncio
async def test_agent_handles_trace_path_verdict():
    """DeepAuditAgent should update coverage when trace_path_verdict is called."""
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

    agent.state = AuditState(run_id="test-run")
    agent.state.budgets = {"tc_rem": 100}

    # Simulate trace_path_verdict tool call
    tool_calls = [{
        "name": "trace_path_verdict",
        "arguments": json.dumps({
            "entry_point_file": "routes/api.py",
            "entry_point_line": 25,
            "sink_file": "db/queries.py",
            "sink_line": 100,
            "verdict": "safe",
            "reasoning": "Input is properly parameterized",
            "files_examined": ["routes/api.py", "db/queries.py"]
        })
    }]

    await agent._process_tool_calls(tool_calls)

    # Check coverage was updated
    stats = agent.coverage_tracker.get_coverage_stats()
    assert stats.total_paths == 1
    assert stats.traced_safe_count == 1
