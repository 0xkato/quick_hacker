import json
import pytest
from unittest.mock import Mock, AsyncMock, patch
from agents.deep_audit_agent import DeepAuditAgent, AuditState
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig, ProviderType
from services.coverage_tracker import CoverageTracker, PathStatus

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


@pytest.mark.asyncio
async def test_complete_audit_rejected_when_no_coverage():
    """complete_audit should be rejected when coverage requirements not met."""
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
    agent.state.iteration = 5  # Too few iterations

    # Simulate complete_audit tool call
    tool_calls = [{
        "name": "complete_audit",
        "arguments": json.dumps({
            "outcome": "no_findings",
            "summary": "No vulnerabilities found",
            "coverage_acknowledgment": True
        })
    }]

    await agent._process_tool_calls(tool_calls)

    # Agent should NOT have completion flag set
    assert not agent._completion_approved


@pytest.mark.asyncio
async def test_complete_audit_accepted_when_requirements_met():
    """complete_audit should be accepted when all requirements are met."""
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
    agent.state.iteration = 15  # Enough iterations

    # Add some coverage
    path_id = agent.coverage_tracker.register_path(
        "a.py", 10, "handler", "b.py", 20, "sql", "execute"
    )
    agent.coverage_tracker.update_status(path_id, PathStatus.TRACED_SAFE)

    # Add examined files
    agent.files_examined = {"a.py", "b.py", "c.py", "d.py", "e.py"}

    # Simulate complete_audit tool call
    tool_calls = [{
        "name": "complete_audit",
        "arguments": json.dumps({
            "outcome": "no_findings",
            "summary": "Thoroughly reviewed, no vulnerabilities",
            "coverage_acknowledgment": True
        })
    }]

    await agent._process_tool_calls(tool_calls)

    # Agent should have completion flag set
    assert agent._completion_approved


def test_string_completion_detection_removed():
    """The old string-based completion detection should be removed."""
    import inspect
    from agents.deep_audit_agent import DeepAuditAgent

    # Get the source code of _audit_loop
    source = inspect.getsource(DeepAuditAgent._audit_loop)

    # These patterns should NOT be in the code anymore
    # The old code checked: if "FINAL OUTCOME" in content or "Case A:" in content ...
    assert '"FINAL OUTCOME" in content' not in source
    assert '"Case A:" in content' not in source
