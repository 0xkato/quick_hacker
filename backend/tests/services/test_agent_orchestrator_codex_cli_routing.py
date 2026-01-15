from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest

from models.schemas import AgentStatus


@pytest.mark.asyncio
async def test_run_agent_routes_codex_cli_to_codex_runner():
    from services.agent_orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator()

    mock_agent = Mock()
    mock_agent.id = "codex-agent-id"
    mock_agent.repo_id = "proj"
    mock_agent.status = AgentStatus.PENDING
    mock_agent.request = Mock()
    mock_agent.request.provider_config = Mock()
    mock_agent.request.provider_config.provider = "codex_cli"
    mock_agent.request.scan_tier = "quick"
    mock_agent.findings = []
    mock_agent.to_schema = Mock(return_value=Mock(id="codex-agent-id"))
    mock_agent.run = AsyncMock(return_value=[])

    orchestrator._agents[mock_agent.id] = mock_agent
    orchestrator._run_codex_cli_agent = AsyncMock(return_value=[])

    await orchestrator._run_agent(mock_agent)

    orchestrator._run_codex_cli_agent.assert_called_once_with(mock_agent)


@pytest.mark.asyncio
async def test_cancel_agent_interrupts_codex_provider():
    from services.agent_orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator()

    mock_agent = Mock()
    mock_agent.id = "codex-cancel-id"
    mock_agent.status = AgentStatus.RUNNING
    mock_agent.cancel = Mock()

    mock_provider = Mock()
    mock_provider.interrupt = AsyncMock()
    mock_agent._codex_provider = mock_provider

    orchestrator._agents[mock_agent.id] = mock_agent

    await orchestrator.cancel_agent(mock_agent.id)

    mock_provider.interrupt.assert_called_once()


@pytest.mark.asyncio
async def test_pause_agent_interrupts_codex_provider():
    from services.agent_orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator()

    mock_provider = Mock()
    mock_provider.interrupt = AsyncMock()

    mock_agent = Mock(spec_set=["id", "status", "pause", "to_schema", "_codex_provider"])
    mock_agent.id = "codex-pause-id"
    mock_agent.status = AgentStatus.RUNNING
    mock_agent.pause = Mock()
    mock_agent.to_schema = Mock(return_value=Mock(id="codex-pause-id"))
    mock_agent._codex_provider = mock_provider

    orchestrator._agents[mock_agent.id] = mock_agent

    await orchestrator.pause_agent(mock_agent.id)

    mock_provider.interrupt.assert_called_once()
