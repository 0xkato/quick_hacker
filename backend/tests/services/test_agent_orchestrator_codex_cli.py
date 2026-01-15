from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from models.schemas import AgentCreateRequest, AgentType, ProviderConfig, ProviderType


@pytest.mark.asyncio
async def test_create_agent_allows_codex_cli_without_api_key(tmp_path):
    """codex_cli provider should not require an API key at agent creation time."""
    from services.agent_orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator()

    request = AgentCreateRequest(
        repo_id="proj123",
        agent_type=AgentType.QUICK_AUDIT,
        provider_config=ProviderConfig(provider=ProviderType.CODEX_CLI, model="gpt-5.2-codex", api_key=None),
        scan_tier="quick",
    )

    auth_context = Mock()
    db = Mock()

    with patch("services.agent_orchestrator.project_service") as mock_project_service, \
         patch("services.agent_orchestrator.get_user_api_key_for_provider", new=AsyncMock(return_value=None)):
        mock_project_service.get_project_repo_path.return_value = str(tmp_path)
        agent = await orchestrator.create_agent(request, auth_context, db)

    assert agent.provider_config.provider == ProviderType.CODEX_CLI


@pytest.mark.asyncio
async def test_create_custom_agent_allows_codex_cli_without_api_provider(tmp_path):
    """AgentType.CUSTOM uses ReActSecurityAgent; codex_cli must not require get_provider()."""
    from services.agent_orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator()

    request = AgentCreateRequest(
        repo_id="proj_custom_codex",
        agent_type=AgentType.CUSTOM,
        provider_config=ProviderConfig(provider=ProviderType.CODEX_CLI, model="gpt-5.2-codex", api_key=None),
        time_budget_seconds=60,
    )

    auth_context = Mock()
    db = Mock()

    with patch("services.agent_orchestrator.project_service") as mock_project_service, patch(
        "services.agent_orchestrator.get_user_api_key_for_provider",
        new=AsyncMock(return_value=None),
    ):
        mock_project_service.get_project_repo_path.return_value = str(tmp_path)
        agent = await orchestrator.create_agent(request, auth_context, db)

    assert agent.provider_config.provider == ProviderType.CODEX_CLI
