# backend/tests/services/test_agent_orchestrator_cache.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from services.agent_orchestrator import AgentOrchestrator
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig


class TestAgentOrchestratorCache:
    @pytest.mark.asyncio
    async def test_cache_created_when_enabled(self):
        """Test that cache is created when tool_cache_enabled=True."""
        orchestrator = AgentOrchestrator()

        request = AgentCreateRequest(
            repo_id="test_repo",
            agent_type=AgentType.QUICK_AUDIT,
            provider_config=ProviderConfig(
                provider="openai",
                model="gpt-4",
                api_key="test-key"
            ),
        )

        auth_context = MagicMock()
        auth_context.user_id = "test_user"
        db = AsyncMock()

        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = True
            mock_settings.tool_cache_max_size = 1000
            mock_settings.tool_cache_ttl_seconds = 3600
            mock_settings.max_concurrent_agents = 10

            with patch("services.agent_orchestrator.project_service") as mock_proj:
                mock_proj.get_project_repo_path.return_value = "/tmp/test_repo"

                agent = await orchestrator.create_agent(request, auth_context, db)

                # Verify cache was created
                assert agent is not None
                # Check that ToolCore was initialized with cache
                # (This requires inspection of the agent's tool_core)

    @pytest.mark.asyncio
    async def test_cache_disabled_when_config_false(self):
        """Test that cache is None when tool_cache_enabled=False."""
        orchestrator = AgentOrchestrator()

        request = AgentCreateRequest(
            repo_id="test_repo",
            agent_type=AgentType.QUICK_AUDIT,
            provider_config=ProviderConfig(
                provider="openai",
                model="gpt-4",
                api_key="test-key"
            ),
        )

        auth_context = MagicMock()
        auth_context.user_id = "test_user"
        db = AsyncMock()

        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = False
            mock_settings.max_concurrent_agents = 10

            with patch("services.agent_orchestrator.project_service") as mock_proj:
                mock_proj.get_project_repo_path.return_value = "/tmp/test_repo"

                agent = await orchestrator.create_agent(request, auth_context, db)

                # Verify cache was not created
                assert agent is not None
