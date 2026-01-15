# backend/tests/services/test_agent_orchestrator_cache.py
import pytest
from unittest.mock import MagicMock, patch
from services.agent_orchestrator import AgentOrchestrator


class TestAgentOrchestratorCache:
    @pytest.mark.asyncio
    async def test_cache_created_when_enabled(self):
        """ToolCache should be created once on orchestrator init when enabled."""
        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = True
            mock_settings.tool_cache_max_size = 1000
            mock_settings.tool_cache_ttl_seconds = 3600

            with patch("services.agent_orchestrator.ToolCache") as mock_cache_cls:
                mock_cache_instance = MagicMock()
                mock_cache_cls.return_value = mock_cache_instance

                orchestrator = AgentOrchestrator()
                assert orchestrator._shared_cache is mock_cache_instance
                mock_cache_cls.assert_called_once_with(max_size=1000, ttl_seconds=3600)

    @pytest.mark.asyncio
    async def test_cache_disabled_when_config_false(self):
        """ToolCache should not be created on init when disabled."""
        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = False

            with patch("services.agent_orchestrator.ToolCache") as mock_cache_cls:
                orchestrator = AgentOrchestrator()
                assert orchestrator._shared_cache is None
                mock_cache_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_created_with_custom_settings(self):
        """ToolCache should respect custom settings values."""
        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = True
            mock_settings.tool_cache_max_size = 500  # Custom value
            mock_settings.tool_cache_ttl_seconds = 7200  # Custom value

            with patch("services.agent_orchestrator.ToolCache") as mock_cache_cls:
                mock_cache_instance = MagicMock()
                mock_cache_cls.return_value = mock_cache_instance

                orchestrator = AgentOrchestrator()
                assert orchestrator._shared_cache is mock_cache_instance
                mock_cache_cls.assert_called_once_with(max_size=500, ttl_seconds=7200)
