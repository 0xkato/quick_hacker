# backend/tests/services/test_agent_orchestrator_cache.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call
from services.agent_orchestrator import AgentOrchestrator
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig, ProviderType
from agents.quick_audit_agent import QuickAuditAgent


class TestAgentOrchestratorCache:
    @pytest.mark.asyncio
    async def test_cache_created_when_enabled(self):
        """Test that cache is created when tool_cache_enabled=True."""
        orchestrator = AgentOrchestrator()

        # Create a mock agent
        mock_agent = MagicMock(spec=QuickAuditAgent)
        mock_agent.repo_path = "/tmp/test_repo"
        mock_agent.repo_id = "test_repo"
        mock_agent.id = "test_agent_id"
        mock_agent.request = MagicMock()
        mock_agent.request.scan_tier = "quick"
        mock_agent.request.provider_config = MagicMock()

        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = True
            mock_settings.tool_cache_max_size = 1000
            mock_settings.tool_cache_ttl_seconds = 3600

            with patch("services.agent_orchestrator.ToolCache") as mock_cache_cls:
                mock_cache_instance = MagicMock()
                mock_cache_cls.return_value = mock_cache_instance

                with patch("services.agent_orchestrator.ClaudeSDKOrchestrator") as mock_sdk_orch_cls:
                    # Mock the orchestrator instance
                    mock_sdk_orch = AsyncMock()
                    mock_sdk_orch.run_audit.return_value = {"findings": []}
                    mock_sdk_orch_cls.return_value = mock_sdk_orch

                    with patch("services.agent_orchestrator.ToolCore"):
                        with patch("services.agent_orchestrator.ClaudeSDKProvider") as mock_provider_cls:
                            # Mock the provider instance
                            mock_provider = AsyncMock()
                            mock_provider.close = AsyncMock()
                            mock_provider_cls.return_value = mock_provider

                            with patch("services.agent_orchestrator.settings_service"):
                                # Call _run_sdk_agent directly
                                await orchestrator._run_sdk_agent(mock_agent)

                                # Verify ToolCache was instantiated with correct parameters
                                mock_cache_cls.assert_called_once_with(
                                    max_size=1000,
                                    ttl_seconds=3600
                                )

    @pytest.mark.asyncio
    async def test_cache_disabled_when_config_false(self):
        """Test that ToolCache is not created when tool_cache_enabled=False."""
        orchestrator = AgentOrchestrator()

        # Create a mock agent
        mock_agent = MagicMock(spec=QuickAuditAgent)
        mock_agent.repo_path = "/tmp/test_repo"
        mock_agent.repo_id = "test_repo"
        mock_agent.id = "test_agent_id"
        mock_agent.request = MagicMock()
        mock_agent.request.scan_tier = "quick"
        mock_agent.request.provider_config = MagicMock()

        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = False

            with patch("services.agent_orchestrator.ToolCache") as mock_cache_cls:
                with patch("services.agent_orchestrator.ClaudeSDKOrchestrator") as mock_sdk_orch_cls:
                    # Mock the orchestrator instance
                    mock_sdk_orch = AsyncMock()
                    mock_sdk_orch.run_audit.return_value = {"findings": []}
                    mock_sdk_orch_cls.return_value = mock_sdk_orch

                    with patch("services.agent_orchestrator.ToolCore"):
                        with patch("services.agent_orchestrator.ClaudeSDKProvider") as mock_provider_cls:
                            # Mock the provider instance
                            mock_provider = AsyncMock()
                            mock_provider.close = AsyncMock()
                            mock_provider_cls.return_value = mock_provider

                            with patch("services.agent_orchestrator.settings_service"):
                                # Call _run_sdk_agent directly
                                await orchestrator._run_sdk_agent(mock_agent)

                                # Verify ToolCache was NOT instantiated
                                mock_cache_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_created_with_custom_settings(self):
        """Test that cache uses custom settings values."""
        orchestrator = AgentOrchestrator()

        # Create a mock agent
        mock_agent = MagicMock(spec=QuickAuditAgent)
        mock_agent.repo_path = "/tmp/test_repo"
        mock_agent.repo_id = "test_repo"
        mock_agent.id = "test_agent_id"
        mock_agent.request = MagicMock()
        mock_agent.request.scan_tier = "quick"
        mock_agent.request.provider_config = MagicMock()

        with patch("services.agent_orchestrator.settings") as mock_settings:
            mock_settings.tool_cache_enabled = True
            mock_settings.tool_cache_max_size = 500  # Custom value
            mock_settings.tool_cache_ttl_seconds = 7200  # Custom value

            with patch("services.agent_orchestrator.ToolCache") as mock_cache_cls:
                with patch("services.agent_orchestrator.ClaudeSDKOrchestrator") as mock_sdk_orch_cls:
                    # Mock the orchestrator instance
                    mock_sdk_orch = AsyncMock()
                    mock_sdk_orch.run_audit.return_value = {"findings": []}
                    mock_sdk_orch_cls.return_value = mock_sdk_orch

                    with patch("services.agent_orchestrator.ToolCore"):
                        with patch("services.agent_orchestrator.ClaudeSDKProvider") as mock_provider_cls:
                            # Mock the provider instance
                            mock_provider = AsyncMock()
                            mock_provider.close = AsyncMock()
                            mock_provider_cls.return_value = mock_provider

                            with patch("services.agent_orchestrator.settings_service"):
                                # Call _run_sdk_agent directly
                                await orchestrator._run_sdk_agent(mock_agent)

                                # Verify custom settings are used
                                mock_cache_cls.assert_called_once_with(
                                    max_size=500,
                                    ttl_seconds=7200
                                )
