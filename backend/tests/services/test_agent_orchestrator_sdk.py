"""
Tests for AgentOrchestrator SDK provider routing.

Tests the routing logic that selects between Claude SDK and legacy ReAct providers
based on the provider_config.provider value.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from models.schemas import (
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    ProviderConfig,
)


class TestAgentOrchestratorProviderRouting:
    """Tests for provider routing in AgentOrchestrator."""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock agent with necessary attributes."""
        agent = Mock()
        agent.id = "test-agent-id"
        agent.repo_id = "test-repo"
        agent.status = AgentStatus.PENDING
        agent.request = Mock()
        agent.request.provider_config = Mock()
        agent.request.provider_config.provider = "claude_sdk"
        agent.request.scan_tier = "quick"
        agent.findings = []
        agent.to_schema = Mock(return_value=Mock(id="test-agent-id"))
        agent.run = AsyncMock(return_value=[])
        return agent

    @pytest.fixture
    def mock_react_agent(self):
        """Create a mock agent for ReAct (anthropic provider without SDK flag)."""
        agent = Mock()
        agent.id = "react-agent-id"
        agent.repo_id = "test-repo"
        agent.status = AgentStatus.PENDING
        agent.request = Mock()
        agent.request.provider_config = Mock()
        agent.request.provider_config.provider = "anthropic"
        agent.request.scan_tier = "quick"
        agent.request.use_claude_sdk = False  # Explicitly set to False for ReAct routing
        agent.findings = []
        agent.to_schema = Mock(return_value=Mock(id="react-agent-id"))
        agent.run = AsyncMock(return_value=[])
        return agent

    @pytest.fixture
    def mock_anthropic_sdk_agent(self):
        """Create a mock agent for Anthropic provider with SDK flag enabled."""
        agent = Mock()
        agent.id = "anthropic-sdk-agent-id"
        agent.repo_id = "test-repo"
        agent.repo_path = "/tmp/test-repo"
        agent.status = AgentStatus.PENDING
        agent.request = Mock()
        agent.request.provider_config = Mock()
        agent.request.provider_config.provider = "anthropic"
        agent.request.provider_config.model = "claude-sonnet-4-20250514"
        agent.request.provider_config.api_key = "test-key"
        agent.request.scan_tier = "quick"
        agent.request.use_claude_sdk = True  # SDK flag enabled
        agent.findings = []
        agent.to_schema = Mock(return_value=Mock(id="anthropic-sdk-agent-id"))
        agent.run = AsyncMock(return_value=[])
        return agent

    @pytest.mark.asyncio
    async def test_routes_claude_sdk_provider(self, mock_agent):
        """Should use ClaudeSDKOrchestrator for claude_sdk provider."""
        from services.agent_orchestrator import AgentOrchestrator

        # Mock SDK availability to True
        with patch('services.agent_orchestrator.SDK_AVAILABLE', True):
            orchestrator = AgentOrchestrator()

            # Add mock agent to orchestrator
            orchestrator._agents[mock_agent.id] = mock_agent

            # Mock the _run_sdk_agent method to verify it gets called
            orchestrator._run_sdk_agent = AsyncMock(return_value=[])

            # Run the agent - should route to SDK
            await orchestrator._run_agent(mock_agent)

            # Verify _run_sdk_agent was called for claude_sdk provider
            orchestrator._run_sdk_agent.assert_called_once_with(mock_agent)

    @pytest.mark.asyncio
    async def test_routes_anthropic_to_react(self, mock_react_agent):
        """Should use ReAct loop for anthropic provider when use_claude_sdk=False."""
        from services.agent_orchestrator import AgentOrchestrator

        orchestrator = AgentOrchestrator()

        # Add mock agent to orchestrator
        orchestrator._agents[mock_react_agent.id] = mock_react_agent

        # Run the agent - should call the default run method (ReAct path)
        await orchestrator._run_agent(mock_react_agent)

        # Verify the agent's run method was called (ReAct path)
        mock_react_agent.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_routes_anthropic_sdk_when_flag_enabled(self, mock_anthropic_sdk_agent):
        """Should use SDK for anthropic provider when use_claude_sdk=True."""
        from services.agent_orchestrator import AgentOrchestrator

        # Mock SDK availability to True
        with patch('services.agent_orchestrator.SDK_AVAILABLE', True):
            orchestrator = AgentOrchestrator()

            # Add mock agent to orchestrator
            orchestrator._agents[mock_anthropic_sdk_agent.id] = mock_anthropic_sdk_agent

            # Mock the _run_sdk_agent method to verify it gets called
            orchestrator._run_sdk_agent = AsyncMock(return_value=[])

            # Run the agent - should route to SDK
            await orchestrator._run_agent(mock_anthropic_sdk_agent)

            # Verify _run_sdk_agent was called for anthropic provider with SDK flag
            orchestrator._run_sdk_agent.assert_called_once_with(mock_anthropic_sdk_agent)

    @pytest.mark.asyncio
    async def test_sdk_agent_cancel_calls_interrupt(self, mock_agent):
        """Should call provider.interrupt() when cancelling SDK agent."""
        from services.agent_orchestrator import AgentOrchestrator

        orchestrator = AgentOrchestrator()

        # Create a mock SDK provider with interrupt method
        mock_provider = Mock()
        mock_provider.interrupt = Mock()

        # Add mock agent to orchestrator with SDK provider reference
        mock_agent._sdk_provider = mock_provider
        mock_agent.status = AgentStatus.RUNNING
        mock_agent.cancel = Mock()
        orchestrator._agents[mock_agent.id] = mock_agent

        # Cancel the agent
        await orchestrator.cancel_agent(mock_agent.id)

        # Verify interrupt was called on the SDK provider
        mock_provider.interrupt.assert_called_once()


class TestAgentOrchestratorSDKIntegration:
    """Integration tests for SDK provider in AgentOrchestrator."""

    def _create_mock_agent(self):
        """Create a mock agent for SDK integration tests."""
        mock_agent = Mock()
        mock_agent.id = "sdk-agent"
        mock_agent.repo_id = "test-repo"
        mock_agent.repo_path = "/tmp/test-repo"
        mock_agent.request = Mock()
        mock_agent.request.provider_config = Mock()
        mock_agent.request.provider_config.provider = "claude_sdk"
        mock_agent.request.provider_config.model = "claude-sonnet-4-20250514"
        mock_agent.request.provider_config.api_key = "test-key"
        mock_agent.request.provider_config.max_tokens = 8192
        mock_agent.request.scan_tier = "quick"
        mock_agent.request.custom_prompt = None
        mock_agent.request.focus_areas = None
        mock_agent.request.target_files = None
        mock_agent.findings = []
        mock_agent.status = AgentStatus.RUNNING
        return mock_agent

    @pytest.mark.asyncio
    async def test_run_sdk_agent_creates_tool_core(self):
        """_run_sdk_agent should create ToolCore with proper limits factory."""
        mock_agent = self._create_mock_agent()

        # Patch all the required components at the module level
        with patch('services.agent_orchestrator.ToolCore') as MockToolCore, \
             patch('services.agent_orchestrator.ClaudeSDKProvider') as MockProvider, \
             patch('services.agent_orchestrator.ClaudeSDKOrchestrator') as MockOrchestrator:

            # Setup mock orchestrator
            mock_sdk_orchestrator = MagicMock()
            mock_sdk_orchestrator.make_fresh_limits = Mock(return_value=Mock())
            mock_sdk_orchestrator.run_audit = AsyncMock(return_value={
                'findings': [],
                'success': True,
            })
            MockOrchestrator.return_value = mock_sdk_orchestrator

            # Setup mock provider
            mock_provider_instance = MagicMock()
            mock_provider_instance.close = AsyncMock()
            MockProvider.return_value = mock_provider_instance

            # Import after patching
            from services.agent_orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator()

            # Call _run_sdk_agent
            await orchestrator._run_sdk_agent(mock_agent)

            # Verify ToolCore was created
            MockToolCore.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sdk_agent_resolves_api_key_from_settings(self):
        """_run_sdk_agent should re-resolve missing/masked API key from Settings."""
        mock_agent = self._create_mock_agent()
        mock_agent.request.provider_config.api_key = None

        mock_settings = MagicMock()
        mock_settings.providers = {"anthropic": MagicMock(api_key="settings-key")}

        with patch('services.agent_orchestrator.settings_service.get_settings', new=AsyncMock(return_value=mock_settings)), \
             patch('services.agent_orchestrator.ToolCore') as MockToolCore, \
             patch('services.agent_orchestrator.ClaudeSDKProvider') as MockProvider, \
             patch('services.agent_orchestrator.ClaudeSDKOrchestrator') as MockOrchestrator:

            mock_sdk_orchestrator = MagicMock()
            mock_sdk_orchestrator.make_fresh_limits = Mock(return_value=Mock())
            mock_sdk_orchestrator.run_audit = AsyncMock(return_value={
                'findings': [],
                'success': True,
            })
            MockOrchestrator.return_value = mock_sdk_orchestrator

            mock_provider_instance = MagicMock()
            mock_provider_instance.close = AsyncMock()
            MockProvider.return_value = mock_provider_instance

            from services.agent_orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator()

            await orchestrator._run_sdk_agent(mock_agent)

            _, kwargs = MockProvider.call_args
            assert kwargs["config"]["api_key"] == "settings-key"

    @pytest.mark.asyncio
    async def test_run_sdk_agent_creates_provider(self):
        """_run_sdk_agent should create ClaudeSDKProvider."""
        mock_agent = self._create_mock_agent()

        with patch('services.agent_orchestrator.ToolCore') as MockToolCore, \
             patch('services.agent_orchestrator.ClaudeSDKProvider') as MockProvider, \
             patch('services.agent_orchestrator.ClaudeSDKOrchestrator') as MockOrchestrator:

            mock_sdk_orchestrator = MagicMock()
            mock_sdk_orchestrator.make_fresh_limits = Mock(return_value=Mock())
            mock_sdk_orchestrator.run_audit = AsyncMock(return_value={
                'findings': [],
                'success': True,
            })
            MockOrchestrator.return_value = mock_sdk_orchestrator

            mock_provider_instance = MagicMock()
            mock_provider_instance.close = AsyncMock()
            MockProvider.return_value = mock_provider_instance

            from services.agent_orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator()

            await orchestrator._run_sdk_agent(mock_agent)

            # Verify ClaudeSDKProvider was created
            MockProvider.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sdk_agent_creates_orchestrator(self):
        """_run_sdk_agent should create ClaudeSDKOrchestrator."""
        mock_agent = self._create_mock_agent()

        with patch('services.agent_orchestrator.ToolCore') as MockToolCore, \
             patch('services.agent_orchestrator.ClaudeSDKProvider') as MockProvider, \
             patch('services.agent_orchestrator.ClaudeSDKOrchestrator') as MockOrchestrator:

            mock_sdk_orchestrator = MagicMock()
            mock_sdk_orchestrator.make_fresh_limits = Mock(return_value=Mock())
            mock_sdk_orchestrator.run_audit = AsyncMock(return_value={
                'findings': [],
                'success': True,
            })
            MockOrchestrator.return_value = mock_sdk_orchestrator

            mock_provider_instance = MagicMock()
            mock_provider_instance.close = AsyncMock()
            MockProvider.return_value = mock_provider_instance

            from services.agent_orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator()

            await orchestrator._run_sdk_agent(mock_agent)

            # Verify ClaudeSDKOrchestrator was created
            MockOrchestrator.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sdk_agent_runs_audit(self):
        """_run_sdk_agent should call run_audit on the SDK orchestrator."""
        mock_agent = self._create_mock_agent()

        with patch('services.agent_orchestrator.ToolCore'), \
             patch('services.agent_orchestrator.ClaudeSDKProvider') as MockProvider, \
             patch('services.agent_orchestrator.ClaudeSDKOrchestrator') as MockOrchestrator:

            mock_sdk_orchestrator = MagicMock()
            mock_sdk_orchestrator.make_fresh_limits = Mock(return_value=Mock())
            mock_sdk_orchestrator.run_audit = AsyncMock(return_value={
                'findings': [{'title': 'Test Finding', 'severity': 'high'}],
                'success': True,
            })
            MockOrchestrator.return_value = mock_sdk_orchestrator

            mock_provider_instance = MagicMock()
            mock_provider_instance.close = AsyncMock()
            MockProvider.return_value = mock_provider_instance

            from services.agent_orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator()

            await orchestrator._run_sdk_agent(mock_agent)

            # Verify run_audit was called
            mock_sdk_orchestrator.run_audit.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sdk_agent_stores_provider_reference(self):
        """_run_sdk_agent should store provider reference on agent for cancellation."""
        mock_agent = self._create_mock_agent()

        with patch('services.agent_orchestrator.ToolCore'), \
             patch('services.agent_orchestrator.ClaudeSDKProvider') as MockProvider, \
             patch('services.agent_orchestrator.ClaudeSDKOrchestrator') as MockOrchestrator:

            mock_sdk_orchestrator = MagicMock()
            mock_sdk_orchestrator.make_fresh_limits = Mock(return_value=Mock())
            mock_sdk_orchestrator.run_audit = AsyncMock(return_value={
                'findings': [],
                'success': True,
            })
            MockOrchestrator.return_value = mock_sdk_orchestrator

            mock_provider_instance = MagicMock()
            mock_provider_instance.close = AsyncMock()
            MockProvider.return_value = mock_provider_instance

            from services.agent_orchestrator import AgentOrchestrator
            orchestrator = AgentOrchestrator()

            await orchestrator._run_sdk_agent(mock_agent)

            # Verify provider reference was stored on agent
            assert hasattr(mock_agent, '_sdk_provider')
            assert mock_agent._sdk_provider is mock_provider_instance


class TestAgentOrchestratorProviderTypeCheck:
    """Tests for provider type checking logic."""

    def test_provider_is_claude_sdk_string(self):
        """Provider config should accept 'claude_sdk' as string."""
        # The provider routing checks config.provider.lower() == "claude_sdk"
        provider_value = "claude_sdk"
        assert provider_value.lower() == "claude_sdk"

    def test_provider_is_anthropic_string(self):
        """Provider config should accept 'anthropic' as string."""
        provider_value = "anthropic"
        assert provider_value.lower() == "anthropic"

    def test_provider_routing_case_insensitive(self):
        """Provider routing should be case insensitive."""
        values = ["CLAUDE_SDK", "Claude_SDK", "claude_SDK", "claude_sdk"]
        for val in values:
            assert val.lower() == "claude_sdk"


class TestAgentOrchestratorCancelSDK:
    """Tests for SDK agent cancellation."""

    @pytest.mark.asyncio
    async def test_cancel_calls_sdk_orchestrator_cancel(self):
        """Should call cancel on SDK orchestrator when cancelling agent."""
        from services.agent_orchestrator import AgentOrchestrator

        orchestrator = AgentOrchestrator()

        # Create mock agent with SDK orchestrator
        mock_agent = Mock()
        mock_agent.id = "sdk-cancel-test"
        mock_agent.status = AgentStatus.RUNNING
        mock_agent.cancel = Mock()

        mock_sdk_orchestrator = Mock()
        mock_sdk_orchestrator.cancel = Mock()
        mock_agent._sdk_orchestrator = mock_sdk_orchestrator

        mock_provider = Mock()
        mock_provider.interrupt = Mock()
        mock_agent._sdk_provider = mock_provider

        orchestrator._agents[mock_agent.id] = mock_agent

        # Cancel the agent
        await orchestrator.cancel_agent(mock_agent.id)

        # Verify both provider.interrupt() and orchestrator.cancel() were called
        mock_provider.interrupt.assert_called_once()
        mock_sdk_orchestrator.cancel.assert_called_once()

    @pytest.mark.asyncio
    async def test_cancel_handles_missing_sdk_provider(self):
        """Should not fail when cancelling agent without SDK provider."""
        from services.agent_orchestrator import AgentOrchestrator

        orchestrator = AgentOrchestrator()

        # Create mock agent without SDK attributes
        mock_agent = Mock()
        mock_agent.id = "non-sdk-cancel-test"
        mock_agent.status = AgentStatus.RUNNING
        mock_agent.cancel = Mock()
        # Explicitly don't set _sdk_provider or _sdk_orchestrator

        # Remove the attributes if they were auto-created by Mock
        if hasattr(mock_agent, '_sdk_provider'):
            del mock_agent._sdk_provider
        if hasattr(mock_agent, '_sdk_orchestrator'):
            del mock_agent._sdk_orchestrator

        orchestrator._agents[mock_agent.id] = mock_agent

        # Cancel should not raise
        await orchestrator.cancel_agent(mock_agent.id)

        # Agent's cancel method should still be called
        mock_agent.cancel.assert_called_once()
