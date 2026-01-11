# backend/tests/providers/test_claude_sdk_provider.py
"""Tests for ClaudeSDKProvider - wraps ClaudeSDKClient for native agent loop."""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch


class TestClaudeSDKProviderInit:
    """Tests for ClaudeSDKProvider initialization."""

    def test_init_stores_config(self, tmp_path):
        """Should store configuration in instance."""
        from providers.claude_sdk_provider import ClaudeSDKProvider
        from services.tool_core import ToolCore

        repo = tmp_path / "repo"
        repo.mkdir()
        tool_core = ToolCore(repo_path=str(repo), project_id="test-project")

        config = {
            "model": "claude-sonnet-4-20250514",
            "api_key": "test-key",
            "max_tokens": 8192,
        }

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=tool_core,
            config=config,
        )

        assert provider.repo_path == str(repo)
        assert provider.project_id == "test-project"
        assert provider.tool_core is tool_core
        assert provider.config == config

    def test_init_no_client_yet(self, tmp_path):
        """Client should not be created until start_session is called."""
        from providers.claude_sdk_provider import ClaudeSDKProvider
        from services.tool_core import ToolCore

        repo = tmp_path / "repo"
        repo.mkdir()
        tool_core = ToolCore(repo_path=str(repo), project_id="test-project")

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=tool_core,
            config={"model": "claude-sonnet-4-20250514"},
        )

        # Client should be None until start_session
        assert provider.client is None
        assert provider.session_id is None


class TestClaudeSDKProviderLifecycle:
    """Tests for ClaudeSDKProvider session lifecycle."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        from services.tool_core import ToolCore

        repo = tmp_path / "repo"
        repo.mkdir()
        return ToolCore(repo_path=str(repo), project_id="test-project")

    @pytest.mark.asyncio
    async def test_start_session_creates_client(self, mock_tool_core, tmp_path):
        """start_session should create and connect client."""
        from providers.claude_sdk_provider import ClaudeSDKProvider, SDK_AVAILABLE

        if not SDK_AVAILABLE:
            pytest.skip("Claude SDK not installed")

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={
                "model": "claude-sonnet-4-20250514",
                "api_key": "test-key",
            },
        )

        # Mock the ClaudeSDKClient
        with patch("providers.claude_sdk_provider.ClaudeSDKClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock()
            MockClient.return_value = mock_client

            await provider.start_session(audit_policy="read_only")

            # Client should be created
            assert provider.client is not None
            # Session ID should be set
            assert provider.session_id is not None
            # Client connect should have been called
            mock_client.connect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_session_with_resume_session_id(self, mock_tool_core, tmp_path):
        """start_session should use provided session_id when resuming."""
        from providers.claude_sdk_provider import ClaudeSDKProvider, SDK_AVAILABLE

        if not SDK_AVAILABLE:
            pytest.skip("Claude SDK not installed")

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={
                "model": "claude-sonnet-4-20250514",
                "api_key": "test-key",
            },
        )

        with patch("providers.claude_sdk_provider.ClaudeSDKClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock()
            MockClient.return_value = mock_client

            await provider.start_session(
                audit_policy="read_only",
                resume_session_id="existing-session-123",
            )

            # Session ID should be the resumed one
            assert provider.session_id == "existing-session-123"

    @pytest.mark.asyncio
    async def test_close_disconnects_client(self, mock_tool_core, tmp_path):
        """close should disconnect client."""
        from providers.claude_sdk_provider import ClaudeSDKProvider, SDK_AVAILABLE

        if not SDK_AVAILABLE:
            pytest.skip("Claude SDK not installed")

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={
                "model": "claude-sonnet-4-20250514",
                "api_key": "test-key",
            },
        )

        with patch("providers.claude_sdk_provider.ClaudeSDKClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock()
            mock_client.disconnect = AsyncMock()
            MockClient.return_value = mock_client

            await provider.start_session(audit_policy="read_only")
            await provider.close()

            # Client disconnect should have been called
            mock_client.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_close_handles_no_client(self, mock_tool_core, tmp_path):
        """close should handle case where client was never created."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={"model": "claude-sonnet-4-20250514"},
        )

        # Should not raise when client is None
        await provider.close()


class TestClaudeSDKProviderInterrupt:
    """Tests for ClaudeSDKProvider interrupt functionality."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        from services.tool_core import ToolCore

        repo = tmp_path / "repo"
        repo.mkdir()
        return ToolCore(repo_path=str(repo), project_id="test-project")

    @pytest.mark.asyncio
    async def test_interrupt_calls_client_interrupt(self, mock_tool_core, tmp_path):
        """interrupt should call client.interrupt()."""
        from providers.claude_sdk_provider import ClaudeSDKProvider, SDK_AVAILABLE

        if not SDK_AVAILABLE:
            pytest.skip("Claude SDK not installed")

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={
                "model": "claude-sonnet-4-20250514",
                "api_key": "test-key",
            },
        )

        with patch("providers.claude_sdk_provider.ClaudeSDKClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock()
            mock_client.interrupt = MagicMock()
            MockClient.return_value = mock_client

            await provider.start_session(audit_policy="read_only")
            await provider.interrupt()

            mock_client.interrupt.assert_called_once()

    @pytest.mark.asyncio
    async def test_interrupt_handles_no_client(self, mock_tool_core, tmp_path):
        """interrupt should handle case where client was never created."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={"model": "claude-sonnet-4-20250514"},
        )

        # Should not raise when client is None
        await provider.interrupt()


class TestClaudeSDKProviderWSEventConversion:
    """Tests for converting SDK messages to WebSocket events.

    Note: These tests use mock objects, so they don't require the SDK to be installed.
    The _to_ws_events method is a static method that processes any object with
    the expected attributes.
    """

    def test_to_ws_events_system_message(self):
        """SystemMessage should convert to {type: system, subtype, data}."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        # Create a mock SystemMessage
        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "SystemMessage"
        mock_msg.subtype = "init"
        mock_msg.data = {"session_id": "test-123"}

        events = ClaudeSDKProvider._to_ws_events(mock_msg)

        assert len(events) == 1
        assert events[0]["type"] == "system"
        assert events[0]["subtype"] == "init"
        assert events[0]["data"] == {"session_id": "test-123"}

    def test_to_ws_events_result_message(self):
        """ResultMessage should convert to {type: turn_complete, ...}."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        # Create a mock ResultMessage
        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "ResultMessage"
        mock_msg.session_id = "test-session"
        mock_msg.duration_ms = 1500
        mock_msg.total_cost_usd = 0.05

        events = ClaudeSDKProvider._to_ws_events(mock_msg)

        assert len(events) == 1
        assert events[0]["type"] == "turn_complete"
        assert events[0]["session_id"] == "test-session"
        assert events[0]["duration_ms"] == 1500
        assert events[0]["total_cost_usd"] == 0.05

    def test_to_ws_events_assistant_text_block(self):
        """AssistantMessage with TextBlock should convert to {type: agent_text, text}."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        # Create mock TextBlock
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "Hello, I found a vulnerability."

        # Create mock AssistantMessage
        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "AssistantMessage"
        mock_msg.content = [text_block]

        events = ClaudeSDKProvider._to_ws_events(mock_msg)

        assert len(events) == 1
        assert events[0]["type"] == "agent_text"
        assert events[0]["text"] == "Hello, I found a vulnerability."

    def test_to_ws_events_assistant_tool_use_block(self):
        """AssistantMessage with ToolUseBlock should convert to {type: tool_call, ...}."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        # Create mock ToolUseBlock
        tool_block = MagicMock()
        tool_block.type = "tool_use"
        tool_block.id = "tool-123"
        tool_block.name = "read_file"
        tool_block.input = {"path": "src/main.py"}

        # Create mock AssistantMessage
        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "AssistantMessage"
        mock_msg.content = [tool_block]

        events = ClaudeSDKProvider._to_ws_events(mock_msg)

        assert len(events) == 1
        assert events[0]["type"] == "tool_call"
        assert events[0]["id"] == "tool-123"
        assert events[0]["name"] == "read_file"
        assert events[0]["args"] == {"path": "src/main.py"}

    def test_to_ws_events_assistant_tool_result_block(self):
        """AssistantMessage with ToolResultBlock should convert to {type: tool_result, ...}."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        # Create mock ToolResultBlock
        result_block = MagicMock()
        result_block.type = "tool_result"
        result_block.tool_use_id = "tool-123"
        result_block.content = "File contents here..."

        # Create mock AssistantMessage
        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "AssistantMessage"
        mock_msg.content = [result_block]

        events = ClaudeSDKProvider._to_ws_events(mock_msg)

        assert len(events) == 1
        assert events[0]["type"] == "tool_result"
        assert events[0]["tool_use_id"] == "tool-123"
        assert events[0]["result"] == "File contents here..."

    def test_to_ws_events_multiple_content_blocks(self):
        """AssistantMessage with multiple blocks should generate multiple events."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        # Create mock blocks
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "Let me read the file."

        tool_block = MagicMock()
        tool_block.type = "tool_use"
        tool_block.id = "tool-456"
        tool_block.name = "read_file"
        tool_block.input = {"path": "test.py"}

        # Create mock AssistantMessage with multiple blocks
        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "AssistantMessage"
        mock_msg.content = [text_block, tool_block]

        events = ClaudeSDKProvider._to_ws_events(mock_msg)

        assert len(events) == 2
        assert events[0]["type"] == "agent_text"
        assert events[1]["type"] == "tool_call"

    def test_to_ws_events_unknown_message_type(self):
        """Unknown message types should return empty list."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        # Create a mock unknown message type
        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "UnknownMessageType"

        events = ClaudeSDKProvider._to_ws_events(mock_msg)

        assert len(events) == 0


class TestSDKAvailableFlag:
    """Tests for SDK_AVAILABLE flag behavior."""

    def test_sdk_available_is_boolean(self):
        """SDK_AVAILABLE should be a boolean."""
        from providers.claude_sdk_provider import SDK_AVAILABLE

        assert isinstance(SDK_AVAILABLE, bool)

    def test_provider_can_be_imported_without_sdk(self):
        """Provider module should be importable even if SDK is not installed."""
        # This test passes if we reach here without ImportError
        from providers.claude_sdk_provider import ClaudeSDKProvider, SDK_AVAILABLE
        assert ClaudeSDKProvider is not None

    @pytest.mark.asyncio
    async def test_start_session_raises_when_sdk_unavailable(self, tmp_path):
        """start_session should raise RuntimeError when SDK_AVAILABLE is False."""
        from services.tool_core import ToolCore

        repo = tmp_path / "repo"
        repo.mkdir()
        tool_core = ToolCore(repo_path=str(repo), project_id="test-project")

        # Patch SDK_AVAILABLE to False
        with patch("providers.claude_sdk_provider.SDK_AVAILABLE", False):
            from providers.claude_sdk_provider import ClaudeSDKProvider

            provider = ClaudeSDKProvider(
                repo_path=str(repo),
                project_id="test-project",
                tool_core=tool_core,
                config={"model": "claude-sonnet-4-20250514"},
            )

            with pytest.raises(RuntimeError) as exc_info:
                await provider.start_session(audit_policy="read_only")

            assert "Claude SDK not installed" in str(exc_info.value)


class TestClaudeSDKProviderRunTurn:
    """Tests for ClaudeSDKProvider run_turn functionality."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        from services.tool_core import ToolCore

        repo = tmp_path / "repo"
        repo.mkdir()
        return ToolCore(repo_path=str(repo), project_id="test-project")

    @pytest.mark.asyncio
    async def test_run_turn_raises_if_session_not_started(self, mock_tool_core, tmp_path):
        """run_turn should raise RuntimeError if session not started."""
        from providers.claude_sdk_provider import ClaudeSDKProvider

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={"model": "claude-sonnet-4-20250514"},
        )

        with pytest.raises(RuntimeError) as exc_info:
            await provider.run_turn("Hello")

        assert "Session not started" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_turn_calls_on_event_callback(self, mock_tool_core, tmp_path):
        """run_turn should call on_event callback for each event."""
        from providers.claude_sdk_provider import ClaudeSDKProvider, SDK_AVAILABLE

        if not SDK_AVAILABLE:
            pytest.skip("Claude SDK not installed")

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={
                "model": "claude-sonnet-4-20250514",
                "api_key": "test-key",
            },
        )

        # Create mock messages to be returned by client.query()
        text_block = MagicMock()
        text_block.type = "text"
        text_block.text = "Hello!"

        mock_msg = MagicMock()
        mock_msg.__class__.__name__ = "AssistantMessage"
        mock_msg.content = [text_block]

        with patch("providers.claude_sdk_provider.ClaudeSDKClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock()

            mock_client.query = AsyncMock()

            async def mock_receive_response():
                yield mock_msg

            mock_client.receive_response = MagicMock(return_value=mock_receive_response())
            MockClient.return_value = mock_client

            await provider.start_session(audit_policy="read_only")

            # Track callback invocations
            callback_events = []
            def on_event(event):
                callback_events.append(event)

            events = await provider.run_turn("Test prompt", on_event=on_event)

            # Verify callback was called
            assert len(callback_events) == 1
            assert callback_events[0]["type"] == "agent_text"
            assert callback_events[0]["text"] == "Hello!"

            # Verify returned events match callback events
            assert events == callback_events


class TestClaudeSDKProviderCloseIdempotent:
    """Tests for ClaudeSDKProvider close() idempotency."""

    @pytest.fixture
    def mock_tool_core(self, tmp_path):
        """Create a mock ToolCore for testing."""
        from services.tool_core import ToolCore

        repo = tmp_path / "repo"
        repo.mkdir()
        return ToolCore(repo_path=str(repo), project_id="test-project")

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self, mock_tool_core, tmp_path):
        """close() should be safe to call multiple times."""
        from providers.claude_sdk_provider import ClaudeSDKProvider, SDK_AVAILABLE

        if not SDK_AVAILABLE:
            pytest.skip("Claude SDK not installed")

        repo = tmp_path / "repo"

        provider = ClaudeSDKProvider(
            repo_path=str(repo),
            project_id="test-project",
            tool_core=mock_tool_core,
            config={
                "model": "claude-sonnet-4-20250514",
                "api_key": "test-key",
            },
        )

        with patch("providers.claude_sdk_provider.ClaudeSDKClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock()
            mock_client.disconnect = AsyncMock()
            MockClient.return_value = mock_client

            await provider.start_session(audit_policy="read_only")

            # Call close multiple times
            await provider.close()
            await provider.close()
            await provider.close()

            # disconnect should only be called once
            mock_client.disconnect.assert_awaited_once()
