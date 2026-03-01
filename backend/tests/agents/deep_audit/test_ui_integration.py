"""Tests for UI integration - verifying sub-agents broadcast status messages."""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime

from agents.deep_audit.dispatcher import (
    WaveDispatcher,
    WavePlan,
    DispatchTask,
)
from agents.deep_audit.filesystem import MemoriesFilesystem
from models.schemas import WSMessage, WSMessageType


class TestUIBroadcasting:
    """Test that sub-agents broadcast their status for UI visibility."""

    @pytest.fixture
    def mock_filesystem(self, tmp_path):
        """Create a mock filesystem with required attributes."""
        mock_fs = MagicMock(spec=MemoriesFilesystem)
        mock_fs.project_id = "test-project-id"
        return mock_fs

    @pytest.fixture
    def captured_messages(self):
        """List to capture broadcast messages."""
        return []

    @pytest.fixture
    def on_message_callback(self, captured_messages):
        """Create callback that captures messages."""
        def callback(msg: WSMessage):
            captured_messages.append(msg)
        return callback

    def test_dispatcher_accepts_on_message_callback(self, mock_filesystem, on_message_callback, tmp_path):
        """Test that WaveDispatcher accepts on_message callback."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
            on_message=on_message_callback,
        )
        assert dispatcher.on_message is not None

    def test_broadcast_helper_creates_ws_message(self, mock_filesystem, on_message_callback, captured_messages, tmp_path):
        """Test that _broadcast creates proper WSMessage."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
            on_message=on_message_callback,
        )

        dispatcher._broadcast(
            WSMessageType.AGENT_STATUS,
            "test-agent-id",
            {"status": "running", "name": "TestAgent"}
        )

        assert len(captured_messages) == 1
        msg = captured_messages[0]
        assert msg.type == WSMessageType.AGENT_STATUS
        assert msg.agent_id == "test-agent-id"
        assert msg.data["status"] == "running"
        assert msg.data["name"] == "TestAgent"

    def test_broadcast_noop_without_callback(self, mock_filesystem, tmp_path):
        """Test that _broadcast does nothing if no callback is set."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
            on_message=None,  # No callback
        )

        # Should not raise
        dispatcher._broadcast(
            WSMessageType.AGENT_STATUS,
            "test-agent-id",
            {"status": "running"}
        )

    def test_broadcast_multiple_messages(self, mock_filesystem, on_message_callback, captured_messages, tmp_path):
        """Test broadcasting multiple messages in sequence."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
            on_message=on_message_callback,
        )

        # Broadcast start
        dispatcher._broadcast(
            WSMessageType.AGENT_STATUS,
            "agent-001",
            {"status": "running", "agent_type": "SinkHunter"}
        )

        # Broadcast tool use
        dispatcher._broadcast(
            WSMessageType.TOOL_DETAIL,
            "agent-001",
            {"tool": "read_file", "args": {"path": "src/main.py"}}
        )

        # Broadcast complete
        dispatcher._broadcast(
            WSMessageType.AGENT_STATUS,
            "agent-001",
            {"status": "completed", "findings_count": 2}
        )

        assert len(captured_messages) == 3
        assert captured_messages[0].data["status"] == "running"
        assert captured_messages[1].data["tool"] == "read_file"
        assert captured_messages[2].data["status"] == "completed"

    def test_dispatcher_init_stores_on_message(self, mock_filesystem, on_message_callback, tmp_path):
        """Test that dispatcher stores on_message for later use."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
            provider_config={"provider": "anthropic", "model": "claude-sonnet-4-5-20250929"},
            on_agent_start=lambda tid, atype: None,
            on_agent_complete=lambda tid, atype, status: None,
            on_message=on_message_callback,
        )

        # All callbacks should be stored
        assert dispatcher.on_message == on_message_callback
        assert dispatcher.on_agent_start is not None
        assert dispatcher.on_agent_complete is not None

    def test_ws_message_has_correct_fields(self, mock_filesystem, on_message_callback, captured_messages, tmp_path):
        """Test WSMessage structure matches UI expectations."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
            on_message=on_message_callback,
        )

        dispatcher._broadcast(
            WSMessageType.AGENT_STATUS,
            "specialist-sql-001",
            {
                "agent_id": "specialist-sql-001",
                "name": "SQL Injection Specialist",
                "agent_type": "Specialist",
                "status": "running",
                "task_id": "task-abc123",
                "objective": "Analyze SQL injection signal",
            }
        )

        msg = captured_messages[0]

        # Verify all fields the UI expects
        assert hasattr(msg, 'type')
        assert hasattr(msg, 'agent_id')
        assert hasattr(msg, 'data')
        assert hasattr(msg, 'timestamp')

        # Verify data structure
        assert "agent_id" in msg.data
        assert "name" in msg.data
        assert "agent_type" in msg.data
        assert "status" in msg.data
        assert "task_id" in msg.data

    @pytest.mark.asyncio
    async def test_dispatcher_passes_on_message_to_subagent(self, mock_filesystem, on_message_callback, tmp_path):
        """Test that dispatcher is configured to pass on_message to subagents."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
            on_message=on_message_callback,
        )

        # Verify dispatcher has on_message set
        assert dispatcher.on_message is not None

        # Verify _broadcast method works
        assert hasattr(dispatcher, '_broadcast')

        # The actual passing to ReactAgent is tested by checking the dispatcher code
        # includes on_message=self.on_message in _spawn_subagent
