"""Tests for session hibernation WebSocket events."""
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch


def test_ws_message_type_has_session_events():
    """Test that WSMessageType enum includes session hibernation events."""
    from models.schemas import WSMessageType

    # Verify session event types exist
    assert hasattr(WSMessageType, "SESSION_PAUSING")
    assert hasattr(WSMessageType, "SESSION_PAUSED")
    assert hasattr(WSMessageType, "SESSION_RESUMED")

    # Verify values are correct strings
    assert WSMessageType.SESSION_PAUSING.value == "session_pausing"
    assert WSMessageType.SESSION_PAUSED.value == "session_paused"
    assert WSMessageType.SESSION_RESUMED.value == "session_resumed"


def test_session_event_types_are_valid_enum_members():
    """Test session event types can be used in type annotations."""
    from models.schemas import WSMessageType

    # Verify they can be used as enum members
    events = [
        WSMessageType.SESSION_PAUSING,
        WSMessageType.SESSION_PAUSED,
        WSMessageType.SESSION_RESUMED,
    ]
    for event in events:
        assert isinstance(event, WSMessageType)
        assert event.name.startswith("SESSION_")


@pytest.mark.asyncio
async def test_broadcast_session_event_exists():
    """Test that broadcast_session_event function exists."""
    from routers.websocket import broadcast_session_event

    # Function should be importable
    assert callable(broadcast_session_event)


@pytest.mark.asyncio
async def test_broadcast_session_event_sends_correct_format():
    """Test broadcast_session_event sends message with correct structure."""
    from routers.websocket import broadcast_session_event, manager

    # Mock a connected client
    mock_ws = AsyncMock()
    manager.active_connections.add(mock_ws)

    try:
        await broadcast_session_event(
            event_type="session_paused",
            data={"project_id": "proj123", "agent_count": 2}
        )

        # Verify message was sent
        assert mock_ws.send_text.called

        # Parse the sent message
        import json
        sent_message = json.loads(mock_ws.send_text.call_args[0][0])

        # Verify message structure
        assert sent_message["type"] == "session_paused"
        assert sent_message["agent_id"] == "session"  # Special ID for session-level events
        assert sent_message["data"]["project_id"] == "proj123"
        assert sent_message["data"]["agent_count"] == 2
        assert "timestamp" in sent_message

    finally:
        # Cleanup
        manager.active_connections.discard(mock_ws)


@pytest.mark.asyncio
async def test_broadcast_session_event_handles_disconnected_clients():
    """Test that broadcast_session_event removes disconnected clients."""
    from routers.websocket import broadcast_session_event, manager

    # Mock a client that fails to receive messages
    mock_ws = AsyncMock()
    mock_ws.send_text.side_effect = Exception("Connection closed")
    manager.active_connections.add(mock_ws)

    try:
        await broadcast_session_event(
            event_type="session_pausing",
            data={}
        )

        # The failed client should be removed
        assert mock_ws not in manager.active_connections

    finally:
        # Cleanup just in case
        manager.active_connections.discard(mock_ws)


@pytest.mark.asyncio
async def test_broadcast_session_event_with_empty_connections():
    """Test broadcast_session_event handles no connected clients gracefully."""
    from routers.websocket import broadcast_session_event, manager

    # Ensure no connections
    original_connections = manager.active_connections.copy()
    manager.active_connections.clear()

    try:
        # Should not raise an error
        await broadcast_session_event(
            event_type="session_resumed",
            data={"project_id": "proj123"}
        )
    finally:
        # Restore original connections
        manager.active_connections = original_connections
