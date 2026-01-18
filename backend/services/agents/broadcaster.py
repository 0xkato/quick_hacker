"""WebSocket broadcasting for agent events."""

from typing import Any, Callable

from models.schemas import Finding, WSMessage, WSMessageType


class AgentBroadcaster:
    """Broadcasts agent events via WebSocket."""

    def __init__(self):
        self._message_callbacks: list[Callable[[WSMessage], None]] = []

    def add_message_callback(self, callback: Callable[[WSMessage], None]):
        """Add a callback for agent messages (WebSocket broadcast)."""
        self._message_callbacks.append(callback)

    def remove_message_callback(self, callback: Callable[[WSMessage], None]):
        """Remove a message callback."""
        if callback in self._message_callbacks:
            self._message_callbacks.remove(callback)

    def broadcast_message(self, message: WSMessage):
        """Broadcast message to all registered callbacks."""
        for callback in self._message_callbacks:
            try:
                callback(message)
            except Exception as e:
                print(f"Callback error: {e}")

    async def send_status(self, agent_id: str, status: str, **kwargs):
        """Send status update."""
        self.broadcast_message(WSMessage(
            type=WSMessageType.AGENT_STATUS,
            agent_id=agent_id,
            data={"status": status, **kwargs}
        ))

    async def send_progress(self, agent_id: str, data: dict):
        """Send progress update."""
        self.broadcast_message(WSMessage(
            type=WSMessageType.PROGRESS,
            agent_id=agent_id,
            data=data
        ))

    async def send_finding(self, agent_id: str, finding: Finding):
        """Send finding discovered event."""
        self.broadcast_message(WSMessage(
            type=WSMessageType.FINDING,
            agent_id=agent_id,
            data=finding.model_dump(mode='json')
        ))

    async def send_report_ready(self, agent_id: str, data: dict):
        """Send report ready event."""
        self.broadcast_message(WSMessage(
            type=WSMessageType.REPORT_READY,
            agent_id=agent_id,
            data=data
        ))

    async def send_error(self, agent_id: str, error: str):
        """Send error event."""
        self.broadcast_message(WSMessage(
            type=WSMessageType.ERROR,
            agent_id=agent_id,
            data={"error": error}
        ))

    async def send_log(self, agent_id: str, message: str):
        """Send log message."""
        self.broadcast_message(WSMessage(
            type=WSMessageType.LOG,
            agent_id=agent_id,
            data={"message": message}
        ))
