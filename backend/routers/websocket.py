"""WebSocket router for real-time agent updates."""

import asyncio
import json
from typing import Set, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from models.schemas import WSMessage
from services.agent_orchestrator import orchestrator
from services.observability_service import observability_service
from middleware.auth import verify_session


router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        print(f"WebSocket connected. Total: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        async with self._lock:
            self.active_connections.discard(websocket)
        print(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return

        disconnected = set()
        message_str = json.dumps(message, default=str)

        for connection in self.active_connections:
            try:
                await connection.send_text(message_str)
            except Exception:
                disconnected.add(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                self.active_connections -= disconnected

    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send message to a specific client."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception:
            await self.disconnect(websocket)


# Global connection manager
manager = ConnectionManager()

# Store the main event loop reference
_main_loop: Optional[asyncio.AbstractEventLoop] = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    """Set the main event loop for broadcast callbacks."""
    global _main_loop
    _main_loop = loop


def broadcast_agent_message(message: WSMessage):
    """Callback for agent messages - schedules broadcast."""
    try:
        # Try to get the running loop (works if called from async context)
        loop = asyncio.get_running_loop()
        loop.create_task(manager.broadcast(message.model_dump()))
    except RuntimeError:
        # No running loop - use the main loop if available
        if _main_loop and _main_loop.is_running():
            asyncio.run_coroutine_threadsafe(
                manager.broadcast(message.model_dump()),
                _main_loop
            )
        else:
            # Fallback: try to run synchronously (not ideal but prevents crash)
            try:
                asyncio.run(manager.broadcast(message.model_dump()))
            except Exception as e:
                print(f"Failed to broadcast message: {e}")


# Register the callback with the orchestrator
orchestrator.add_message_callback(broadcast_agent_message)

# Register the callback with the observability service
observability_service.set_broadcast_callback(broadcast_agent_message)


@router.websocket("")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    Main WebSocket endpoint for real-time updates.

    Authentication:
    - Pass token as query parameter: /ws?token=<your_token>
    - Get token from /api/auth/token endpoint

    Receives:
    - subscribe: { repo_id?: string, agent_id?: string }
    - ping: heartbeat

    Sends:
    - agent_status: Agent status changes
    - finding: New vulnerability findings
    - progress: Analysis progress updates
    - error: Error messages
    - log: Log messages
    - pong: Heartbeat response
    """
    # Validate authentication token
    if not token:
        print("[WS] Connection rejected: No token provided")
        await websocket.close(code=4001, reason="Authentication required. Use ?token=<session_token>")
        return

    if not verify_session(token):
        # Log more details for debugging
        from middleware.auth import get_session_token
        expected = get_session_token()
        print(f"[WS] Token mismatch - received: {token[:8]}... expected: {expected[:8]}...")
        await websocket.close(code=4001, reason="Invalid or expired token. Refresh the page to get a new token.")
        return

    await manager.connect(websocket)

    try:
        while True:
            # Receive and parse message
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await manager.send_personal(
                    websocket,
                    {"type": "error", "data": {"error": "Invalid JSON"}}
                )
                continue

            msg_type = message.get("type", "")

            if msg_type == "ping":
                # Heartbeat
                await manager.send_personal(websocket, {"type": "pong"})

            elif msg_type == "subscribe":
                # Client wants to subscribe to specific updates
                # For now, all clients receive all updates
                await manager.send_personal(
                    websocket,
                    {
                        "type": "subscribed",
                        "data": {
                            "repo_id": message.get("repo_id"),
                            "agent_id": message.get("agent_id"),
                        }
                    }
                )

            elif msg_type == "get_status":
                # Send current orchestrator stats
                stats = await orchestrator.get_stats()
                await manager.send_personal(
                    websocket,
                    {"type": "status", "data": stats}
                )

            else:
                await manager.send_personal(
                    websocket,
                    {"type": "error", "data": {"error": f"Unknown message type: {msg_type}"}}
                )

    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        await manager.disconnect(websocket)
