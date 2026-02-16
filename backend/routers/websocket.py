"""WebSocket router for real-time agent updates."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Set, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from starlette.websockets import WebSocketState

from models.schemas import WSMessage
from services.agents import orchestrator
from services.observability_service import observability_service
from services.persistence_service import persistence_service
from services.report_service import report_service
from middleware.auth import verify_ws_token

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        # The endpoint may accept early to perform an auth handshake. Avoid double-accept.
        if websocket.application_state == WebSocketState.CONNECTING:
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
            except Exception as e:
                logger.debug(f"Broadcast failed for connection: {e}")
                disconnected.add(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                self.active_connections -= disconnected

    async def send_personal(self, websocket: WebSocket, message: dict):
        """Send message to a specific client."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception as e:
            logger.debug(f"Send failed: {e}")
            await self.disconnect(websocket)


# Global connection manager
manager = ConnectionManager()

# Store the main event loop reference
_main_loop: Optional[asyncio.AbstractEventLoop] = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    """Set the main event loop for broadcast callbacks."""
    global _main_loop
    _main_loop = loop


def _handle_broadcast_task_exception(task: asyncio.Task):
    """Callback to log exceptions from fire-and-forget broadcast tasks."""
    try:
        exc = task.exception()
        if exc is not None:
            logger.error(f"Broadcast task failed: {exc}")
    except asyncio.CancelledError:
        pass  # Task was cancelled, not an error


def broadcast_agent_message(message: WSMessage):
    """Callback for agent messages - schedules broadcast."""
    try:
        # Try to get the running loop (works if called from async context)
        loop = asyncio.get_running_loop()
        task = loop.create_task(manager.broadcast(message.model_dump()))
        task.add_done_callback(_handle_broadcast_task_exception)
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


async def broadcast_session_event(event_type: str, data: dict):
    """Broadcast a session event to all connected clients."""
    message = {
        "type": event_type,
        "agent_id": "session",  # Special ID for session-level events
        "data": data,
        "timestamp": datetime.utcnow().isoformat(),
    }
    await manager.broadcast(message)


# Register the callback with the orchestrator
orchestrator.add_message_callback(broadcast_agent_message)

# Register the callback with the observability service
observability_service.set_broadcast_callback(broadcast_agent_message)

# Register callbacks for other services that emit WSMessage events
persistence_service.set_broadcast_callback(broadcast_agent_message)
report_service.set_broadcast_callback(broadcast_agent_message)

# Register the callback with the behavior tree service
from services.behavior_tree_service import behavior_tree_service
behavior_tree_service.set_broadcast_callback(broadcast_agent_message)


@router.websocket("")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
):
    """
    Main WebSocket endpoint for real-time updates.

    Authentication:
    - Pass token as query parameter: /ws?token=<your_token>
    - Legacy session token from /api/auth/token (localhost-only by default)
    - OR a JWT access token from /api/auth/login

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
    # FastAPI should populate `token` from the query string.
    # In practice (dev tooling / proxies), we occasionally see `token` arrive as None
    # even when the client includes it. Fall back to Starlette's parsed query params.
    token = token or websocket.query_params.get("token")

    # Accept early so we can exchange an auth message even when query params are missing.
    await websocket.accept()

    # Validate authentication token (query param OR message-based handshake).
    if not token or not verify_ws_token(token):
        query_keys = list(websocket.query_params.keys())
        reason = "missing" if not token else "invalid"
        print(f"[WS] Auth required (reason={reason}, query_keys={query_keys})")

        # Ask the client to send an auth message:
        # { "type": "auth", "token": "<jwt|session_token>" }
        await websocket.send_text(json.dumps({"type": "auth_required", "data": {"reason": reason}}))

        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        except asyncio.TimeoutError:
            await websocket.close(code=4001, reason="Authentication required.")
            return
        except WebSocketDisconnect:
            return

        try:
            auth_msg = json.loads(raw)
        except json.JSONDecodeError:
            await websocket.close(code=4001, reason="Authentication required.")
            return

        if auth_msg.get("type") != "auth":
            await websocket.close(code=4001, reason="Authentication required.")
            return

        provided_token = auth_msg.get("token") or (auth_msg.get("data") or {}).get("token")
        if not provided_token:
            await websocket.close(code=4001, reason="Authentication required.")
            return

        provided_token = str(provided_token)
        if not verify_ws_token(provided_token):
            await websocket.close(code=4001, reason="Invalid or expired token.")
            return

        token = provided_token

    await manager.connect(websocket)
    # Confirm successful authentication to the client so it can start heartbeats/subscriptions.
    await manager.send_personal(websocket, {"type": "auth_ok"})

    try:
        # Receive timeout in seconds - clients should send ping within this interval
        receive_timeout = 120  # 2 minutes

        while True:
            # Receive and parse message with timeout
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=receive_timeout
                )
            except asyncio.TimeoutError:
                # No message received within timeout - close idle connection
                print(f"WebSocket receive timeout after {receive_timeout}s")
                await websocket.close(code=1001, reason="Idle timeout")
                break

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

            elif msg_type == "auth":
                # Client may send auth proactively; ignore once connected.
                await manager.send_personal(websocket, {"type": "auth_ok"})

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
        logger.debug("WebSocket client disconnected normally")
        await manager.disconnect(websocket)
    except asyncio.CancelledError:
        logger.debug("WebSocket connection cancelled")
        await manager.disconnect(websocket)
        raise  # Re-raise CancelledError for proper cleanup
    except ConnectionResetError as e:
        logger.warning(f"WebSocket connection reset by peer: {e}")
        await manager.disconnect(websocket)
    except Exception as e:
        logger.exception(f"Unexpected WebSocket error: {type(e).__name__}: {e}")
        await manager.disconnect(websocket)
