# backend/providers/claude_sdk_provider.py
"""Claude SDK Provider - wraps ClaudeSDKClient for native agent loop.

This provider uses the Claude Agent SDK's native agentic loop for tool execution,
providing better performance and native tool handling compared to the ReAct-based
providers.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable

from services.tool_core import ToolCore
from providers.mcp_tools import create_quickhack_mcp_server

logger = logging.getLogger(__name__)

# Try to import Claude SDK, but don't fail if not installed
SDK_AVAILABLE = False
ClaudeSDKClient = None
ClaudeAgentOptions = None

try:
    from claude_sdk import ClaudeSDKClient as _ClaudeSDKClient
    from claude_sdk import ClaudeAgentOptions as _ClaudeAgentOptions
    ClaudeSDKClient = _ClaudeSDKClient
    ClaudeAgentOptions = _ClaudeAgentOptions
    SDK_AVAILABLE = True
except ImportError:
    logger.warning("Claude SDK not installed. ClaudeSDKProvider will not be functional.")


class ClaudeSDKProvider:
    """Provider that wraps ClaudeSDKClient for native agent loop.

    This provider creates an MCP server from ToolCore and uses the Claude SDK's
    native agent loop for tool execution. It converts SDK messages to WebSocket
    events for the frontend.

    Attributes:
        repo_path: Path to the repository being analyzed
        project_id: Unique identifier for the project
        tool_core: ToolCore instance for security tool implementations
        config: Provider configuration (model, api_key, etc.)
        client: ClaudeSDKClient instance (None until start_session)
        session_id: Current session ID (None until start_session)
    """

    def __init__(
        self,
        repo_path: str,
        project_id: str,
        tool_core: ToolCore,
        config: dict[str, Any],
    ):
        """Initialize ClaudeSDKProvider.

        Args:
            repo_path: Path to the repository root
            project_id: Project identifier
            tool_core: ToolCore instance with security tool implementations
            config: Configuration dict with model, api_key, max_tokens, etc.
        """
        self.repo_path = repo_path
        self.project_id = project_id
        self.tool_core = tool_core
        self.config = config

        # Client and session are not created until start_session
        self.client = None
        self.session_id = None

        # MCP server config and tools (created on start_session)
        self._mcp_config = None
        self._mcp_tools = None

    async def start_session(
        self,
        audit_policy: str,
        resume_session_id: str | None = None,
    ) -> str:
        """Start a new session or resume an existing one.

        Creates the MCP server, builds allowed_tools list, creates ClaudeAgentOptions,
        and creates/connects the ClaudeSDKClient.

        Args:
            audit_policy: Security policy for the session (e.g., "read_only")
            resume_session_id: Optional session ID to resume

        Returns:
            The session ID (new or resumed)

        Raises:
            RuntimeError: If Claude SDK is not available
        """
        if not SDK_AVAILABLE:
            raise RuntimeError(
                "Claude SDK not installed. Install with: pip install claude-sdk"
            )

        # Create MCP server and tools from ToolCore
        self._mcp_config, self._mcp_tools = create_quickhack_mcp_server(self.tool_core)

        # Build allowed_tools list (mcp__quickhack__<name> format)
        allowed_tools = self._mcp_config.get("allowed_tools", [])

        # Create ClaudeAgentOptions
        options = ClaudeAgentOptions(
            model=self.config.get("model", "claude-sonnet-4-20250514"),
            api_key=self.config.get("api_key"),
            max_tokens=self.config.get("max_tokens", 8192),
            allowed_tools=allowed_tools,
            mcp_tools=self._mcp_tools,
            audit_policy=audit_policy,
        )

        # Create ClaudeSDKClient
        self.client = ClaudeSDKClient(options)

        # Set session ID
        self.session_id = resume_session_id or str(uuid.uuid4())

        # Connect client
        await self.client.connect()

        logger.info(
            f"ClaudeSDKProvider session started: {self.session_id}, "
            f"model={options.model}, tools={len(allowed_tools)}"
        )

        return self.session_id

    async def run_turn(
        self,
        prompt: str,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Run a turn in the agent loop.

        Sends a query to the client, processes the response stream, and converts
        messages to WebSocket events.

        Args:
            prompt: The user prompt to send
            on_event: Optional callback for each WebSocket event

        Returns:
            List of all WebSocket events generated during the turn

        Raises:
            RuntimeError: If session not started
        """
        if self.client is None:
            raise RuntimeError("Session not started. Call start_session first.")

        events: list[dict[str, Any]] = []

        # Send query and process response stream
        async for message in self.client.query(prompt):
            ws_events = self._to_ws_events(message)
            for event in ws_events:
                events.append(event)
                if on_event:
                    on_event(event)

        return events

    def interrupt(self) -> None:
        """Interrupt the current agent operation.

        Safe to call even if client is not initialized.
        """
        if self.client is not None:
            self.client.interrupt()
            logger.info(f"ClaudeSDKProvider session {self.session_id} interrupted")

    async def close(self) -> None:
        """Close the session and disconnect the client.

        Safe to call even if client was never created.
        Idempotent: safe to call multiple times.
        """
        if self.client is not None:
            client = self.client
            self.client = None  # Set to None first to prevent double-close race condition
            await client.disconnect()
            logger.info(f"ClaudeSDKProvider session {self.session_id} closed")

    @staticmethod
    def _to_ws_events(msg: Any) -> list[dict[str, Any]]:
        """Convert SDK message to WebSocket events.

        Args:
            msg: SDK message object (SystemMessage, ResultMessage, AssistantMessage, etc.)

        Returns:
            List of WebSocket event dicts

        Message type conversions:
            - SystemMessage -> {type: "system", subtype, data}
            - ResultMessage -> {type: "turn_complete", session_id, duration_ms, total_cost_usd}
            - AssistantMessage with TextBlock -> {type: "agent_text", text}
            - AssistantMessage with ToolUseBlock -> {type: "tool_call", id, name, args}
            - AssistantMessage with ToolResultBlock -> {type: "tool_result", tool_use_id, result}
        """
        events: list[dict[str, Any]] = []
        msg_type = msg.__class__.__name__

        if msg_type == "SystemMessage":
            events.append({
                "type": "system",
                "subtype": getattr(msg, "subtype", "unknown"),
                "data": getattr(msg, "data", {}),
            })

        elif msg_type == "ResultMessage":
            events.append({
                "type": "turn_complete",
                "session_id": getattr(msg, "session_id", None),
                "duration_ms": getattr(msg, "duration_ms", 0),
                "total_cost_usd": getattr(msg, "total_cost_usd", 0.0),
            })

        elif msg_type == "AssistantMessage":
            # AssistantMessage can have multiple content blocks
            content_blocks = getattr(msg, "content", [])
            for block in content_blocks:
                block_type = getattr(block, "type", None)

                if block_type == "text":
                    events.append({
                        "type": "agent_text",
                        "text": getattr(block, "text", ""),
                    })

                elif block_type == "tool_use":
                    events.append({
                        "type": "tool_call",
                        "id": getattr(block, "id", ""),
                        "name": getattr(block, "name", ""),
                        "args": getattr(block, "input", {}),
                    })

                elif block_type == "tool_result":
                    events.append({
                        "type": "tool_result",
                        "tool_use_id": getattr(block, "tool_use_id", ""),
                        "result": getattr(block, "content", ""),
                    })

        else:
            # Unknown message type - log and skip
            logger.debug(f"Unknown SDK message type: {msg_type}")

        return events
