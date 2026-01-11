# backend/providers/claude_sdk_provider.py
"""Claude SDK Provider - wraps ClaudeSDKClient for native agent loop.

This provider uses the Claude Agent SDK's native agentic loop for tool execution,
providing better performance and native tool handling compared to the ReAct-based
providers.
"""
from __future__ import annotations

import os
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
    from claude_agent_sdk import (
        ClaudeSDKClient as _ClaudeSDKClient,
        ClaudeAgentOptions as _ClaudeAgentOptions,
        AssistantMessage as _AssistantMessage,
        SystemMessage as _SystemMessage,
        ResultMessage as _ResultMessage,
        TextBlock as _TextBlock,
        ToolUseBlock as _ToolUseBlock,
        ToolResultBlock as _ToolResultBlock,
    )
    ClaudeSDKClient = _ClaudeSDKClient
    ClaudeAgentOptions = _ClaudeAgentOptions
    AssistantMessage = _AssistantMessage
    SystemMessage = _SystemMessage
    ResultMessage = _ResultMessage
    TextBlock = _TextBlock
    ToolUseBlock = _ToolUseBlock
    ToolResultBlock = _ToolResultBlock
    SDK_AVAILABLE = True
    print("[ClaudeSDKProvider] Claude Agent SDK loaded successfully")
except ImportError as e:
    print(f"[ClaudeSDKProvider] Claude Agent SDK import failed: {e}")
    logger.warning("Claude Agent SDK not installed. ClaudeSDKProvider will not be functional.")


class ClaudeSDKProvider:
    """Provider that wraps ClaudeSDKClient for native agent loop.

    This provider creates an MCP server from ToolCore and uses the Claude SDK's
    native agent loop for tool execution. It converts SDK messages to WebSocket
    events for the frontend.

    Attributes:
        repo_path: Path to the repository being analyzed
        project_id: Unique identifier for the project
        tool_core: ToolCore instance for security tool implementations
        config: Provider configuration (model, etc.)
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
            config: Configuration dict with model, max_turns, max_budget_usd, etc.
        """
        self.repo_path = repo_path
        self.project_id = project_id
        self.tool_core = tool_core
        self.config = config

        # Client and session are not created until start_session
        self.client = None
        self.session_id = None

        # MCP server config and server (created on start_session)
        self._mcp_config = None
        self._mcp_server = None

    async def start_session(
        self,
        audit_policy: str,
        resume_session_id: str | None = None,
    ) -> str:
        """Start a new session or resume an existing one.

        Creates the MCP server, builds allowed_tools list, creates ClaudeAgentOptions,
        and creates/connects the ClaudeSDKClient.

        Args:
            audit_policy: Security policy for the session (used for system prompt)
            resume_session_id: Optional session ID to resume

        Returns:
            The session ID (new or resumed)

        Raises:
            RuntimeError: If Claude SDK is not available
        """
        print(f"[ClaudeSDKProvider] start_session called, SDK_AVAILABLE={SDK_AVAILABLE}")
        if not SDK_AVAILABLE:
            raise RuntimeError(
                "Claude SDK not installed. Install with: pip install claude-agent-sdk"
            )

        # Create MCP server and tools from ToolCore
        print("[ClaudeSDKProvider] Creating MCP server...")
        self._mcp_config, self._mcp_server = create_quickhack_mcp_server(self.tool_core)
        allowed_tools = self._mcp_config.get('allowed_tools', [])
        print(f"[ClaudeSDKProvider] MCP server created, {len(allowed_tools)} tools:")
        for tool_name in allowed_tools:
            print(f"  - {tool_name}")

        # Build allowed_tools list
        allowed_tools = self._mcp_config.get("allowed_tools", [])

        # Build system prompt incorporating audit policy
        system_prompt = self._build_system_prompt(audit_policy)

        # Create ClaudeAgentOptions with SDK-compatible parameters
        model = self.config.get("model", "claude-sonnet-4-20250514")
        max_turns = self.config.get("max_turns")
        max_budget = self.config.get("max_budget_usd")
        permission_mode = self.config.get("permission_mode", "bypassPermissions")
        api_key = self.config.get("api_key")
        auth_token = self.config.get("auth_token")

        print(f"[ClaudeSDKProvider] Creating ClaudeAgentOptions:")
        print(f"  model={model}")
        print(f"  cwd={self.repo_path}")
        print(f"  max_turns={max_turns}")
        print(f"  max_budget_usd={max_budget}")
        print(f"  permission_mode={permission_mode}")
        print(f"  api_key={'SET' if api_key else 'NOT SET'}")
        print(f"  auth_token={'SET' if auth_token else 'NOT SET'}")
        print(f"  mcp_servers keys: {list({'quickhack': self._mcp_server}.keys())}")
        print(f"  mcp_server type: {type(self._mcp_server)}")
        print(f"  system_prompt length: {len(system_prompt)}")

        env: dict[str, str] = {}
        # Claude Code reads credentials from environment variables; pass them directly
        # to the CLI subprocess environment (avoid mutating the backend process env).
        # - `ANTHROPIC_API_KEY` for API key auth (X-Api-Key)
        # - `ANTHROPIC_AUTH_TOKEN` for OAuth-style tokens (Authorization: Bearer)
        resolved_auth_token = (auth_token or "").strip() or (os.environ.get("ANTHROPIC_AUTH_TOKEN") or "").strip()
        resolved_api_key = (api_key or "").strip() or (os.environ.get("ANTHROPIC_API_KEY") or "").strip()

        if resolved_auth_token:
            env["ANTHROPIC_AUTH_TOKEN"] = resolved_auth_token
        elif resolved_api_key:
            # Heuristic: OAuth tokens are commonly `sk-ant-oat*`; treat them as auth tokens.
            if resolved_api_key.lower().startswith("sk-ant-oat"):
                env["ANTHROPIC_AUTH_TOKEN"] = resolved_api_key
            else:
                env["ANTHROPIC_API_KEY"] = resolved_api_key

        options = ClaudeAgentOptions(
            model=model,
            system_prompt=system_prompt,
            mcp_servers={"quickhack": self._mcp_server},
            allowed_tools=allowed_tools,
            cwd=self.repo_path,
            max_turns=max_turns,
            max_budget_usd=max_budget,
            permission_mode=permission_mode,
            env=env,
        )

        # Create ClaudeSDKClient
        print(f"[ClaudeSDKProvider] Creating ClaudeSDKClient...")
        self.client = ClaudeSDKClient(options)
        print(f"[ClaudeSDKProvider] ClaudeSDKClient created: {type(self.client)}")

        # Set session ID
        self.session_id = resume_session_id or str(uuid.uuid4())

        # Connect client
        print(f"[ClaudeSDKProvider] Connecting client...")
        await self.client.connect()
        print(f"[ClaudeSDKProvider] Client connected successfully")

        logger.info(
            f"ClaudeSDKProvider session started: {self.session_id}, "
            f"model={options.model}, tools={len(allowed_tools)}"
        )

        return self.session_id

    def _build_system_prompt(self, audit_policy: str) -> str:
        """Build system prompt incorporating audit policy.

        Args:
            audit_policy: The security audit policy (e.g., "read_only", "full_access")

        Returns:
            System prompt string for the SDK
        """
        return f"""You are a security research assistant analyzing code in {self.repo_path}.

Audit Policy: {audit_policy}

You have access to security research tools through the quickhack MCP server:
- read_file: Read file contents
- search_code: Search for regex patterns
- list_directory: List directory contents
- scan_repo_for_secrets: Scan for hardcoded secrets
- dependency_audit: Audit dependencies for vulnerabilities
- grep_semantic: Search code with context
- list_sink_signals: List security-relevant code patterns
- upsert_sink_signal: Track security patterns
- report_finding: Report security vulnerabilities
- generate_security_report: Generate formatted reports

Focus on finding security vulnerabilities, following data flows from sources to sinks,
and providing actionable security insights."""

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

        try:
            import time as time_module
            # SDK pattern:
            # 1. query() sends the prompt (async, returns None)
            # 2. receive_response() returns AsyncIterator that yields messages until ResultMessage
            print(f"[ClaudeSDKProvider] Sending query: {prompt[:100]}...")
            query_start = time_module.monotonic()
            await self.client.query(prompt)
            query_time = time_module.monotonic() - query_start
            print(f"[ClaudeSDKProvider] query() completed in {query_time:.3f}s")

            # Iterate over the async iterator (NOT await it)
            print("[ClaudeSDKProvider] Receiving response stream...")
            receive_start = time_module.monotonic()
            message_count = 0
            async for message in self.client.receive_response():
                message_count += 1
                msg_type = type(message).__name__
                print(f"[ClaudeSDKProvider] Message {message_count}: {msg_type}")

                ws_events = self._to_ws_events(message)
                for event in ws_events:
                    events.append(event)
                    if on_event:
                        on_event(event)

            receive_time = time_module.monotonic() - receive_start
            total_time = time_module.monotonic() - query_start
            print(f"[ClaudeSDKProvider] Stream complete: {message_count} msgs, {len(events)} events, receive={receive_time:.3f}s, total={total_time:.3f}s")

        except Exception as e:
            print(f"[ClaudeSDKProvider] Error in run_turn: {e}")
            import traceback
            traceback.print_exc()
            raise

        return events

    async def interrupt(self) -> None:
        """Interrupt the current agent operation.

        Safe to call even if client is not initialized.
        """
        if self.client is not None:
            # interrupt() may be sync or async depending on SDK version
            result = self.client.interrupt()
            if hasattr(result, '__await__'):
                await result
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
            - ResultMessage -> {type: "turn_complete", total_cost_usd, result}
            - AssistantMessage with TextBlock -> {type: "agent_text", text}
            - AssistantMessage with ToolUseBlock -> {type: "tool_call", id, name, args}
            - AssistantMessage with ToolResultBlock -> {type: "tool_result", tool_use_id, result}
        """
        events: list[dict[str, Any]] = []
        msg_type = msg.__class__.__name__

        if msg_type == "SystemMessage":
            subtype = getattr(msg, "subtype", "unknown")
            data = getattr(msg, "data", {})
            tools = data.get("tools", [])
            tool_count = len(tools) if isinstance(tools, list) else None
            print(
                "[ClaudeSDKProvider] SystemMessage:"
                f" subtype={subtype}"
                f" session_id={data.get('session_id')}"
                f" model={data.get('model')}"
                f" tools={tool_count}"
                f" apiKeySource={data.get('apiKeySource')}"
            )
            events.append({
                "type": "system",
                "subtype": subtype,
                "data": data,
            })

        elif msg_type == "ResultMessage":
            session_id = getattr(msg, "session_id", None)
            duration_ms = getattr(msg, "duration_ms", None)
            cost = getattr(msg, "total_cost_usd", 0.0)
            result = getattr(msg, "result", None)
            usage = getattr(msg, "usage", None)
            is_error = getattr(msg, "is_error", False)
            print(
                "[ClaudeSDKProvider] ResultMessage:"
                f" is_error={is_error}"
                f" cost={cost}"
                f" result={result}"
            )
            events.append({
                "type": "turn_complete",
                "is_error": is_error,
                "total_cost_usd": cost,
                "result": result,
                "usage": usage,
                "session_id": session_id,
                "duration_ms": duration_ms,
            })

        elif msg_type == "AssistantMessage":
            # AssistantMessage.content is list of TextBlock|ThinkingBlock|ToolUseBlock|ToolResultBlock
            content_blocks = getattr(msg, "content", [])
            for block in content_blocks:
                # SDK blocks are class instances, check __class__.__name__ not .type attribute
                block_type = block.__class__.__name__
                fallback_type: str | None = getattr(block, "type", None)
                if isinstance(fallback_type, str):
                    fallback_type = fallback_type.lower()
                else:
                    fallback_type = None

                if block_type == "TextBlock" or fallback_type == "text":
                    # TextBlock has .text attribute
                    text = getattr(block, "text", "")
                    if text:
                        # Debug: Log what Claude is actually saying
                        print(f"[ClaudeSDKProvider] TextBlock content: {text[:200]}{'...' if len(text) > 200 else ''}")
                        events.append({
                            "type": "agent_text",
                            "text": text,
                        })

                elif block_type == "ThinkingBlock" or fallback_type == "thinking":
                    # ThinkingBlock has .thinking attribute
                    thinking = getattr(block, "thinking", "")
                    if thinking:
                        events.append({
                            "type": "agent_thinking",
                            "thinking": thinking,
                        })

                elif block_type == "ToolUseBlock" or fallback_type == "tool_use":
                    # ToolUseBlock has .id, .name, .input attributes
                    events.append({
                        "type": "tool_call",
                        "id": getattr(block, "id", ""),
                        "name": getattr(block, "name", ""),
                        "args": getattr(block, "input", {}),
                    })

                elif block_type == "ToolResultBlock" or fallback_type == "tool_result":
                    # ToolResultBlock has .tool_use_id, .content, .is_error attributes
                    events.append({
                        "type": "tool_result",
                        "tool_use_id": getattr(block, "tool_use_id", ""),
                        "result": getattr(block, "content", ""),
                        "is_error": getattr(block, "is_error", False),
                    })

                else:
                    logger.debug(f"Unknown block type in AssistantMessage: {block_type}")

        else:
            # Unknown message type - log and skip
            logger.debug(f"Unknown SDK message type: {msg_type}")

        return events
