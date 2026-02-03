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
from prompting_loader import render_prompt

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
        max_turns = self.config.get("max_turns")  # None = no limit, controlled by time budget
        max_budget = self.config.get("max_budget_usd")
        permission_mode = self.config.get("permission_mode", "bypassPermissions")
        api_key = self.config.get("api_key")
        auth_token = self.config.get("auth_token")

        # Determine auth mode: explicit selection from config
        # use_claude_code_auth=True → Claude Code subscription auth
        # use_claude_code_auth=False (default) → API key mode
        #
        # Claude Code auth loads user-level settings/tools which can conflict with our MCP tools,
        # so we default to API key mode unless explicitly requested.
        use_claude_code_auth = self.config.get("use_claude_code_auth", False)

        print(f"[ClaudeSDKProvider] Creating ClaudeAgentOptions:")
        print(f"  model={model}")
        print(f"  cwd={self.repo_path}")
        print(f"  max_turns={max_turns}")
        print(f"  max_budget_usd={max_budget}")
        print(f"  permission_mode={permission_mode}")
        print(f"  api_key={'SET' if api_key else 'NOT SET'}")
        print(f"  auth_token={'SET' if auth_token else 'NOT SET'}")
        print(f"  auth_mode={'CLAUDE_CODE' if use_claude_code_auth else 'API_KEY'}")
        print(f"  mcp_servers keys: {list({'quickhack': self._mcp_server}.keys())}")
        print(f"  mcp_server type: {type(self._mcp_server)}")
        print(f"  system_prompt length: {len(system_prompt)}")

        env: dict[str, str] = {}
        setting_sources: list[str] | None = None

        if use_claude_code_auth:
            # Claude Code mode: use subscription auth from user settings
            # Set setting_sources to ["user"] so SDK loads user's Claude Code auth
            setting_sources = ["user"]
            print(f"[ClaudeSDKProvider] Using Claude Code auth mode, setting_sources={setting_sources}")
        else:
            # API Key mode: pass credentials via environment variables
            # Don't set setting_sources (SDK defaults to empty, skipping user settings)
            resolved_auth_token = (auth_token or "").strip()
            resolved_api_key = (api_key or "").strip()

            # Fallback to environment variables if not provided via config
            if not resolved_auth_token and not resolved_api_key:
                resolved_auth_token = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()
                resolved_api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
                if resolved_auth_token or resolved_api_key:
                    print(f"[ClaudeSDKProvider] Using credentials from environment variables")

            if resolved_auth_token:
                env["ANTHROPIC_AUTH_TOKEN"] = resolved_auth_token
                print(f"[ClaudeSDKProvider] Using auth_token, prefix: {resolved_auth_token[:15]}...")
            elif resolved_api_key:
                # Heuristic: OAuth tokens are commonly `sk-ant-oat*`; treat them as auth tokens.
                if resolved_api_key.lower().startswith("sk-ant-oat"):
                    env["ANTHROPIC_AUTH_TOKEN"] = resolved_api_key
                    print(f"[ClaudeSDKProvider] OAuth token detected, using ANTHROPIC_AUTH_TOKEN, prefix: {resolved_api_key[:15]}...")
                else:
                    env["ANTHROPIC_API_KEY"] = resolved_api_key
                    print(f"[ClaudeSDKProvider] API key detected, using ANTHROPIC_API_KEY, prefix: {resolved_api_key[:15]}...")
            else:
                print(f"[ClaudeSDKProvider] WARNING: No API key or auth token provided!")
                print(f"[ClaudeSDKProvider] Set ANTHROPIC_API_KEY environment variable or configure in Settings > Providers")
            print(f"[ClaudeSDKProvider] Using API key mode, env keys: {list(env.keys())}")

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
            setting_sources=setting_sources,
            # Disable inherited hooks to prevent "tool use concurrency" errors
            # This is a known Claude Code bug where hooks interfere with parallel
            # tool execution. Plugins (like superpowers) still work, just not hooks.
            # See: https://github.com/anthropics/claude-agent-sdk-python/issues/265
            hooks={},
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
        return render_prompt(
            "agents/claude_sdk_provider_system_prompt.md",
            repo_path=self.repo_path,
            audit_policy=audit_policy,
        )

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
            import asyncio
            import time as time_module
            # SDK pattern:
            # 1. query() sends the prompt (async, returns None)
            # 2. receive_response() returns AsyncIterator that yields messages until ResultMessage
            print(f"[ClaudeSDKProvider] Sending query: {prompt[:100]}...")
            query_start = time_module.monotonic()
            await self.client.query(prompt)
            query_time = time_module.monotonic() - query_start
            print(f"[ClaudeSDKProvider] query() completed in {query_time:.3f}s")

            # Iterate over the async iterator with per-message timeout
            # This prevents hanging indefinitely if the SDK subprocess gets stuck
            # Note: Large repos like Chromium can cause the SDK subprocess to hang
            # in an infinite CPU loop. 2 minutes is enough for normal operations.
            print("[ClaudeSDKProvider] Receiving response stream...")
            receive_start = time_module.monotonic()
            message_count = 0
            MESSAGE_TIMEOUT = 120  # 2 minutes max between messages (reduced from 5)

            response_iter = self.client.receive_response()
            while True:
                try:
                    # Get next message with timeout
                    message = await asyncio.wait_for(
                        anext(response_iter),
                        timeout=MESSAGE_TIMEOUT
                    )
                except StopAsyncIteration:
                    # Normal end of stream
                    break
                except asyncio.TimeoutError:
                    elapsed = time_module.monotonic() - receive_start
                    print(f"[ClaudeSDKProvider] TIMEOUT: No message received for {MESSAGE_TIMEOUT}s (total elapsed: {elapsed:.1f}s)")
                    # Try to interrupt the stuck subprocess
                    try:
                        await self.interrupt()
                    except Exception as int_err:
                        print(f"[ClaudeSDKProvider] Failed to interrupt: {int_err}")
                    raise RuntimeError(f"SDK subprocess appears stuck - no response for {MESSAGE_TIMEOUT} seconds")

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
            - UserMessage with ToolResultBlock -> {type: "tool_result", tool_use_id, result}
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
            # AssistantMessage.content is list of TextBlock|ThinkingBlock|ToolUseBlock
            # Note: ToolResultBlock belongs in UserMessage, not AssistantMessage
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

                else:
                    # ToolResultBlock should NOT appear in AssistantMessage (only in UserMessage)
                    # Log unexpected block types for debugging
                    logger.debug(f"Unexpected block type in AssistantMessage: {block_type}")

        elif msg_type == "UserMessage":
            # UserMessage contains tool results from tool execution
            # UserMessage.content is list of ToolResultBlock
            content_blocks = getattr(msg, "content", [])
            for block in content_blocks:
                block_type = block.__class__.__name__
                fallback_type: str | None = getattr(block, "type", None)
                if isinstance(fallback_type, str):
                    fallback_type = fallback_type.lower()
                else:
                    fallback_type = None

                if block_type == "ToolResultBlock" or fallback_type == "tool_result":
                    # ToolResultBlock has .tool_use_id, .content, .is_error attributes
                    tool_result_content = getattr(block, "content", "")
                    print(f"[ClaudeSDKProvider] ToolResultBlock: tool_use_id={getattr(block, 'tool_use_id', 'unknown')}, is_error={getattr(block, 'is_error', False)}")
                    events.append({
                        "type": "tool_result",
                        "tool_use_id": getattr(block, "tool_use_id", ""),
                        "result": tool_result_content,
                        "is_error": getattr(block, "is_error", False),
                    })

        else:
            # Unknown message type - log and skip
            logger.debug(f"Unknown SDK message type: {msg_type}")

        return events
