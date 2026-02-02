"""
Observability Service - Tracks LLM interactions and tool executions.

Provides real-time visibility into agent decision-making process.
"""

import uuid
from datetime import datetime
from typing import Optional, Callable, Any
from collections import defaultdict

from models.observability import (
    LLMInteraction,
    LLMInteractionType,
    ToolDetail,
    TokenUsage,
)
from models.schemas import WSMessage, WSMessageType


def truncate_for_summary(text: str, max_length: int = 200) -> str:
    """Truncate text for summary display."""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def format_messages_summary(messages: list[dict]) -> str:
    """Create a summary of conversation messages."""
    if not messages:
        return "No messages"

    parts = []
    for msg in messages[-3:]:  # Last 3 messages
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(f"{role}: {truncate_for_summary(content, 50)}")

    return " | ".join(parts)


def format_tool_args_summary(tool_name: str, args: dict) -> str:
    """Create a human-readable summary of tool arguments."""
    # Normalize tool name (some providers use different naming)
    name_lower = tool_name.lower()

    if name_lower in ("read_file", "readfile", "read"):
        # Check multiple possible key names
        path = args.get('path') or args.get('file_path') or args.get('file') or 'unknown'
        start = args.get('start_line')
        end = args.get('end_line')
        if start and end:
            return f"Read: {path}:{start}-{end}"
        return f"Read: {path}"
    elif name_lower in ("list_files", "listfiles", "list_directory"):
        return f"List: {args.get('path', args.get('directory', '.'))}"
    elif name_lower in ("search_code", "searchcode", "search"):
        return f"Search: {args.get('pattern', args.get('query', 'unknown'))}"
    elif name_lower in ("grep_search", "grep", "ripgrep"):
        return f"Grep: {args.get('pattern', args.get('query', 'unknown'))}"
    elif name_lower in ("find_definition", "finddefinition", "goto_definition"):
        return f"Find def: {args.get('symbol', args.get('name', 'unknown'))}"
    elif name_lower in ("report_finding", "reportfinding", "create_finding"):
        severity = args.get("severity", "unknown")
        title = args.get("title", "unknown")
        return f"Finding ({severity}): {truncate_for_summary(title, 50)}"
    elif name_lower in ("write_file", "writefile", "write"):
        path = args.get('path') or args.get('file_path') or args.get('file') or 'unknown'
        return f"Write: {path}"
    elif name_lower in ("execute", "run_command", "shell"):
        cmd = args.get('command', args.get('cmd', 'unknown'))
        return f"Execute: {truncate_for_summary(cmd, 50)}"
    else:
        # Generic summary - show first few args
        arg_strs = [f"{k}={truncate_for_summary(str(v), 30)}" for k, v in list(args.items())[:3]]
        return f"{tool_name}({', '.join(arg_strs)})"


def format_tool_result_summary(result: Any) -> str:
    """Create a human-readable summary of tool result."""
    if result is None:
        return "No result"
    if isinstance(result, str):
        lines = result.split("\n")
        if len(lines) > 5:
            return f"{len(lines)} lines of output"
        return truncate_for_summary(result, 100)
    if isinstance(result, list):
        return f"List with {len(result)} items"
    if isinstance(result, dict):
        if "error" in result:
            return f"Error: {truncate_for_summary(str(result['error']), 80)}"
        return f"Dict with keys: {', '.join(list(result.keys())[:5])}"
    return truncate_for_summary(str(result), 100)


class ObservabilityService:
    """Manages LLM interaction and tool execution logging."""

    # Bounds to prevent unbounded memory growth
    MAX_INTERACTIONS_PER_AGENT = 1000
    MAX_TOOL_DETAILS_PER_AGENT = 1000

    def __init__(self):
        # agent_id -> list of interactions
        self._interactions: dict[str, list[LLMInteraction]] = defaultdict(list)
        # agent_id -> list of tool details
        self._tool_details: dict[str, list[ToolDetail]] = defaultdict(list)
        # agent_id -> cumulative token usage
        self._token_usage: dict[str, TokenUsage] = {}
        # WebSocket broadcast callback
        self._broadcast_callback: Optional[Callable[[WSMessage], None]] = None

    def set_broadcast_callback(self, callback: Callable[[WSMessage], None]) -> None:
        """Set the callback for broadcasting messages via WebSocket."""
        self._broadcast_callback = callback

    def _broadcast(self, message: WSMessage) -> None:
        """Broadcast message to WebSocket clients."""
        if self._broadcast_callback:
            try:
                self._broadcast_callback(message)
            except Exception as e:
                print(f"[Observability] Broadcast error: {e}")

    # === LLM Interaction Logging ===

    def log_llm_request(
        self,
        agent_id: str,
        messages: list[dict],
        tools_available: Optional[list[str]] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> str:
        """Log an LLM request and return the request ID."""
        request_id = str(uuid.uuid4())[:12]

        # Build full content representation
        full_content = ""
        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if content:
                full_content += f"[{role}]\n{content}\n\n"

        interaction = LLMInteraction(
            id=request_id,
            agent_id=agent_id,
            interaction_type=LLMInteractionType.REQUEST,
            summary=format_messages_summary(messages),
            full_content=full_content,
            messages=messages,
            tools_available=tools_available,
            model=model,
            provider=provider,
        )

        self._interactions[agent_id].append(interaction)
        # Evict oldest entries if over limit to prevent unbounded memory growth
        while len(self._interactions[agent_id]) > self.MAX_INTERACTIONS_PER_AGENT:
            self._interactions[agent_id].pop(0)

        # Broadcast to WebSocket
        self._broadcast(WSMessage(
            type=WSMessageType.LLM_REQUEST,
            agent_id=agent_id,
            data=interaction.model_dump(exclude_none=True),
        ))

        return request_id

    def log_llm_response(
        self,
        agent_id: str,
        request_id: str,
        content: str,
        tool_calls: Optional[list[dict]] = None,
        usage: Optional[dict] = None,
        duration_ms: Optional[int] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        subagent: Optional[str] = None,
    ) -> None:
        """Log an LLM response."""
        response_id = str(uuid.uuid4())[:12]

        # Build summary
        if tool_calls:
            tool_names = [tc.get("function", {}).get("name") or tc.get("name", "unknown")
                          for tc in tool_calls]
            summary = f"Calling: {', '.join(tool_names)}"
        else:
            summary = truncate_for_summary(content, 200)

        # Build full content
        full_content = content
        if tool_calls:
            full_content += "\n\n[Tool Calls]\n"
            for tc in tool_calls:
                name = tc.get("function", {}).get("name") or tc.get("name", "unknown")
                args = tc.get("function", {}).get("arguments") or tc.get("arguments", "{}")
                full_content += f"- {name}: {args}\n"

        # Extract token usage
        prompt_tokens = None
        completion_tokens = None
        total_tokens = None
        if usage:
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")
            total_tokens = usage.get("total_tokens")

            # Update cumulative usage
            current = self._token_usage.get(agent_id, TokenUsage())
            self._token_usage[agent_id] = TokenUsage(
                prompt_tokens=current.prompt_tokens + (prompt_tokens or 0),
                completion_tokens=current.completion_tokens + (completion_tokens or 0),
                total_tokens=current.total_tokens + (total_tokens or 0),
            )

        interaction = LLMInteraction(
            id=response_id,
            agent_id=agent_id,
            interaction_type=LLMInteractionType.RESPONSE,
            summary=summary,
            full_content=full_content,
            tool_calls=tool_calls,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            duration_ms=duration_ms,
            model=model,
            provider=provider,
            request_id=request_id,
            subagent=subagent,
        )

        self._interactions[agent_id].append(interaction)
        # Evict oldest entries if over limit to prevent unbounded memory growth
        while len(self._interactions[agent_id]) > self.MAX_INTERACTIONS_PER_AGENT:
            self._interactions[agent_id].pop(0)

        # Broadcast to WebSocket
        self._broadcast(WSMessage(
            type=WSMessageType.LLM_RESPONSE,
            agent_id=agent_id,
            data=interaction.model_dump(exclude_none=True),
        ))

    # === Tool Execution Logging ===

    def log_tool_execution(
        self,
        agent_id: str,
        tool_name: str,
        tool_call_id: str,
        arguments: dict,
        result: Any,
        success: bool,
        duration_ms: int,
        error_message: Optional[str] = None,
        code_context: Optional[dict] = None,
        llm_reasoning: Optional[str] = None,
        confidence_score: Optional[float] = None,
        subagent: Optional[str] = None,
    ) -> str:
        """Log a tool execution."""
        detail_id = str(uuid.uuid4())[:12]

        tool_detail = ToolDetail(
            id=detail_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            arguments=arguments,
            arguments_summary=format_tool_args_summary(tool_name, arguments),
            result=result if len(str(result)) < 10000 else format_tool_result_summary(result),
            result_summary=format_tool_result_summary(result),
            success=success,
            error_message=error_message,
            code_context=code_context,
            duration_ms=duration_ms,
            llm_reasoning=llm_reasoning,
            confidence_score=confidence_score,
            subagent=subagent,
        )

        self._tool_details[agent_id].append(tool_detail)
        # Evict oldest entries if over limit to prevent unbounded memory growth
        while len(self._tool_details[agent_id]) > self.MAX_TOOL_DETAILS_PER_AGENT:
            self._tool_details[agent_id].pop(0)

        # Broadcast to WebSocket
        self._broadcast(WSMessage(
            type=WSMessageType.TOOL_DETAIL,
            agent_id=agent_id,
            data=tool_detail.model_dump(exclude_none=True),
        ))

        return detail_id

    # === Critic Loop Logging ===

    def log_critic_started(
        self,
        agent_id: str,
        span_id: str,
        parent_span_id: str,
        pass_number: int,
    ) -> None:
        """Log critic evaluation start."""
        self._broadcast(WSMessage(
            type=WSMessageType.PROGRESS,
            agent_id=agent_id,
            data={
                "event": "critic_started",
                "span_id": span_id,
                "parent_span_id": parent_span_id,
                "pass_number": pass_number,
                "timestamp": datetime.utcnow().isoformat(),
            },
        ))

    def log_critic_decision(
        self,
        agent_id: str,
        span_id: str,
        decision: str,
        reasoning: Optional[str] = None,
    ) -> None:
        """Log critic decision."""
        self._broadcast(WSMessage(
            type=WSMessageType.PROGRESS,
            agent_id=agent_id,
            data={
                "event": "critic_decision",
                "span_id": span_id,
                "decision": decision,
                "reasoning": reasoning,
                "timestamp": datetime.utcnow().isoformat(),
            },
        ))

    def log_critic_output(
        self,
        agent_id: str,
        span_id: str,
        blocking_gaps: list[str],
        recommended_tool_calls: list[str],
        disposition_hint: Optional[str] = None,
    ) -> None:
        """Log critic output details."""
        self._broadcast(WSMessage(
            type=WSMessageType.PROGRESS,
            agent_id=agent_id,
            data={
                "event": "critic_output",
                "span_id": span_id,
                "blocking_gaps": blocking_gaps,
                "recommended_tool_calls": recommended_tool_calls,
                "disposition_hint": disposition_hint,
                "timestamp": datetime.utcnow().isoformat(),
            },
        ))

    def log_critic_completed(
        self,
        agent_id: str,
        span_id: str,
    ) -> None:
        """Log critic evaluation completion."""
        self._broadcast(WSMessage(
            type=WSMessageType.PROGRESS,
            agent_id=agent_id,
            data={
                "event": "critic_completed",
                "span_id": span_id,
                "timestamp": datetime.utcnow().isoformat(),
            },
        ))

    # === Data Retrieval ===

    def get_interactions(
        self,
        agent_id: str,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[LLMInteraction]:
        """Get LLM interactions for an agent."""
        interactions = self._interactions.get(agent_id, [])
        if offset:
            interactions = interactions[offset:]
        if limit:
            interactions = interactions[:limit]
        return interactions

    def get_tool_details(
        self,
        agent_id: str,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[ToolDetail]:
        """Get tool execution details for an agent."""
        details = self._tool_details.get(agent_id, [])
        if offset:
            details = details[offset:]
        if limit:
            details = details[:limit]
        return details

    def get_token_usage(self, agent_id: str) -> TokenUsage:
        """Get cumulative token usage for an agent."""
        return self._token_usage.get(agent_id, TokenUsage())

    def get_stats(self, agent_id: str) -> dict:
        """Get observability statistics for an agent."""
        interactions = self._interactions.get(agent_id, [])
        tool_details = self._tool_details.get(agent_id, [])
        usage = self.get_token_usage(agent_id)

        request_count = sum(1 for i in interactions if i.interaction_type == LLMInteractionType.REQUEST)
        response_count = sum(1 for i in interactions if i.interaction_type == LLMInteractionType.RESPONSE)

        tool_counts = defaultdict(int)
        for td in tool_details:
            tool_counts[td.tool_name] += 1

        return {
            "total_interactions": len(interactions),
            "request_count": request_count,
            "response_count": response_count,
            "tool_executions": len(tool_details),
            "tool_counts": dict(tool_counts),
            "token_usage": {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            },
        }

    def clear_agent(self, agent_id: str) -> None:
        """Clear all observability data for an agent."""
        if agent_id in self._interactions:
            del self._interactions[agent_id]
        if agent_id in self._tool_details:
            del self._tool_details[agent_id]
        if agent_id in self._token_usage:
            del self._token_usage[agent_id]

    def export_for_state(self, agent_id: str) -> dict:
        """Export observability data for state persistence."""
        return {
            "interactions": [i.model_dump() for i in self._interactions.get(agent_id, [])],
            "tool_details": [t.model_dump() for t in self._tool_details.get(agent_id, [])],
            "token_usage": self.get_token_usage(agent_id).model_dump(),
        }


# Global instance
observability_service = ObservabilityService()
