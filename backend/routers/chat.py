"""Chat API endpoints for AI-assisted analysis."""

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, AsyncGenerator
import json
import asyncio

from services.settings_service import settings_service
from providers import Message, get_provider
from models.schemas import ProviderType, ProviderConfig
from prompting_loader import load_prompt

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatMessage(BaseModel):
    role: str  # user, assistant, system
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    context: Optional[dict] = None  # file content, findings, etc.
    provider: Optional[str] = None  # openai, anthropic, ollama
    model: Optional[str] = None
    stream: bool = True
    system_prompt: Optional[str] = None


class ChatResponse(BaseModel):
    content: str
    model: str
    provider: str
    usage: Optional[dict] = None


CHAT_SYSTEM_PROMPT_FILES = {
    "general": "chat/general.md",
    "code_review": "chat/code_review.md",
    "exploit_dev": "chat/exploit_dev.md",
    "findings_analysis": "chat/findings_analysis.md",
}

FLOW_CONTEXT_MAX_FIELD_CHARS = 2500
FLOW_CONTEXT_MAX_PATH_NODES = 30


def _get_chat_system_prompt(name: str) -> str:
    relative_path = CHAT_SYSTEM_PROMPT_FILES.get(name)
    if not relative_path:
        raise ValueError(f"Unknown chat system prompt: {name}")
    return load_prompt(relative_path)


def _truncate_text(value: str, max_chars: int = FLOW_CONTEXT_MAX_FIELD_CHARS) -> str:
    if not isinstance(value, str):
        return ""
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n... [truncated]"


def _format_flow_context_pack(pack: dict) -> str:
    """Format a compact, safe 'context pack' for post-scan follow-up chat."""
    if not isinstance(pack, dict):
        return ""

    selected = pack.get("selected_node")
    selected = selected if isinstance(selected, dict) else {}

    def _get_str(obj: dict, key: str) -> str:
        val = obj.get(key)
        return val.strip() if isinstance(val, str) else ""

    def _get_int(obj: dict, key: str) -> int | None:
        val = obj.get(key)
        return val if isinstance(val, int) else None

    selected_id = _get_str(selected, "id")
    selected_type = _get_str(selected, "type")
    selected_label = _get_str(selected, "label")

    lines: list[str] = []
    lines.append("Flow Context (from scan diagram)")
    if selected_label or selected_type or selected_id:
        header_bits = []
        if selected_type:
            header_bits.append(f"[{selected_type}]")
        if selected_label:
            header_bits.append(selected_label)
        if selected_id:
            header_bits.append(f"(id={selected_id})")
        lines.append("Selected node: " + " ".join(header_bits))

    path = pack.get("path")
    if isinstance(path, list) and path:
        path_lines: list[str] = []
        for item in path[:FLOW_CONTEXT_MAX_PATH_NODES]:
            if not isinstance(item, dict):
                continue
            node_type = _get_str(item, "type") or "node"
            node_label = _get_str(item, "label") or _get_str(item, "id") or "(unnamed)"
            file_path = _get_str(item, "file_path")
            line_num = _get_int(item, "line_number") or _get_int(item, "line_start")
            loc = ""
            if file_path:
                loc = f" ({file_path}{':' + str(line_num) if isinstance(line_num, int) else ''})"
            path_lines.append(f"- {node_type}: {node_label}{loc}")
        if path_lines:
            lines.append("")
            lines.append("Path:")
            lines.extend(path_lines)

    finding = pack.get("finding")
    if isinstance(finding, dict) and finding:
        severity = _get_str(finding, "severity") or "unknown"
        title = _get_str(finding, "title") or "Unknown finding"
        file_path = _get_str(finding, "file_path")
        line_start = _get_int(finding, "line_start")
        vuln_type = _get_str(finding, "vulnerability_type")
        loc = ""
        if file_path:
            loc = f" ({file_path}{':' + str(line_start) if isinstance(line_start, int) else ''})"
        meta_bits = []
        if vuln_type:
            meta_bits.append(f"type={vuln_type}")
        lines.append("")
        lines.append(f"Finding: [{severity}] {title}{loc}" + (f" ({', '.join(meta_bits)})" if meta_bits else ""))
        description = _get_str(finding, "description")
        if description:
            lines.append("")
            lines.append("Finding description:")
            lines.append(_truncate_text(description))

    # Selected node details (best-effort; capped).
    for key, title in (
        ("tool_result_summary", "Tool result summary"),
        ("code_context", "Code context"),
        ("llm_reasoning", "LLM reasoning"),
    ):
        raw = selected.get(key)
        if isinstance(raw, str) and raw.strip():
            lines.append("")
            lines.append(f"{title}:")
            lines.append("```")
            lines.append(_truncate_text(raw))
            lines.append("```")

    return "\n".join(lines)


def get_system_prompt(context: Optional[dict]) -> str:
    """Generate system prompt based on context."""
    base_prompt = _get_chat_system_prompt("general")

    if not context:
        return base_prompt

    # Add context-specific information
    prompt_parts = [base_prompt]

    if context.get("type") == "code_review":
        prompt_parts.append(_get_chat_system_prompt("code_review"))

    if context.get("current_file"):
        prompt_parts.append(f"\nCurrently viewing file: {context['current_file']}")

    if context.get("file_content"):
        content = context["file_content"]
        if len(content) > 5000:
            content = content[:5000] + "\n... [truncated]"
        prompt_parts.append(f"\nFile content:\n```\n{content}\n```")

    if context.get("findings"):
        findings_summary = "\n".join([
            f"- [{f.get('severity', 'UNKNOWN')}] {f.get('title', 'Unknown')} at line {f.get('line_start', '?')}"
            for f in context["findings"][:10]
        ])
        prompt_parts.append(f"\nCurrent findings:\n{findings_summary}")

    if context.get("selected_text"):
        prompt_parts.append(f"\nUser selected code:\n```\n{context['selected_text']}\n```")

    if context.get("flow_context_pack"):
        flow_section = _format_flow_context_pack(context.get("flow_context_pack"))
        if flow_section:
            prompt_parts.append("\n" + flow_section)

    return "\n\n".join(prompt_parts)


async def stream_chat_response(
    messages: list[Message],
    provider_name: str,
    model: str,
    system_prompt: str,
) -> AsyncGenerator[str, None]:
    """Stream chat response."""
    settings = await settings_service.get_settings()

    # Get provider settings
    provider_settings = settings.providers.get(provider_name)
    if not provider_settings:
        yield f"data: {json.dumps({'error': f'Provider not found: {provider_name}'})}\n\n"
        return

    if not provider_settings.api_key and provider_name != "ollama":
        yield f"data: {json.dumps({'error': f'No API key for {provider_name}'})}\n\n"
        return

    # Create provider config
    provider_type = ProviderType(provider_name)
    config = ProviderConfig(
        provider=provider_type,
        model=model or provider_settings.default_model,
        api_key=provider_settings.api_key,
        base_url=provider_settings.base_url,
    )

    try:
        provider = get_provider(config)

        async for chunk in provider.generate_stream(messages, system_prompt):
            if chunk.content:
                yield f"data: {json.dumps({'content': chunk.content, 'done': False})}\n\n"
            if chunk.is_complete:
                yield f"data: {json.dumps({'content': '', 'done': True})}\n\n"
                break

    except Exception as e:
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


@router.post("/stream")
async def chat_stream(request: ChatRequest):
    """Stream chat response."""
    settings = await settings_service.get_settings()

    # Determine provider and model
    provider_name = request.provider or settings.agent_defaults.default_provider
    model = request.model or settings.providers.get(provider_name, {}).default_model

    # Build system prompt
    system_prompt = request.system_prompt or get_system_prompt(request.context)

    # Convert messages
    messages = [Message(role=m.role, content=m.content) for m in request.messages]

    return StreamingResponse(
        stream_chat_response(messages, provider_name, model, system_prompt),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("")
async def chat(request: ChatRequest) -> ChatResponse:
    """Non-streaming chat endpoint."""
    settings = await settings_service.get_settings()

    # Determine provider and model
    provider_name = request.provider or settings.agent_defaults.default_provider
    provider_settings = settings.providers.get(provider_name)

    if not provider_settings:
        raise HTTPException(404, f"Provider not found: {provider_name}")

    if not provider_settings.api_key and provider_name != "ollama":
        raise HTTPException(400, f"No API key configured for {provider_name}")

    model = request.model or provider_settings.default_model

    # Build system prompt
    system_prompt = request.system_prompt or get_system_prompt(request.context)

    # Convert messages
    messages = [Message(role=m.role, content=m.content) for m in request.messages]

    # Create provider config
    provider_type = ProviderType(provider_name)
    config = ProviderConfig(
        provider=provider_type,
        model=model,
        api_key=provider_settings.api_key,
        base_url=provider_settings.base_url,
    )

    try:
        provider = get_provider(config)
        response = await provider.generate(messages, system_prompt)

        return ChatResponse(
            content=response,
            model=model,
            provider=provider_name,
        )
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/prompts")
async def get_chat_prompts():
    """Get available chat system prompts."""
    return {
        name: (
            prompt[:200] + "..."
            if len(prompt := _get_chat_system_prompt(name)) > 200
            else prompt
        )
        for name in CHAT_SYSTEM_PROMPT_FILES
    }
