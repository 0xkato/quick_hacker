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


# System prompts for different contexts
CHAT_SYSTEM_PROMPTS = {
    "general": """You are an expert security researcher assistant helping with code auditing.
You have deep knowledge of:
- Web application security (OWASP Top 10)
- Binary exploitation and reverse engineering
- Cryptographic vulnerabilities
- Network security
- Secure coding practices

Be concise but thorough. When analyzing code, point out specific line numbers and explain the vulnerability clearly.
If asked to write exploits or PoCs, provide them for educational/defensive purposes.""",

    "code_review": """You are reviewing code for security vulnerabilities.
Focus on:
1. Input validation and sanitization
2. Authentication and authorization flaws
3. Injection vulnerabilities (SQL, command, XSS)
4. Cryptographic issues
5. Business logic flaws
6. Race conditions
7. Information disclosure

For each issue found, provide:
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Line number(s)
- Description
- Attack scenario
- Recommended fix""",

    "exploit_dev": """You are helping develop proof-of-concept exploits for identified vulnerabilities.
This is for authorized security testing and educational purposes.

For each exploit:
1. Explain the vulnerability being exploited
2. Show the exact payload
3. Explain how it bypasses protections
4. Describe the expected impact
5. Suggest mitigations""",

    "findings_analysis": """You are analyzing security findings from an automated scan.
Help the user:
1. Understand the severity and impact
2. Verify if findings are true positives
3. Prioritize remediation efforts
4. Develop fixes
5. Write security advisories""",
}


def get_system_prompt(context: Optional[dict]) -> str:
    """Generate system prompt based on context."""
    base_prompt = CHAT_SYSTEM_PROMPTS["general"]

    if not context:
        return base_prompt

    # Add context-specific information
    prompt_parts = [base_prompt]

    if context.get("type") == "code_review":
        prompt_parts.append(CHAT_SYSTEM_PROMPTS["code_review"])

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
        name: prompt[:200] + "..." if len(prompt) > 200 else prompt
        for name, prompt in CHAT_SYSTEM_PROMPTS.items()
    }
