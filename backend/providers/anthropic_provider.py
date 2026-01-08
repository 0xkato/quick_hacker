"""Anthropic provider implementation."""

import json
from typing import AsyncGenerator, Optional

from anthropic import AsyncAnthropic

from config import settings
from models.schemas import ProviderConfig
from .base_provider import BaseProvider, Message, StreamChunk, estimate_tokens, sanitize_string


class AnthropicProvider(BaseProvider):
    """Provider for Anthropic models (Claude)."""

    provider_type = "anthropic"

    MODELS = [
        "claude-opus-4-5-20251101",
        "claude-sonnet-4-20250514",
        "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku-20241022",
        "claude-3-opus-20240229",
        "claude-3-sonnet-20240229",
        "claude-3-haiku-20240307",
    ]

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        # Sanitize API key to remove invisible Unicode characters
        api_key = sanitize_string(config.api_key) or sanitize_string(settings.anthropic_api_key)
        if not api_key:
            raise ValueError("Anthropic API key not provided")

        self.client = AsyncAnthropic(
            api_key=api_key,
            base_url=sanitize_string(config.base_url),
        )

    async def generate(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> str:
        """Generate a completion (non-streaming)."""
        anthropic_messages = self._convert_messages(messages)

        kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": self.max_tokens,
        }

        if self.temperature > 0:
            kwargs["temperature"] = self.temperature

        if system_prompt:
            kwargs["system"] = system_prompt

        response = await self.client.messages.create(**kwargs)

        return response.content[0].text if response.content else ""

    async def generate_stream(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """Generate a completion with streaming."""
        anthropic_messages = self._convert_messages(messages)

        kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": self.max_tokens,
        }

        if self.temperature > 0:
            kwargs["temperature"] = self.temperature

        if system_prompt:
            kwargs["system"] = system_prompt

        async with self.client.messages.stream(**kwargs) as stream:
            async for text in stream.text_stream:
                yield StreamChunk(content=text, is_complete=False)

            yield StreamChunk(content="", is_complete=True)

    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
    ) -> dict:
        """Generate a completion with tool use capability."""
        # Convert OpenAI tool format to Anthropic format
        anthropic_tools = []
        for tool in tools:
            func = tool.get("function", tool)
            anthropic_tools.append({
                "name": func["name"],
                "description": func["description"],
                "input_schema": func["parameters"]
            })

        # Convert messages to Anthropic format
        anthropic_messages = []
        system_prompt = None

        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")

            if role == "system":
                system_prompt = content
                continue

            if role == "tool":
                # Tool result - add as user message with tool_result content
                anthropic_messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", "unknown"),
                        "content": content or ""
                    }]
                })
                continue

            if role == "assistant":
                # Check if this was a tool call response
                tool_calls = msg.get("tool_calls")
                if tool_calls:
                    # Create assistant message with tool_use blocks
                    tool_use_blocks = []
                    for tc in tool_calls:
                        tool_use_blocks.append({
                            "type": "tool_use",
                            "id": tc.get("id", "unknown"),
                            "name": tc.get("name") or tc.get("function", {}).get("name"),
                            "input": json.loads(tc.get("arguments") or tc.get("function", {}).get("arguments", "{}"))
                        })
                    anthropic_messages.append({
                        "role": "assistant",
                        "content": tool_use_blocks
                    })
                else:
                    anthropic_messages.append({
                        "role": "assistant",
                        "content": content or ""
                    })
                continue

            # User message
            anthropic_messages.append({
                "role": role,
                "content": content or ""
            })

        kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": self.max_tokens,
            "tools": anthropic_tools if anthropic_tools else None,
        }

        if self.temperature > 0:
            kwargs["temperature"] = self.temperature

        if system_prompt:
            kwargs["system"] = system_prompt

        response = await self.client.messages.create(**kwargs)

        result = {
            "content": "",
            "tool_calls": None,
            "usage": None,
        }

        # Capture token usage from response
        if response.usage:
            result["usage"] = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            }

        # Process response content blocks
        tool_calls = []
        for block in response.content:
            if block.type == "text":
                result["content"] += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": json.dumps(block.input)
                })

        if tool_calls:
            result["tool_calls"] = tool_calls

        return result

    async def count_tokens(self, text: str) -> int:
        """Estimate token count (Anthropic doesn't expose tokenizer)."""
        return estimate_tokens(text)

    @classmethod
    def list_models(cls) -> list[str]:
        """List available Anthropic models."""
        return cls.MODELS

    def _convert_messages(self, messages: list[Message]) -> list[dict]:
        """Convert to Anthropic message format."""
        anthropic_messages = []

        for msg in messages:
            # Skip system messages (handled separately)
            if msg.role == "system":
                continue

            anthropic_messages.append({
                "role": msg.role,
                "content": msg.content,
            })

        return anthropic_messages
