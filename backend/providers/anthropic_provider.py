"""Anthropic provider implementation."""

import json
import logging
from typing import AsyncGenerator, Optional

from anthropic import AsyncAnthropic, APIError, AuthenticationError, RateLimitError, APIConnectionError

logger = logging.getLogger(__name__)

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

    # Models that support extended thinking
    THINKING_MODELS = {
        "claude-opus-4-5-20251101",
        "claude-sonnet-4-20250514",
    }

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

        try:
            response = await self.client.messages.create(**kwargs)
            return response.content[0].text if response.content else ""
        except AuthenticationError as e:
            logger.error(f"Anthropic authentication failed: {e}")
            raise ValueError(
                "Invalid Anthropic API key. Please check your API key in Settings."
            ) from e
        except RateLimitError as e:
            logger.warning(f"Anthropic rate limit hit: {e}")
            raise ValueError(
                "Rate limit exceeded. Please wait a moment and try again."
            ) from e
        except APIConnectionError as e:
            logger.error(f"Anthropic connection error: {e}")
            raise ValueError(
                "Failed to connect to Anthropic API. Please check your internet connection."
            ) from e
        except APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise ValueError(f"Anthropic API error: {e.message}") from e

    async def generate_with_thinking(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
        thinking_budget: int = 10000,
    ) -> tuple[str, Optional[str]]:
        """
        Generate a completion with extended thinking.

        Args:
            messages: Conversation messages
            system_prompt: Optional system prompt
            thinking_budget: Token budget for thinking (default 10000)

        Returns:
            Tuple of (response_text, thinking_text)
            thinking_text is None if model doesn't support extended thinking
        """
        # Check if model supports extended thinking
        supports_thinking = self.model in self.THINKING_MODELS

        # Convert messages
        anthropic_messages = self._convert_messages(messages)

        kwargs = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": self.max_tokens,
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        if supports_thinking:
            # Use extended thinking parameters
            # Extended thinking requires temperature=1
            kwargs["temperature"] = 1.0
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget,
            }
        else:
            if self.temperature > 0:
                kwargs["temperature"] = self.temperature

        try:
            response = await self.client.messages.create(**kwargs)
        except AuthenticationError as e:
            logger.error(f"Anthropic authentication failed: {e}")
            raise ValueError(
                "Invalid Anthropic API key. Please check your API key in Settings."
            ) from e
        except RateLimitError as e:
            logger.warning(f"Anthropic rate limit hit: {e}")
            raise ValueError(
                "Rate limit exceeded. Please wait a moment and try again."
            ) from e
        except APIConnectionError as e:
            logger.error(f"Anthropic connection error: {e}")
            raise ValueError(
                "Failed to connect to Anthropic API. Please check your internet connection."
            ) from e
        except APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise ValueError(f"Anthropic API error: {e.message}") from e

        # Extract thinking and text from response
        thinking_text = None
        response_text = ""

        for block in response.content:
            if hasattr(block, 'type'):
                if block.type == "thinking":
                    thinking_text = block.thinking
                elif block.type == "text":
                    response_text = block.text

        return response_text, thinking_text

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

        try:
            async with self.client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    yield StreamChunk(content=text, is_complete=False)

                yield StreamChunk(content="", is_complete=True)
        except AuthenticationError as e:
            logger.error(f"Anthropic authentication failed: {e}")
            raise ValueError(
                "Invalid Anthropic API key. Please check your API key in Settings."
            ) from e
        except RateLimitError as e:
            logger.warning(f"Anthropic rate limit hit: {e}")
            raise ValueError(
                "Rate limit exceeded. Please wait a moment and try again."
            ) from e
        except APIConnectionError as e:
            logger.error(f"Anthropic connection error: {e}")
            raise ValueError(
                "Failed to connect to Anthropic API. Please check your internet connection."
            ) from e
        except APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise ValueError(f"Anthropic API error: {e.message}") from e

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

        try:
            response = await self.client.messages.create(**kwargs)
        except AuthenticationError as e:
            logger.error(f"Anthropic authentication failed: {e}")
            raise ValueError(
                "Invalid Anthropic API key. Please check your API key in Settings."
            ) from e
        except RateLimitError as e:
            logger.warning(f"Anthropic rate limit hit: {e}")
            raise ValueError(
                "Rate limit exceeded. Please wait a moment and try again."
            ) from e
        except APIConnectionError as e:
            logger.error(f"Anthropic connection error: {e}")
            raise ValueError(
                "Failed to connect to Anthropic API. Please check your internet connection."
            ) from e
        except APIError as e:
            logger.error(f"Anthropic API error: {e}")
            raise ValueError(f"Anthropic API error: {e.message}") from e

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
