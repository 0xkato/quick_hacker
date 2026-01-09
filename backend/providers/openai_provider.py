"""OpenAI provider implementation."""

import logging
import re
from typing import AsyncGenerator, Optional

from openai import AsyncOpenAI, APIError, AuthenticationError, RateLimitError, APIConnectionError

logger = logging.getLogger(__name__)

from config import settings
from models.schemas import ProviderConfig
from .base_provider import BaseProvider, Message, StreamChunk, estimate_tokens, sanitize_string


class OpenAIProvider(BaseProvider):
    """Provider for OpenAI models (GPT-4, GPT-3.5, etc.)."""

    provider_type = "openai"

    MODELS = [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-4-turbo-preview",
        "gpt-4",
        "gpt-3.5-turbo",
        "gpt-5.2",
        "o1",
        "o1-preview",
        "o1-mini",
    ]

    _NO_STREAMING_MODEL_RE = re.compile(r"^o\d", re.IGNORECASE)
    _MAX_COMPLETION_TOKENS_MODEL_RE = re.compile(r"^(o\d|gpt-5)", re.IGNORECASE)
    _GPT5_MODEL_RE = re.compile(r"^gpt-5", re.IGNORECASE)

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        # Sanitize API key to remove invisible Unicode characters
        api_key = sanitize_string(config.api_key) or sanitize_string(settings.openai_api_key)
        if not api_key:
            raise ValueError("OpenAI API key not provided")

        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=sanitize_string(config.base_url),
        )

    def _supports_streaming(self) -> bool:
        model = (self.model or "").strip()
        return not bool(self._NO_STREAMING_MODEL_RE.match(model))

    def _needs_max_completion_tokens(self) -> bool:
        model = (self.model or "").strip()
        return bool(self._MAX_COMPLETION_TOKENS_MODEL_RE.match(model))

    def _default_reasoning_effort(self) -> Optional[str]:
        model = (self.model or "").strip()
        if self._GPT5_MODEL_RE.match(model):
            return "none"
        return None

    def _get_generation_kwargs(self) -> dict:
        if self._needs_max_completion_tokens():
            kwargs = {"max_completion_tokens": self.max_tokens}
            reasoning_effort = self._default_reasoning_effort()
            if reasoning_effort:
                kwargs["reasoning_effort"] = reasoning_effort
            return kwargs

        return {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

    async def generate(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> str:
        """Generate a completion (non-streaming)."""
        openai_messages = self._convert_messages(messages, system_prompt)

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=openai_messages,
                **self._get_generation_kwargs(),
            )
            return response.choices[0].message.content or ""
        except AuthenticationError as e:
            logger.error(f"OpenAI authentication failed: {e}")
            raise ValueError(
                "Invalid OpenAI API key. Please check your API key in Settings."
            ) from e
        except RateLimitError as e:
            logger.warning(f"OpenAI rate limit hit: {e}")
            raise ValueError(
                "Rate limit exceeded. Please wait a moment and try again."
            ) from e
        except APIConnectionError as e:
            logger.error(f"OpenAI connection error: {e}")
            raise ValueError(
                "Failed to connect to OpenAI API. Please check your internet connection."
            ) from e
        except APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise ValueError(f"OpenAI API error: {e.message}") from e

    async def generate_stream(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """Generate a completion with streaming."""
        openai_messages = self._convert_messages(messages, system_prompt)

        # Some OpenAI reasoning models don't support streaming. Fall back to a single buffered response.
        if not self._supports_streaming():
            content = await self.generate(messages, system_prompt)
            if content:
                yield StreamChunk(content=content, is_complete=False)
            yield StreamChunk(content="", is_complete=True)
            return

        try:
            stream = await self.client.chat.completions.create(
                model=self.model,
                messages=openai_messages,
                **self._get_generation_kwargs(),
                stream=True,
            )

            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield StreamChunk(
                        content=chunk.choices[0].delta.content,
                        is_complete=False,
                    )

                if chunk.choices[0].finish_reason:
                    yield StreamChunk(content="", is_complete=True)
        except AuthenticationError as e:
            logger.error(f"OpenAI authentication failed: {e}")
            raise ValueError(
                "Invalid OpenAI API key. Please check your API key in Settings."
            ) from e
        except RateLimitError as e:
            logger.warning(f"OpenAI rate limit hit: {e}")
            raise ValueError(
                "Rate limit exceeded. Please wait a moment and try again."
            ) from e
        except APIConnectionError as e:
            logger.error(f"OpenAI connection error: {e}")
            raise ValueError(
                "Failed to connect to OpenAI API. Please check your internet connection."
            ) from e
        except APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise ValueError(f"OpenAI API error: {e.message}") from e

    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
    ) -> dict:
        """Generate a completion with tool use capability."""
        # Clean messages - remove None content for assistant messages with tool_calls
        clean_messages = []
        for msg in messages:
            clean_msg = {k: v for k, v in msg.items() if v is not None or k == 'content'}
            # For assistant messages with tool_calls, content can be None
            if msg.get('role') == 'assistant' and msg.get('tool_calls'):
                if clean_msg.get('content') is None:
                    clean_msg['content'] = ''
            clean_messages.append(clean_msg)

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=clean_messages,
                tools=tools if tools else None,
                tool_choice="auto" if tools else None,
                **self._get_generation_kwargs(),
            )

            result = {
                "content": response.choices[0].message.content or "",
                "tool_calls": None,
                "usage": None,
            }

            # Capture token usage from response
            if response.usage:
                result["usage"] = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }

            # Extract tool calls if present - format for re-submission to OpenAI
            if response.choices[0].message.tool_calls:
                result["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        }
                    }
                    for tc in response.choices[0].message.tool_calls
                ]

            return result
        except AuthenticationError as e:
            logger.error(f"OpenAI authentication failed: {e}")
            raise ValueError(
                "Invalid OpenAI API key. Please check your API key in Settings."
            ) from e
        except RateLimitError as e:
            logger.warning(f"OpenAI rate limit hit: {e}")
            raise ValueError(
                "Rate limit exceeded. Please wait a moment and try again."
            ) from e
        except APIConnectionError as e:
            logger.error(f"OpenAI connection error: {e}")
            raise ValueError(
                "Failed to connect to OpenAI API. Please check your internet connection."
            ) from e
        except APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise ValueError(f"OpenAI API error: {e.message}") from e

    async def count_tokens(self, text: str) -> int:
        """Count tokens using tiktoken (approximate)."""
        try:
            import tiktoken

            encoding = tiktoken.encoding_for_model(self.model)
            return len(encoding.encode(text))
        except Exception:
            return estimate_tokens(text)

    @classmethod
    def list_models(cls) -> list[str]:
        """List available OpenAI models."""
        return cls.MODELS

    def _convert_messages(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> list[dict]:
        """Convert to OpenAI message format."""
        openai_messages = []

        if system_prompt:
            openai_messages.append({
                "role": "system",
                "content": system_prompt,
            })

        for msg in messages:
            openai_messages.append({
                "role": msg.role,
                "content": msg.content,
            })

        return openai_messages
