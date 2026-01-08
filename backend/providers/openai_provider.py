"""OpenAI provider implementation."""

from typing import AsyncGenerator, Optional

from openai import AsyncOpenAI

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
        "o1-preview",
        "o1-mini",
    ]

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

    async def generate(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> str:
        """Generate a completion (non-streaming)."""
        openai_messages = self._convert_messages(messages, system_prompt)

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        return response.choices[0].message.content or ""

    async def generate_stream(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """Generate a completion with streaming."""
        openai_messages = self._convert_messages(messages, system_prompt)

        stream = await self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
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

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=clean_messages,
            tools=tools if tools else None,
            tool_choice="auto" if tools else None,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
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
