"""OpenAI provider implementation."""

import logging
import re
from typing import AsyncGenerator, Optional

from openai import (
    APIConnectionError,
    APIError,
    AsyncOpenAI,
    AuthenticationError,
    RateLimitError,
)

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

    def _uses_responses_api(self) -> bool:
        """GPT-5.* models use the Responses API (v1/responses)."""
        model = (self.model or "").strip()
        return bool(self._GPT5_MODEL_RE.match(model))

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
            return {"max_completion_tokens": self.max_tokens}

        return {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

    def _convert_tools_to_responses(self, tools: list[dict]) -> list[dict]:
        """Convert ChatCompletions-style tools into Responses API tools."""
        converted: list[dict] = []
        for tool in tools or []:
            if tool.get("type") != "function":
                continue
            fn = tool.get("function") or {}
            name = fn.get("name")
            if not name:
                continue
            converted.append(
                {
                    "type": "function",
                    "name": name,
                    "description": fn.get("description"),
                    "parameters": fn.get("parameters"),
                    "strict": False,
                }
            )
        return converted

    def _convert_chat_messages_to_responses_input(self, messages: list[dict]) -> tuple[Optional[str], list[dict]]:
        """Convert ChatCompletions-style messages to Responses API input items."""
        instructions_parts: list[str] = []
        input_items: list[dict] = []

        for msg in messages or []:
            role = (msg.get("role") or "").strip()
            if not role:
                continue

            if role == "system":
                content = msg.get("content")
                if isinstance(content, str) and content.strip():
                    instructions_parts.append(content.strip())
                continue

            if role == "tool":
                call_id = msg.get("tool_call_id") or msg.get("call_id")
                output = msg.get("content")
                if not call_id:
                    continue
                input_items.append(
                    {
                        "type": "function_call_output",
                        "call_id": str(call_id),
                        "output": "" if output is None else str(output),
                    }
                )
                continue

            tool_calls = msg.get("tool_calls") or []
            if role == "assistant" and tool_calls:
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    call_id = tc.get("id") or tc.get("call_id")
                    fn = tc.get("function") or {}
                    name = tc.get("name") or fn.get("name")
                    arguments = tc.get("arguments") or fn.get("arguments") or "{}"
                    if not call_id or not name:
                        continue
                    input_items.append(
                        {
                            "type": "function_call",
                            "call_id": str(call_id),
                            "name": str(name),
                            "arguments": str(arguments),
                        }
                    )
                continue

            content = msg.get("content")
            input_items.append(
                {
                    "type": "message",
                    "role": role,
                    "content": "" if content is None else str(content),
                }
            )

        instructions = "\n\n".join(instructions_parts).strip() if instructions_parts else None
        return instructions or None, input_items

    def _extract_responses_text(self, response) -> str:
        """Best-effort extraction of assistant text from a Responses API response."""
        try:
            text = getattr(response, "output_text", None)
            if isinstance(text, str):
                return text
        except Exception:
            pass

        out: list[str] = []
        for item in getattr(response, "output", []) or []:
            if getattr(item, "type", None) != "message":
                continue
            for part in getattr(item, "content", []) or []:
                if getattr(part, "type", None) == "output_text":
                    out.append(getattr(part, "text", "") or "")
        return "".join(out)

    def _extract_responses_tool_calls(self, response) -> list[dict]:
        """Extract tool calls from a Responses API response and normalize to ChatCompletions format."""
        tool_calls: list[dict] = []
        for item in getattr(response, "output", []) or []:
            if getattr(item, "type", None) != "function_call":
                continue
            call_id = getattr(item, "call_id", None) or getattr(item, "id", None)
            name = getattr(item, "name", None)
            arguments = getattr(item, "arguments", None)
            if not call_id or not name:
                continue
            tool_calls.append(
                {
                    "id": str(call_id),
                    "type": "function",
                    "function": {
                        "name": str(name),
                        "arguments": str(arguments or "{}"),
                    },
                }
            )
        return tool_calls

    async def generate(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> str:
        """Generate a completion (non-streaming)."""
        if self._uses_responses_api():
            instructions_parts: list[str] = []
            if system_prompt and system_prompt.strip():
                instructions_parts.append(system_prompt.strip())

            input_items: list[dict] = []
            for msg in messages or []:
                if msg.role == "system":
                    if msg.content and msg.content.strip():
                        instructions_parts.append(msg.content.strip())
                    continue
                input_items.append(
                    {
                        "type": "message",
                        "role": msg.role,
                        "content": msg.content or "",
                    }
                )

            kwargs: dict = {
                "model": self.model,
                "input": input_items,
                "max_output_tokens": self.max_tokens,
            }
            reasoning_effort = self._default_reasoning_effort()
            if reasoning_effort:
                kwargs["reasoning"] = {"effort": reasoning_effort}
            if self.temperature is not None:
                kwargs["temperature"] = self.temperature
            if instructions_parts:
                kwargs["instructions"] = "\n\n".join(instructions_parts)

            try:
                response = await self.client.responses.create(**kwargs)
                return self._extract_responses_text(response) or ""
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
        if self._uses_responses_api():
            # Some models may not support streaming. Fall back to a single buffered response.
            if not self._supports_streaming():
                content = await self.generate(messages, system_prompt)
                if content:
                    yield StreamChunk(content=content, is_complete=False)
                yield StreamChunk(content="", is_complete=True)
                return

            instructions_parts: list[str] = []
            if system_prompt and system_prompt.strip():
                instructions_parts.append(system_prompt.strip())

            input_items: list[dict] = []
            for msg in messages or []:
                if msg.role == "system":
                    if msg.content and msg.content.strip():
                        instructions_parts.append(msg.content.strip())
                    continue
                input_items.append(
                    {
                        "type": "message",
                        "role": msg.role,
                        "content": msg.content or "",
                    }
                )

            kwargs: dict = {
                "model": self.model,
                "input": input_items,
                "max_output_tokens": self.max_tokens,
                "stream": True,
            }
            reasoning_effort = self._default_reasoning_effort()
            if reasoning_effort:
                kwargs["reasoning"] = {"effort": reasoning_effort}
            if self.temperature is not None:
                kwargs["temperature"] = self.temperature
            if instructions_parts:
                kwargs["instructions"] = "\n\n".join(instructions_parts)

            try:
                stream = await self.client.responses.create(**kwargs)
                async for event in stream:
                    delta = getattr(event, "delta", None)
                    if isinstance(delta, str) and delta:
                        yield StreamChunk(content=delta, is_complete=False)
                    if getattr(event, "type", None) == "response.completed":
                        yield StreamChunk(content="", is_complete=True)
                        return
                yield StreamChunk(content="", is_complete=True)
                return
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
        if self._uses_responses_api():
            instructions, input_items = self._convert_chat_messages_to_responses_input(messages)
            response_tools = self._convert_tools_to_responses(tools)

            kwargs: dict = {
                "model": self.model,
                "input": input_items,
                "max_output_tokens": self.max_tokens,
            }
            if instructions:
                kwargs["instructions"] = instructions

            reasoning_effort = self._default_reasoning_effort()
            if reasoning_effort:
                kwargs["reasoning"] = {"effort": reasoning_effort}

            if self.temperature is not None:
                kwargs["temperature"] = self.temperature

            if response_tools:
                kwargs["tools"] = response_tools
                kwargs["tool_choice"] = "auto"

            try:
                response = await self.client.responses.create(**kwargs)
                tool_calls = self._extract_responses_tool_calls(response)

                result = {
                    "content": self._extract_responses_text(response) or "",
                    "tool_calls": tool_calls or None,
                    "usage": None,
                }

                usage = getattr(response, "usage", None)
                if usage:
                    input_tokens = getattr(usage, "input_tokens", None)
                    output_tokens = getattr(usage, "output_tokens", None)
                    total_tokens = getattr(usage, "total_tokens", None)
                    result["usage"] = {
                        "prompt_tokens": int(input_tokens or 0),
                        "completion_tokens": int(output_tokens or 0),
                        "total_tokens": int(total_tokens or (int(input_tokens or 0) + int(output_tokens or 0))),
                    }

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
