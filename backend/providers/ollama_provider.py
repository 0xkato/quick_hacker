"""Ollama provider implementation for local models."""

import json
from typing import AsyncGenerator, Optional

import httpx

from config import settings
from models.schemas import ProviderConfig
from .base_provider import BaseProvider, Message, StreamChunk, estimate_tokens
from prompting_loader import render_prompt


class OllamaProvider(BaseProvider):
    """Provider for local Ollama models."""

    provider_type = "ollama"

    COMMON_MODELS = [
        "llama3.3:70b",
        "llama3.2:3b",
        "codellama:34b",
        "codellama:13b",
        "codellama:7b",
        "deepseek-coder:33b",
        "deepseek-coder:6.7b",
        "mistral:7b",
        "mixtral:8x7b",
        "qwen2.5-coder:32b",
        "qwen2.5-coder:14b",
        "qwen2.5-coder:7b",
        "phi3:14b",
        "phi3:mini",
    ]

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.base_url = config.base_url or settings.ollama_base_url
        self.client = httpx.AsyncClient(timeout=120.0)

    async def generate(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> str:
        """Generate a completion (non-streaming)."""
        ollama_messages = self._convert_messages(messages, system_prompt)

        response = await self.client.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": ollama_messages,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                },
            },
        )
        response.raise_for_status()

        data = response.json()
        return data.get("message", {}).get("content", "")

    async def generate_stream(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """Generate a completion with streaming."""
        ollama_messages = self._convert_messages(messages, system_prompt)

        async with self.client.stream(
            "POST",
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": ollama_messages,
                "stream": True,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens,
                },
            },
        ) as response:
            response.raise_for_status()

            async for line in response.aiter_lines():
                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "message" in data:
                    content = data["message"].get("content", "")
                    if content:
                        yield StreamChunk(content=content, is_complete=False)

                if data.get("done", False):
                    yield StreamChunk(content="", is_complete=True)
                    break

    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
    ) -> dict:
        """
        Generate a completion with tool use capability.

        Ollama supports native tool use in newer versions.
        Falls back to prompt-based tool use if not supported.
        """
        # Convert to Ollama format
        ollama_messages = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")

            if role == "tool":
                # Tool results as user messages
                ollama_messages.append({
                    "role": "user",
                    "content": f"Tool result: {content}"
                })
            elif role == "assistant" and msg.get("tool_calls"):
                # Previous tool calls
                tool_calls = msg.get("tool_calls", [])
                call_str = "\n".join([
                    f"Called {tc.get('name')}({tc.get('arguments')})"
                    for tc in tool_calls
                ])
                ollama_messages.append({
                    "role": "assistant",
                    "content": call_str
                })
            else:
                ollama_messages.append({
                    "role": role,
                    "content": content or ""
                })

        # Convert tools to Ollama format
        ollama_tools = []
        for tool in tools:
            func = tool.get("function", tool)
            ollama_tools.append({
                "type": "function",
                "function": {
                    "name": func["name"],
                    "description": func["description"],
                    "parameters": func["parameters"]
                }
            })

        try:
            # Try native tool support first
            response = await self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": ollama_messages,
                    "tools": ollama_tools,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": self.max_tokens,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

            result = {
                "content": data.get("message", {}).get("content", ""),
                "tool_calls": None
            }

            # Check for tool calls in response
            if "tool_calls" in data.get("message", {}):
                result["tool_calls"] = [
                    {
                        "id": f"call_{i}",
                        "name": tc["function"]["name"],
                        "arguments": json.dumps(tc["function"]["arguments"])
                    }
                    for i, tc in enumerate(data["message"]["tool_calls"])
                ]

            return result

        except Exception as e:
            # Fallback: prompt-based tool use
            # Add tool descriptions to system prompt
            tools_block = "\n".join(
                [
                    f"- {t['function']['name']}: {t['function']['description']}"
                    for t in ollama_tools
                ]
            )
            tool_desc = render_prompt(
                "providers/ollama_tool_fallback_system_prompt.md",
                tools_block=tools_block,
            )

            fallback_messages = [{"role": "system", "content": tool_desc}] + ollama_messages

            response = await self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": fallback_messages,
                    "stream": False,
                    "options": {
                        "temperature": self.temperature,
                        "num_predict": self.max_tokens,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

            content = data.get("message", {}).get("content", "")

            # Parse tool calls from content
            result = {"content": content, "tool_calls": None}

            # Lazy import re to avoid module-level dependency (used only in fallback path)
            import re as re_module
            tool_match = re_module.search(r'TOOL_CALL:\s*(\w+)\s*\((.+?)\)', content)
            if tool_match:
                result["tool_calls"] = [{
                    "id": "call_0",
                    "name": tool_match.group(1),
                    "arguments": tool_match.group(2)
                }]

            return result

    async def count_tokens(self, text: str) -> int:
        """Estimate token count."""
        return estimate_tokens(text)

    @classmethod
    def list_models(cls) -> list[str]:
        """List common Ollama models."""
        return cls.COMMON_MODELS

    async def list_local_models(self) -> list[str]:
        """List locally installed Ollama models."""
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            data = response.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    def _convert_messages(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> list[dict]:
        """Convert to Ollama message format."""
        ollama_messages = []

        if system_prompt:
            ollama_messages.append({
                "role": "system",
                "content": system_prompt,
            })

        for msg in messages:
            ollama_messages.append({
                "role": msg.role,
                "content": msg.content,
            })

        return ollama_messages

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.client.aclose()
