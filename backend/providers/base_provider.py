"""Base provider interface for AI model providers."""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncGenerator, Optional

from models.schemas import ProviderConfig


def sanitize_string(s: Optional[str]) -> Optional[str]:
    """Remove invisible Unicode characters from a string."""
    if s is None:
        return None
    # Remove zero-width spaces, BOM, and other invisible chars
    # \u200b = zero-width space
    # \ufeff = BOM
    # \u200c = zero-width non-joiner
    # \u200d = zero-width joiner
    # \u2060 = word joiner
    # \u00a0 = non-breaking space (convert to regular space)
    cleaned = re.sub(r'[\u200b\ufeff\u200c\u200d\u2060]', '', s)
    cleaned = cleaned.replace('\u00a0', ' ')
    return cleaned.strip()


@dataclass
class Message:
    """A message in a conversation."""

    role: str  # "system", "user", "assistant"
    content: str


@dataclass
class StreamChunk:
    """A chunk of streamed response."""

    content: str
    is_complete: bool = False
    token_count: Optional[int] = None


class BaseProvider(ABC):
    """Abstract base class for AI model providers."""

    provider_type: str = "base"

    def __init__(self, config: ProviderConfig):
        self.config = config
        # Sanitize model name to remove invisible Unicode characters
        self.model = sanitize_string(config.model) or config.model
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens

    @abstractmethod
    async def generate(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> str:
        """Generate a completion (non-streaming)."""
        pass

    @abstractmethod
    async def generate_stream(
        self,
        messages: list[Message],
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[StreamChunk, None]:
        """Generate a completion with streaming."""
        pass

    @abstractmethod
    async def chat_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
    ) -> dict:
        """
        Generate a completion with tool use capability.

        Args:
            messages: List of message dicts with role and content
            tools: List of tool definitions (OpenAI format)

        Returns:
            Dict with 'content' and optionally 'tool_calls' list
        """
        pass

    @abstractmethod
    async def count_tokens(self, text: str) -> int:
        """Count tokens in text (approximate)."""
        pass

    @classmethod
    @abstractmethod
    def list_models(cls) -> list[str]:
        """List available models for this provider."""
        pass

    def validate_config(self) -> bool:
        """Validate provider configuration."""
        return True


def estimate_tokens(text: str) -> int:
    """Rough token estimation (4 chars per token)."""
    return len(text) // 4
