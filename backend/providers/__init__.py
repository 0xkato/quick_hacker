"""AI model providers for quick_hack."""

from models.schemas import ProviderConfig, ProviderType
from .base_provider import BaseProvider, Message, StreamChunk
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama_provider import OllamaProvider
from .claude_sdk_provider import ClaudeSDKProvider
from .mcp_tools import create_quickhack_mcp_server, MCP_TOOLS


def get_provider(config: ProviderConfig) -> BaseProvider:
    """Factory function to get the appropriate provider."""
    providers = {
        ProviderType.OPENAI: OpenAIProvider,
        ProviderType.ANTHROPIC: AnthropicProvider,
        ProviderType.OLLAMA: OllamaProvider,
    }

    provider_class = providers.get(config.provider)
    if not provider_class:
        raise ValueError(f"Unknown provider: {config.provider}")

    return provider_class(config)


def list_all_models() -> dict[str, list[str]]:
    """List all available models by provider."""
    return {
        "openai": OpenAIProvider.list_models(),
        "anthropic": AnthropicProvider.list_models(),
        "ollama": OllamaProvider.list_models(),
    }


__all__ = [
    "BaseProvider",
    "Message",
    "StreamChunk",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "ClaudeSDKProvider",
    "create_quickhack_mcp_server",
    "MCP_TOOLS",
    "get_provider",
    "list_all_models",
]
