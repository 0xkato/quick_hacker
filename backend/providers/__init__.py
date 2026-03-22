"""AI model providers for quick_hack."""

from models.schemas import ProviderConfig, ProviderType
from .base_provider import BaseProvider, Message, StreamChunk
from .anthropic_provider import AnthropicProvider
from .claude_sdk_provider import ClaudeSDKProvider
from .mcp_tools import create_quickhack_mcp_server, MCP_TOOLS


def get_provider(config: ProviderConfig) -> BaseProvider:
    """Factory function to get the appropriate provider."""
    providers = {
        ProviderType.ANTHROPIC: AnthropicProvider,
    }

    provider_class = providers.get(config.provider)
    if not provider_class:
        raise ValueError(f"Unknown provider: {config.provider}")

    return provider_class(config)


def list_all_models() -> dict[str, list[str]]:
    """List all available models by provider."""
    return {
        "anthropic": AnthropicProvider.list_models(),
    }


__all__ = [
    "BaseProvider",
    "Message",
    "StreamChunk",
    "AnthropicProvider",
    "ClaudeSDKProvider",
    "create_quickhack_mcp_server",
    "MCP_TOOLS",
    "get_provider",
    "list_all_models",
]
