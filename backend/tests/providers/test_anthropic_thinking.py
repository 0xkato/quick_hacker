# tests/providers/test_anthropic_thinking.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from providers.anthropic_provider import AnthropicProvider
from providers.base_provider import Message
from models.schemas import ProviderConfig, ProviderType


@pytest.fixture
def anthropic_config():
    return ProviderConfig(
        provider=ProviderType.ANTHROPIC,
        model="claude-opus-4-6",
        api_key="test-key",
    )


@pytest.mark.asyncio
async def test_generate_with_thinking(anthropic_config):
    """Test extended thinking generation."""
    provider = AnthropicProvider(anthropic_config)

    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(type="thinking", thinking="Internal reasoning here..."),
        MagicMock(type="text", text="Final answer here"),
    ]

    with patch.object(provider.client.messages, 'create', new_callable=AsyncMock) as mock_create:
        mock_create.return_value = mock_response

        response, thinking = await provider.generate_with_thinking(
            messages=[Message(role="user", content="Test")],
            system_prompt="You are helpful",
            thinking_budget=10000,
        )

        assert thinking == "Internal reasoning here..."
        assert response == "Final answer here"


@pytest.mark.asyncio
async def test_generate_with_thinking_fallback(anthropic_config):
    """Test fallback when extended thinking not available."""
    anthropic_config.model = "claude-3-haiku-20240307"  # Doesn't support thinking
    provider = AnthropicProvider(anthropic_config)

    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(type="text", text="Regular response"),
    ]

    with patch.object(provider.client.messages, 'create', new_callable=AsyncMock) as mock_create:
        mock_create.return_value = mock_response

        response, thinking = await provider.generate_with_thinking(
            messages=[Message(role="user", content="Test")],
            system_prompt="You are helpful",
            thinking_budget=10000,
        )

        assert response == "Regular response"
        assert thinking is None  # No thinking block
