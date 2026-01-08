"""Tests for provider error handling."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from providers.anthropic_provider import AnthropicProvider
from providers.openai_provider import OpenAIProvider
from providers.base_provider import Message
from models.schemas import ProviderConfig, ProviderType


@pytest.fixture
def anthropic_config():
    return ProviderConfig(
        provider=ProviderType.ANTHROPIC,
        model="claude-3-haiku-20240307",
        api_key="test-key"
    )


@pytest.fixture
def openai_config():
    return ProviderConfig(
        provider=ProviderType.OPENAI,
        model="gpt-4",
        api_key="test-key"
    )


def make_mock_response(status_code: int = 401):
    """Create a mock httpx.Response for exception construction."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.headers = {}
    mock_response.request = MagicMock()
    return mock_response


class TestAnthropicErrorHandling:
    @pytest.mark.asyncio
    async def test_authentication_error(self, anthropic_config):
        """Test that Anthropic AuthenticationError is converted to user-friendly ValueError."""
        from anthropic import AuthenticationError

        provider = AnthropicProvider(anthropic_config)

        # Create a properly constructed AuthenticationError
        mock_response = make_mock_response(401)
        auth_error = AuthenticationError(
            message="Invalid API key",
            response=mock_response,
            body={"error": {"message": "Invalid API key"}}
        )

        provider.client.messages.create = AsyncMock(side_effect=auth_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "Invalid Anthropic API key" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_rate_limit_error(self, anthropic_config):
        """Test that Anthropic RateLimitError is converted to user-friendly ValueError."""
        from anthropic import RateLimitError

        provider = AnthropicProvider(anthropic_config)

        mock_response = make_mock_response(429)
        rate_error = RateLimitError(
            message="Rate limit exceeded",
            response=mock_response,
            body={"error": {"message": "Rate limit exceeded"}}
        )

        provider.client.messages.create = AsyncMock(side_effect=rate_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "Rate limit exceeded" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connection_error(self, anthropic_config):
        """Test that Anthropic APIConnectionError is converted to user-friendly ValueError."""
        from anthropic import APIConnectionError

        provider = AnthropicProvider(anthropic_config)

        # APIConnectionError has different constructor - uses request param
        mock_request = MagicMock()
        conn_error = APIConnectionError(request=mock_request)

        provider.client.messages.create = AsyncMock(side_effect=conn_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "Failed to connect" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_api_error(self, anthropic_config):
        """Test that Anthropic APIError is converted to user-friendly ValueError."""
        from anthropic import APIError

        provider = AnthropicProvider(anthropic_config)

        mock_response = make_mock_response(500)
        api_error = APIError(
            message="Internal server error",
            request=MagicMock(),
            body={"error": {"message": "Internal server error"}}
        )

        provider.client.messages.create = AsyncMock(side_effect=api_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "Anthropic API error" in str(exc_info.value)


class TestOpenAIErrorHandling:
    @pytest.mark.asyncio
    async def test_authentication_error(self, openai_config):
        """Test that OpenAI AuthenticationError is converted to user-friendly ValueError."""
        from openai import AuthenticationError

        provider = OpenAIProvider(openai_config)

        mock_response = make_mock_response(401)
        auth_error = AuthenticationError(
            message="Invalid API key",
            response=mock_response,
            body={"error": {"message": "Invalid API key"}}
        )

        provider.client.chat.completions.create = AsyncMock(side_effect=auth_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "Invalid OpenAI API key" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_rate_limit_error(self, openai_config):
        """Test that OpenAI RateLimitError is converted to user-friendly ValueError."""
        from openai import RateLimitError

        provider = OpenAIProvider(openai_config)

        mock_response = make_mock_response(429)
        rate_error = RateLimitError(
            message="Rate limit exceeded",
            response=mock_response,
            body={"error": {"message": "Rate limit exceeded"}}
        )

        provider.client.chat.completions.create = AsyncMock(side_effect=rate_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "Rate limit exceeded" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connection_error(self, openai_config):
        """Test that OpenAI APIConnectionError is converted to user-friendly ValueError."""
        from openai import APIConnectionError

        provider = OpenAIProvider(openai_config)

        mock_request = MagicMock()
        conn_error = APIConnectionError(request=mock_request)

        provider.client.chat.completions.create = AsyncMock(side_effect=conn_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "Failed to connect" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_api_error(self, openai_config):
        """Test that OpenAI APIError is converted to user-friendly ValueError."""
        from openai import APIError

        provider = OpenAIProvider(openai_config)

        api_error = APIError(
            message="Internal server error",
            request=MagicMock(),
            body={"error": {"message": "Internal server error"}}
        )

        provider.client.chat.completions.create = AsyncMock(side_effect=api_error)

        with pytest.raises(ValueError) as exc_info:
            await provider.generate([Message(role="user", content="test")])

        assert "OpenAI API error" in str(exc_info.value)
