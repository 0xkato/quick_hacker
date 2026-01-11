import pytest
from unittest.mock import MagicMock, patch


@pytest.mark.asyncio
async def test_validate_api_key_accepts_anthropic_oauth_token():
    """OAuth-style tokens (sk-ant-oat*) should be accepted for Claude Code/SDK usage."""
    from routers.auth import APIKeyRequest, validate_api_key

    request = APIKeyRequest(provider="anthropic", api_key="sk-ant-oat01-test-token")

    # Validation for OAuth tokens should short-circuit and not call the HTTP API-key provider.
    with patch("providers.get_provider") as mock_get_provider:
        mock_get_provider.side_effect = AssertionError("get_provider should not be called for OAuth tokens")
        result = await validate_api_key(request=request, user=MagicMock())

    assert result["valid"] is True
    assert result["provider"] == "anthropic"

