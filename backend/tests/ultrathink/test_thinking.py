# tests/ultrathink/test_thinking.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from ultrathink.thinking import ThinkingEngine, ThinkingResult
from ultrathink.config import UltrathinkConfig
from models.schemas import ThinkingMode, ProviderConfig, ProviderType


@pytest.fixture
def mock_provider():
    provider = MagicMock()
    provider.generate = AsyncMock(return_value="Test response")
    return provider


@pytest.mark.asyncio
async def test_thinking_engine_native_mode(mock_provider):
    """Test native extended thinking with Claude."""
    engine = ThinkingEngine(
        config=UltrathinkConfig(thinking_mode=ThinkingMode.NATIVE)
    )

    result = await engine.think(
        prompt="Analyze this code for vulnerabilities",
        context="def login(user, pwd): return db.query(f'SELECT * FROM users WHERE u={user}')",
        provider=mock_provider,
        model="claude-opus-4-5-20251101",
        thinking_budget=10000,
    )

    assert isinstance(result, ThinkingResult)
    assert result.thinking_trace is not None


@pytest.mark.asyncio
async def test_thinking_engine_simulated_mode(mock_provider):
    """Test simulated CoT with GPT-4."""
    engine = ThinkingEngine(
        config=UltrathinkConfig(thinking_mode=ThinkingMode.SIMULATED)
    )

    result = await engine.think(
        prompt="Analyze this code",
        context="code here",
        provider=mock_provider,
        model="gpt-4o",
        thinking_budget=10000,
    )

    assert isinstance(result, ThinkingResult)
    # Simulated mode should have CoT in output
    mock_provider.generate.assert_called_once()


@pytest.mark.asyncio
async def test_thinking_engine_structured_mode(mock_provider):
    """Test structured reasoning with open source models."""
    engine = ThinkingEngine(
        config=UltrathinkConfig(thinking_mode=ThinkingMode.STRUCTURED)
    )

    result = await engine.think(
        prompt="Analyze this code",
        context="code here",
        provider=mock_provider,
        model="llama3.3",
        thinking_budget=10000,
    )

    assert isinstance(result, ThinkingResult)
