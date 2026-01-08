# tests/ultrathink/test_cascade.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from ultrathink.cascade import UltrathinkCascade, CascadeResult
from ultrathink.config import UltrathinkConfig
from models.schemas import Finding, Severity
from datetime import datetime


@pytest.fixture
def sample_finding():
    return Finding(
        id="test-001",
        agent_id="agent-001",
        repo_id="repo-001",
        severity=Severity.HIGH,
        title="SQL Injection in login",
        description="User input concatenated into SQL query",
        file_path="app/auth.py",
        line_start=42,
        vulnerability_type="sqli",
        confidence=0.75,
        created_at=datetime.utcnow(),
    )


@pytest.fixture
def mock_provider():
    provider = MagicMock()
    provider.generate = AsyncMock(return_value='{"verdict": "investigate", "priority": 5}')
    return provider


@pytest.mark.asyncio
async def test_cascade_runs_all_gates(sample_finding, mock_provider):
    """Cascade should run all gates in order."""
    cascade = UltrathinkCascade(config=UltrathinkConfig())

    with patch.object(cascade, '_run_gate') as mock_gate:
        mock_gate.return_value = MagicMock(passed=True, confidence=0.9, full_trace="trace", thinking_result=MagicMock(thinking_tokens_used=100))

        result = await cascade.evaluate(
            finding=sample_finding,
            code_context="SELECT * FROM users WHERE id = " + "user_id",
            provider=mock_provider,
            model="claude-opus-4-5-20251101",
        )

        # Should have run 5 gates
        assert mock_gate.call_count == 5


@pytest.mark.asyncio
async def test_cascade_stops_on_failed_gate(sample_finding, mock_provider):
    """Cascade should stop when a gate fails."""
    cascade = UltrathinkCascade(config=UltrathinkConfig())

    call_count = 0
    async def mock_run_gate(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # Fail on second gate
            return MagicMock(passed=False, confidence=0.3, gate=MagicMock(value="deep_analysis"), reasoning="Failed", full_trace=None, thinking_result=None, metadata={})
        return MagicMock(passed=True, confidence=0.9, gate=MagicMock(value="triage"), full_trace=None, thinking_result=None, metadata={})

    with patch.object(cascade, '_run_gate', side_effect=mock_run_gate):
        result = await cascade.evaluate(
            finding=sample_finding,
            code_context="code",
            provider=mock_provider,
            model="claude-opus-4-5-20251101",
        )

        assert result.final_verdict == False
        assert call_count == 2  # Stopped after failure


@pytest.mark.asyncio
async def test_cascade_captures_full_reasoning_trace(sample_finding, mock_provider):
    """Cascade should capture full reasoning traces from all gates."""
    cascade = UltrathinkCascade(
        config=UltrathinkConfig(capture_full_trace=True)
    )

    with patch.object(cascade, '_run_gate') as mock_gate:
        mock_gate.return_value = MagicMock(
            passed=True,
            confidence=0.9,
            full_trace="Thinking about the vulnerability...",
            thinking_result=MagicMock(thinking_tokens_used=500),
            metadata={},
        )

        result = await cascade.evaluate(
            finding=sample_finding,
            code_context="code",
            provider=mock_provider,
            model="claude-opus-4-5-20251101",
        )

        assert len(result.reasoning_traces) > 0
