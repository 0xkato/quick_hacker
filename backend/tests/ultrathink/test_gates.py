# tests/ultrathink/test_gates.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from ultrathink.gates import (
    BaseGate,
    TriageGate,
    DeepAnalysisGate,
    DevilsAdvocateGate,
    ProofGeneratorGate,
    FinalGate,
    GateResult,
)
from ultrathink.config import GateConfig
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
def mock_thinking_engine():
    engine = MagicMock()
    engine.think = AsyncMock()
    return engine


@pytest.mark.asyncio
async def test_triage_gate_passes_high_confidence(sample_finding, mock_thinking_engine):
    """Triage should pass findings with high initial signal."""
    mock_thinking_engine.think.return_value = MagicMock(
        output='{"verdict": "investigate", "priority": 5, "reasoning": "Clear SQL injection pattern"}',
        thinking_trace="Analyzed the finding...",
    )

    gate = TriageGate(
        config=GateConfig(name="triage", confidence_threshold=0.6),
        thinking_engine=mock_thinking_engine,
    )

    result = await gate.evaluate(sample_finding, code_context="SELECT * FROM users")

    assert result.passed == True
    assert result.confidence >= 0.6


@pytest.mark.asyncio
async def test_devils_advocate_rejects_weak_finding(sample_finding, mock_thinking_engine):
    """Devil's advocate should reject findings with weak evidence."""
    sample_finding.confidence = 0.65  # Weak

    mock_thinking_engine.think.return_value = MagicMock(
        output='{"verdict": "reject", "counter_arguments": ["Parameterized query might be used elsewhere"], "revised_confidence": 0.40}',
        thinking_trace="Argued against the finding...",
    )

    gate = DevilsAdvocateGate(
        config=GateConfig(name="devils_advocate", confidence_threshold=0.8),
        thinking_engine=mock_thinking_engine,
    )

    result = await gate.evaluate(sample_finding, code_context="SELECT * FROM users")

    assert result.passed == False
    assert "counter_arguments" in result.metadata


@pytest.mark.asyncio
async def test_proof_generator_requires_concrete_poc(sample_finding, mock_thinking_engine):
    """Proof generator should require concrete exploits."""
    mock_thinking_engine.think.return_value = MagicMock(
        output='{"can_prove": true, "payload": "admin\' OR 1=1--", "expected_result": "Auth bypass"}',
        thinking_trace="Generated proof...",
    )

    gate = ProofGeneratorGate(
        config=GateConfig(name="proof_generator", confidence_threshold=0.85),
        thinking_engine=mock_thinking_engine,
    )

    result = await gate.evaluate(sample_finding, code_context="query = f'SELECT * FROM users WHERE user={user}'")

    assert result.passed == True
    assert result.metadata.get("payload") is not None
