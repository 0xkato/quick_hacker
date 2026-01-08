# tests/integration/test_ultrathink_e2e.py
"""End-to-end integration test for ultrathink cascade."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from ultrathink import UltrathinkConfig, UltrathinkCascade
from ultrathink.cascade import CascadeResult
from models.schemas import Finding, Severity, ThinkingMode


@pytest.fixture
def vulnerable_code():
    """Sample vulnerable code for testing."""
    return '''
def get_user(user_id):
    """Get user by ID - VULNERABLE TO SQL INJECTION."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def login(username, password):
    """Login function - uses vulnerable get_user."""
    user = get_user(username)
    if user and user.password == password:
        return create_session(user)
    return None
'''


@pytest.fixture
def sample_finding():
    """Sample finding to verify."""
    return Finding(
        id="sqli-001",
        agent_id="test-agent",
        repo_id="test-repo",
        severity=Severity.CRITICAL,
        title="SQL Injection in get_user function",
        description="User input directly concatenated into SQL query",
        file_path="app/auth.py",
        line_start=3,
        vulnerability_type="sqli",
        confidence=0.75,
        created_at=datetime.utcnow(),
    )


@pytest.fixture
def mock_provider():
    """Mock provider that returns realistic responses."""
    provider = MagicMock()

    responses = {
        "triage": '{"verdict": "investigate", "priority": 5, "reasoning": "Clear SQL injection pattern with f-string"}',
        "deep_analysis": '{"source_verified": true, "sink_verified": true, "path_verified": true, "confidence": 0.92, "source_location": "app/auth.py:3", "sink_location": "app/auth.py:4", "trace_steps": ["Input at line 3", "Concat at line 4", "Execute at line 4"], "analysis_summary": "Confirmed SQL injection"}',
        "devils_advocate": '{"verdict": "confirmed", "counter_arguments": ["Could have input validation elsewhere"], "revised_confidence": 0.88, "strongest_counter_argument": "No evidence of parameterization", "remaining_certainty": "f-string clearly shows direct concatenation"}',
        "proof_generator": '{"can_prove": true, "payload": "1 OR 1=1", "entry_point": "get_user(user_id)", "execution_trace": ["user_id=1 OR 1=1", "query=SELECT * FROM users WHERE id = 1 OR 1=1", "Returns all users"], "expected_result": "Authentication bypass", "verification_method": "Call get_user(\"1 OR 1=1\")"}',
        "final_gate": '{"stake_reputation": true, "confidence_percentage": 92, "strongest_evidence": "f-string SQL concatenation without parameterization", "biggest_doubt": "None - classic SQL injection", "final_decision": "REPORT", "reasoning": "Textbook SQL injection vulnerability"}',
    }

    call_count = [0]
    gates = ["triage", "deep_analysis", "devils_advocate", "proof_generator", "final_gate"]

    async def mock_generate(messages, system_prompt=None):
        gate_idx = min(call_count[0], len(gates) - 1)
        response = responses[gates[gate_idx]]
        call_count[0] += 1
        return response

    provider.generate = mock_generate
    return provider


@pytest.mark.asyncio
async def test_ultrathink_cascade_verifies_real_vulnerability(
    sample_finding,
    vulnerable_code,
    mock_provider
):
    """Test that cascade correctly verifies a real vulnerability."""
    config = UltrathinkConfig(
        thinking_mode=ThinkingMode.SIMULATED,
        capture_full_trace=True,
    )

    cascade = UltrathinkCascade(config=config)

    # Patch the thinking engine to use our mock
    with patch.object(cascade.thinking_engine, 'think') as mock_think:
        # Set up mock to return appropriate responses for each gate
        responses = [
            ('{"verdict": "investigate", "priority": 5}', "Triage thinking..."),
            ('{"source_verified": true, "sink_verified": true, "path_verified": true, "confidence": 0.92}', "Deep analysis thinking..."),
            ('{"verdict": "confirmed", "revised_confidence": 0.88}', "Devils advocate thinking..."),
            ('{"can_prove": true, "payload": "1 OR 1=1"}', "Proof gen thinking..."),
            ('{"stake_reputation": true, "confidence_percentage": 92, "final_decision": "REPORT"}', "Final gate thinking..."),
        ]

        call_idx = [0]
        async def mock_think_fn(*args, **kwargs):
            idx = min(call_idx[0], len(responses) - 1)
            output, trace = responses[idx]
            call_idx[0] += 1
            return MagicMock(
                output=output,
                thinking_trace=trace,
                thinking_tokens_used=1000,
            )

        mock_think.side_effect = mock_think_fn

        result = await cascade.evaluate(
            finding=sample_finding,
            code_context=vulnerable_code,
            provider=mock_provider,
            model="test-model",
        )

        # Verify the cascade passed
        assert result.final_verdict == True
        assert result.final_confidence >= 0.85
        assert len(result.gate_results) == 5
        assert all(gr.passed for gr in result.gate_results)
        assert result.rejected_by is None


@pytest.mark.asyncio
async def test_ultrathink_cascade_rejects_false_positive(mock_provider):
    """Test that cascade correctly rejects a false positive."""
    # Create a questionable finding
    weak_finding = Finding(
        id="fp-001",
        agent_id="test-agent",
        repo_id="test-repo",
        severity=Severity.HIGH,
        title="Potential XSS in template",
        description="Variable used in template",
        file_path="app/views.py",
        line_start=10,
        vulnerability_type="xss",
        confidence=0.55,
        created_at=datetime.utcnow(),
    )

    safe_code = '''
def render_user(user):
    """Render user - SAFE because Jinja2 autoescapes."""
    return render_template("user.html", name=user.name)
'''

    config = UltrathinkConfig(thinking_mode=ThinkingMode.SIMULATED)
    cascade = UltrathinkCascade(config=config)

    with patch.object(cascade.thinking_engine, 'think') as mock_think:
        # Devils advocate will reject this
        responses = [
            ('{"verdict": "investigate", "priority": 3}', "Triage..."),
            ('{"source_verified": true, "sink_verified": true, "path_verified": true, "confidence": 0.70}', "Analysis..."),
            ('{"verdict": "reject", "revised_confidence": 0.35, "strongest_counter_argument": "Jinja2 autoescapes by default"}', "Devils advocate rejects..."),
        ]

        call_idx = [0]
        async def mock_think_fn(*args, **kwargs):
            idx = min(call_idx[0], len(responses) - 1)
            output, trace = responses[idx]
            call_idx[0] += 1
            return MagicMock(
                output=output,
                thinking_trace=trace,
                thinking_tokens_used=500,
            )

        mock_think.side_effect = mock_think_fn

        result = await cascade.evaluate(
            finding=weak_finding,
            code_context=safe_code,
            provider=mock_provider,
            model="test-model",
        )

        # Verify rejection
        assert result.final_verdict == False
        assert result.rejected_by is not None


@pytest.mark.asyncio
async def test_cascade_report_generation(sample_finding, vulnerable_code, mock_provider):
    """Test that cascade generates a readable report."""
    config = UltrathinkConfig(thinking_mode=ThinkingMode.SIMULATED)
    cascade = UltrathinkCascade(config=config)

    with patch.object(cascade.thinking_engine, 'think') as mock_think:
        # All gates pass
        async def mock_think_fn(*args, **kwargs):
            return MagicMock(
                output='{"verdict": "investigate", "priority": 5, "source_verified": true, "sink_verified": true, "path_verified": true, "confidence": 0.9, "revised_confidence": 0.9, "can_prove": true, "payload": "test", "stake_reputation": true, "confidence_percentage": 90, "final_decision": "REPORT"}',
                thinking_trace="Mock thinking...",
                thinking_tokens_used=100,
            )

        mock_think.side_effect = mock_think_fn

        result = await cascade.evaluate(
            finding=sample_finding,
            code_context=vulnerable_code,
            provider=mock_provider,
            model="test-model",
        )

        # Generate report
        report = result.to_report()

        # Verify report contents
        assert "ULTRATHINK CASCADE EVALUATION REPORT" in report
        assert sample_finding.title in report
        assert "GATE RESULTS" in report
        assert "FINAL VERDICT" in report
