"""End-to-end integration tests for LLM validation with real file operations."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, Mock
from datetime import datetime, UTC

from models.schemas import (
    Finding,
    Evidence,
    Disposition,
    VulnerabilityCategory,
    InputChannel,
    ChecklistStatus,
    ChecklistItem,
    ProofChecklist,
    Severity,
)
from services.classification.classifier import ClassificationResult
from services.validation.llm_validator import LLMFindingValidator


@pytest.fixture
def temp_repo():
    """Create a temporary repository with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)

        # Create test file with unreachable vulnerable code
        (repo_path / "vulnerable.py").write_text("""
import subprocess

def unused_dangerous_function(user_input):
    # This function is never called
    subprocess.call(user_input, shell=True)

def main():
    print("Hello world")

if __name__ == "__main__":
    main()
""")

        yield repo_path


@pytest.mark.asyncio
async def test_validator_rejects_unreachable_code(temp_repo):
    """Test that validator correctly identifies and rejects unreachable vulnerable code."""

    finding = Finding(
        id="test-unreachable",
        agent_id="test-agent",
        repo_id="test-repo",
        file_path="vulnerable.py",
        line_start=5,
        line_end=5,
        vulnerability_type="command_injection",
        title="Command Injection in subprocess.call",
        description="subprocess.call with shell=True and user input",
        severity=Severity.HIGH,
        confidence=0.8,
        disposition=Disposition.SPECULATIVE,
        discovered_at=datetime.now(UTC),
        created_at=datetime.now(UTC)
    )

    evidence = Evidence(
        finding_id="test-unreachable",
        snippet="subprocess.call(user_input, shell=True)",
        input_channel=InputChannel.network,
        input_channel_signals=["route_registration"],
        dataflow_summary="HTTP body → subprocess.call",
        collected_at=datetime.now(UTC)
    )

    classification = ClassificationResult(
        category=VulnerabilityCategory.COMMAND_INJECTION,
        disposition=Disposition.SPECULATIVE,
        classification_confidence=80,
        exploit_confidence=None,
        reasoning=["Initial classification reasoning"],
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="HTTP body parameter"
            ),
            sink_present=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="subprocess.call with shell=True"
            ),
            dataflow_evidenced=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Needs investigation"
            ),
            reachable=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Needs call graph analysis"
            ),
            boundary_crossed=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="HTTP endpoint"
            ),
            not_only_misconfig=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Code execution issue"
            ),
        )
    )

    # Mock Anthropic API response to investigate and conclude it's unreachable
    mock_response = Mock()
    mock_response.stop_reason = "end_turn"
    mock_response.content = [
        Mock(
            type="text",
            text="""DECISION: INVALID

CATEGORY: unreachable_code

REASONING:
- Function unused_dangerous_function is never called in the codebase
- Performed grep search for "unused_dangerous_function" - no callers found
- The main() function does not invoke this vulnerable code path
- This is dead code that would never execute in practice
- Not a real security issue"""
        )
    ]

    # Create validator with temp repo
    with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
        with patch('anthropic.Anthropic') as mock_anthropic:
            mock_client = Mock()
            mock_client.messages.create.return_value = mock_response
            mock_anthropic.return_value = mock_client

            validator = LLMFindingValidator(
                anthropic_api_key='test-key',
                repo_root=str(temp_repo),
            )

            result = await validator.validate(
                finding=finding,
                evidence=evidence,
                classification=classification,
                threat_model_profile=None,
                criticism_level="high"
            )

    # Should reject as INVALID
    assert result.is_valid is False
    assert "unreachable" in str(result.categories).lower() or "unreachable" in str(result.reasoning).lower()
    assert any("never called" in r.lower() or "dead code" in r.lower() for r in result.reasoning)


@pytest.fixture
def temp_repo_with_reachable_vuln():
    """Create repository with reachable vulnerable code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)

        # Create vulnerable API endpoint
        (repo_path / "api.py").write_text("""
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_command():
    command = request.json.get('command')
    # Direct command injection
    subprocess.call(command, shell=True)
    return {"status": "executed"}
""")

        yield repo_path


@pytest.mark.asyncio
async def test_validator_approves_reachable_vulnerability(temp_repo_with_reachable_vuln):
    """Test that validator correctly identifies and approves reachable vulnerability."""

    finding = Finding(
        id="test-reachable",
        agent_id="test-agent",
        repo_id="test-repo",
        file_path="api.py",
        line_start=10,
        line_end=10,
        vulnerability_type="command_injection",
        title="Command Injection in Flask endpoint",
        description="subprocess.call with untrusted input from HTTP request",
        severity=Severity.CRITICAL,
        confidence=0.9,
        disposition=Disposition.SPECULATIVE,
        discovered_at=datetime.now(UTC),
        created_at=datetime.now(UTC)
    )

    evidence = Evidence(
        finding_id="test-reachable",
        snippet="subprocess.call(command, shell=True)",
        input_channel=InputChannel.network,
        input_channel_signals=["route_registration", "flask_route"],
        dataflow_summary="request.json → command → subprocess.call",
        collected_at=datetime.now(UTC)
    )

    classification = ClassificationResult(
        category=VulnerabilityCategory.COMMAND_INJECTION,
        disposition=Disposition.SPECULATIVE,
        classification_confidence=90,
        exploit_confidence=None,
        reasoning=["Initial classification reasoning"],
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="HTTP JSON body parameter"
            ),
            sink_present=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="subprocess.call with shell=True"
            ),
            dataflow_evidenced=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Needs validation"
            ),
            reachable=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,
                reason="Needs route analysis"
            ),
            boundary_crossed=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Flask route decorator"
            ),
            not_only_misconfig=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Code execution vulnerability"
            ),
        )
    )

    # Mock API response for valid vulnerability
    mock_response = Mock()
    mock_response.stop_reason = "end_turn"
    mock_response.content = [
        Mock(
            type="text",
            text="""DECISION: VALID

CATEGORY: command_injection

REASONING:
- Flask route decorator @app.route makes this reachable via HTTP POST
- User-controlled input from request.json flows directly to subprocess.call
- shell=True enables arbitrary command execution
- No sanitization or validation present
- This is a critical remote code execution vulnerability"""
        )
    ]

    with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
        with patch('anthropic.Anthropic') as mock_anthropic:
            mock_client = Mock()
            mock_client.messages.create.return_value = mock_response
            mock_anthropic.return_value = mock_client

            validator = LLMFindingValidator(
                anthropic_api_key='test-key',
                repo_root=str(temp_repo_with_reachable_vuln),
            )

            result = await validator.validate(
                finding=finding,
                evidence=evidence,
                classification=classification,
                threat_model_profile=None,
                criticism_level="high"
            )

    # Should approve as VALID
    assert result.is_valid is True
    assert "command_injection" in str(result.categories).lower()
    assert any("shell=true" in r.lower() or "remote code execution" in r.lower() for r in result.reasoning)
