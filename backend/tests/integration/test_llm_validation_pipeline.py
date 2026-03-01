"""Integration tests for LLM validation in triage pipeline."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, UTC

from models.schemas import (
    Finding,
    Evidence,
    ProtocolPolicy,
    Disposition,
    VulnerabilityCategory,
    InputChannel,
    SubmissionDecision,
    ValidationResult,
    Severity,
)
from services.classification.classifier import ClassificationResult
from services.finding_triage_service import FindingTriageService
from models.schemas import ChecklistItem, ChecklistStatus, ProofChecklist


@pytest.fixture
def mock_llm_validator():
    """Mock LLM validator."""
    validator = Mock()
    validator.validate = AsyncMock()
    return validator


@pytest.fixture
def protocol_with_validation():
    """Protocol policy with LLM validation enabled."""
    return ProtocolPolicy(
        id="test-protocol",
        display_name="Test Protocol",
        min_disposition_to_submit={Disposition.BUG, Disposition.VALID_SECURITY_ISSUE},
        min_checklist_proven_count=3,
        allow_unknown_in_checklist=False,
        require_realistic_attacker_model=True,
        reject_social_engineering_only=True,
        require_cross_boundary_for_local_bugs=True,
        category_rules={},
        enable_llm_validation=True,
        validation_criticism_level="high",
        validation_model="claude-sonnet-4-5-20250929",
        validation_timeout_seconds=120,
    )


@pytest.fixture
def finding_and_evidence():
    """Sample finding and evidence."""
    finding = Finding(
        id="test-finding-1",
        agent_id="test-agent",
        repo_id="test-repo",
        file_path="src/vulnerable.py",
        line_start=42,
        line_end=42,
        vulnerability_type="command_injection",
        title="Unsanitized input to subprocess",
        description="Unsanitized input to subprocess.call",
        severity=Severity.HIGH,
        confidence=0.85,
        disposition=Disposition.SPECULATIVE,
        created_at=datetime.now(UTC)
    )

    evidence = Evidence(
        finding_id="test-finding-1",
        snippet="subprocess.call(user_input, shell=True)",
        input_channel=InputChannel.network,
        input_channel_deterministic=True,
        input_channel_signals=["route_registration"],
        input_channel_reason="HTTP request → subprocess.call",
    )

    return finding, evidence


@pytest.mark.asyncio
async def test_triage_with_llm_validation_valid(
    mock_llm_validator,
    protocol_with_validation,
    finding_and_evidence
):
    """Test pipeline with LLM validator returning VALID."""
    finding, evidence = finding_and_evidence

    classification = ClassificationResult(
        category=VulnerabilityCategory.COMMAND_INJECTION,
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=95,
        exploit_confidence=90,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="HTTP input flows to subprocess"
            ),
            sink_present=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="subprocess.call with shell=True"
            ),
            dataflow_evidenced=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Direct flow from request to subprocess"
            ),
            reachable=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Route registered and exposed"
            ),
            boundary_crossed=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Network boundary crossed"
            ),
            not_only_misconfig=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Code-level vulnerability, not config"
            ),
        ),
        reasoning=["Command injection via shell=True", "Directly reachable from HTTP"]
    )

    # Mock validator to return VALID
    mock_llm_validator.validate.return_value = ValidationResult(
        is_valid=True,
        reasoning=["Shell command injection confirmed", "Reachable from HTTP endpoint"],
        categories=["command_injection"],
        confidence=95,
        timestamp=datetime.now(UTC)
    )

    # Create service with mocked validator
    with patch('services.finding_triage_service.LLMFindingValidator', return_value=mock_llm_validator), \
         patch('services.finding_triage_service.ProtocolConfig.ANTHROPIC_API_KEY', 'test-api-key'):
        service = FindingTriageService()

        # Call the new triage_finding method (single finding)
        result = await service.triage_finding(
            finding=finding,
            evidence=evidence,
            classification=classification,
            policy=protocol_with_validation
        )

    # Validator should have been called
    mock_llm_validator.validate.assert_called_once()

    # Result should be SUBMIT (passes validation and protocol gates)
    assert result.decision == SubmissionDecision.SUBMIT
    assert any("LLM validation" in r and "VALID" in r for r in result.reasons)


@pytest.mark.asyncio
async def test_triage_with_llm_validation_invalid(
    mock_llm_validator,
    protocol_with_validation,
    finding_and_evidence
):
    """Test pipeline with LLM validator returning INVALID."""
    finding, evidence = finding_and_evidence

    # Use BUG disposition to pass pre-gates but still be rejected by LLM
    classification = ClassificationResult(
        category=VulnerabilityCategory.COMMAND_INJECTION,
        disposition=Disposition.BUG,
        classification_confidence=60,
        exploit_confidence=None,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Input from request"
            ),
            sink_present=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="subprocess.call present"
            ),
            dataflow_evidenced=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Dataflow traced"
            ),
            reachable=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Route reachable"
            ),
            boundary_crossed=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Network boundary"
            ),
            not_only_misconfig=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Code-level issue"
            ),
        ),
        reasoning=["Possible command injection", "Needs investigation"]
    )

    # Mock validator to return INVALID
    mock_llm_validator.validate.return_value = ValidationResult(
        is_valid=False,
        reasoning=[
            "Subprocess call uses shell=False with argv list",
            "This is argument injection, not command injection"
        ],
        categories=["argument_injection"],
        confidence=85,
        timestamp=datetime.now(UTC)
    )

    with patch('services.finding_triage_service.LLMFindingValidator', return_value=mock_llm_validator), \
         patch('services.finding_triage_service.ProtocolConfig.ANTHROPIC_API_KEY', 'test-api-key'):
        service = FindingTriageService()

        result = await service.triage_finding(
            finding=finding,
            evidence=evidence,
            classification=classification,
            policy=protocol_with_validation
        )

    # Should reject without reaching protocol evaluator
    assert result.decision == SubmissionDecision.DONT_SUBMIT
    assert "LLM validation: INVALID" in result.reasons
    assert "argument injection" in str(result.reasons).lower()


@pytest.mark.asyncio
async def test_triage_pre_gates_fast_reject(
    mock_llm_validator,
    protocol_with_validation,
    finding_and_evidence
):
    """Test pre-validation gates reject finding before LLM call."""
    finding, evidence = finding_and_evidence

    # Set finding to HARDENING (should be rejected by pre-gates)
    finding.disposition = Disposition.HARDENING

    classification = ClassificationResult(
        category=VulnerabilityCategory.COMMAND_INJECTION,
        disposition=Disposition.HARDENING,
        classification_confidence=40,
        exploit_confidence=None,
        proof_checklist=ProofChecklist(
            source_controlled_input=ChecklistItem(
                status=ChecklistStatus.DISPROVEN,
                value=False,
                reason="Not attacker controlled"
            ),
            sink_present=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="subprocess.call present"
            ),
            dataflow_evidenced=ChecklistItem(
                status=ChecklistStatus.UNKNOWN,
                value=False,
                reason="No clear dataflow"
            ),
            reachable=ChecklistItem(
                status=ChecklistStatus.UNKNOWN,
                value=False,
                reason="Unclear if reachable"
            ),
            boundary_crossed=ChecklistItem(
                status=ChecklistStatus.DISPROVEN,
                value=False,
                reason="No boundary crossing"
            ),
            not_only_misconfig=ChecklistItem(
                status=ChecklistStatus.PROVEN,
                value=True,
                reason="Code-level pattern"
            ),
        ),
        reasoning=["Dangerous pattern but not exploitable"]
    )

    with patch('services.finding_triage_service.LLMFindingValidator', return_value=mock_llm_validator), \
         patch('services.finding_triage_service.ProtocolConfig.ANTHROPIC_API_KEY', 'test-api-key'):
        service = FindingTriageService()

        result = await service.triage_finding(
            finding=finding,
            evidence=evidence,
            classification=classification,
            policy=protocol_with_validation
        )

    # LLM validator should NOT have been called
    mock_llm_validator.validate.assert_not_called()

    # Should be rejected
    assert result.decision == SubmissionDecision.DONT_SUBMIT
    assert any("pre-validation" in r.lower() or "disposition" in r.lower() for r in result.reasons)
