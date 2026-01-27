"""Tests for pre-validation gates."""
from datetime import UTC, datetime

import pytest
from models.schemas import (
    Finding,
    Evidence,
    ProofChecklist,
    ChecklistItem,
    ChecklistStatus,
    Disposition,
    Severity,
    VulnerabilityCategory,
    ProtocolPolicy,
    ValidationResult,
    InputChannel,
)
from services.classification.classifier import ClassificationResult
from services.validation.pre_validation_gates import PreValidationGates


@pytest.fixture
def gates():
    """Create PreValidationGates instance."""
    return PreValidationGates()


@pytest.fixture
def basic_finding():
    """Create a basic finding for testing."""
    return Finding(
        id="test-1",
        agent_id="agent-1",
        repo_id="repo-1",
        severity=Severity.HIGH,
        title="SQL Injection",
        description="SQL injection vulnerability",
        file_path="/src/main.py",
        line_start=10,
        vulnerability_type="sql_injection",
        confidence=0.9,
        created_at=datetime.now(UTC),
        category=VulnerabilityCategory.SQL_INJECTION,
    )


@pytest.fixture
def basic_evidence():
    """Create basic evidence."""
    return Evidence(
        finding_id="test-1",
        snippet="user_input = request.args.get('id')\nquery = f'SELECT * FROM users WHERE id = {user_input}'",
        input_channel=InputChannel.network,
        input_channel_deterministic=True,
    )


@pytest.fixture
def valid_checklist():
    """Create a valid proof checklist with sufficient PROVEN items."""
    return ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Network input from request.args",
        ),
        sink_present=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="SQL query execution",
        ),
        dataflow_evidenced=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Direct flow from input to query",
        ),
        reachable=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Route is publicly accessible",
        ),
        boundary_crossed=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Network boundary",
        ),
        not_only_misconfig=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Code-level vulnerability",
        ),
    )


@pytest.fixture
def strict_protocol():
    """Create a strict protocol policy."""
    return ProtocolPolicy(
        id="osvrp_strict",
        display_name="OSS VRP (Strict)",
        min_disposition_to_submit={Disposition.VALID_SECURITY_ISSUE},
        reject_social_engineering_only=True,
        min_checklist_proven_count=4,
        allow_unknown_in_checklist=False,
    )


def test_disposition_gate_rejects_low_disposition(gates, basic_finding, basic_evidence, valid_checklist, strict_protocol):
    """Gate 1: Reject findings with low disposition (HARDENING, BY_DESIGN)."""
    # Create classification with HARDENING disposition
    classification = ClassificationResult(
        disposition=Disposition.HARDENING,
        classification_confidence=85,
        exploit_confidence=None,
        proof_checklist=valid_checklist,
        reasoning=["This is a hardening opportunity"],
        category=VulnerabilityCategory.SQL_INJECTION,
    )

    result = gates.check_gates(basic_finding, basic_evidence, classification, strict_protocol)

    # Should return ValidationResult when filtering
    assert result is not None
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert any("disposition" in r.lower() or "hardening" in r.lower() for r in result.reasoning)
    assert "pre_validation_gate" in result.categories


def test_disposition_gate_passes_high_disposition(gates, basic_finding, basic_evidence, valid_checklist, strict_protocol):
    """Gate 1: Pass findings with VALID_SECURITY_ISSUE disposition."""
    # Create classification with VALID_SECURITY_ISSUE disposition
    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=85,
        proof_checklist=valid_checklist,
        reasoning=["Valid SQL injection vulnerability"],
        category=VulnerabilityCategory.SQL_INJECTION,
    )

    result = gates.check_gates(basic_finding, basic_evidence, classification, strict_protocol)

    # Should return None when passing
    assert result is None


def test_checklist_gate_rejects_insufficient_evidence(gates, basic_finding, basic_evidence, strict_protocol):
    """Gate 2: Reject findings with insufficient PROVEN checklist items."""
    # Create a weak checklist with only 2 PROVEN items (policy requires 4)
    weak_checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Network input",
        ),
        sink_present=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="SQL sink",
        ),
        dataflow_evidenced=ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="Dataflow unclear",
        ),
        reachable=ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="Reachability unclear",
        ),
        boundary_crossed=ChecklistItem(
            value=False,
            status=ChecklistStatus.DISPROVEN,
            reason="No boundary crossed",
        ),
        not_only_misconfig=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Code-level issue",
        ),
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=60,
        exploit_confidence=50,
        proof_checklist=weak_checklist,
        reasoning=["Weak evidence for SQL injection"],
        category=VulnerabilityCategory.SQL_INJECTION,
    )

    result = gates.check_gates(basic_finding, basic_evidence, classification, strict_protocol)

    # Should return ValidationResult when filtering
    assert result is not None
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert any("insufficient evidence" in r.lower() or "proven" in r.lower() for r in result.reasoning)
    assert "pre_validation_gate" in result.categories
    assert "insufficient_evidence" in result.categories


def test_social_engineering_gate_rejects_social_eng_only(gates, basic_evidence, valid_checklist, strict_protocol):
    """Gate 3: Reject social-engineering-only findings when policy requires."""
    # Create finding with social engineering keywords
    social_eng_finding = Finding(
        id="test-social",
        agent_id="agent-1",
        repo_id="repo-1",
        severity=Severity.MEDIUM,
        title="Phishing attack possible",
        description="User could be tricked into clicking malicious link",
        file_path="/src/main.py",
        line_start=10,
        vulnerability_type="phishing",
        confidence=0.7,
        created_at=datetime.now(UTC),
    )

    # Create checklist without technical sink
    no_sink_checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="User input",
        ),
        sink_present=ChecklistItem(
            value=False,
            status=ChecklistStatus.DISPROVEN,
            reason="No technical sink",
        ),
        dataflow_evidenced=ChecklistItem(
            value=False,
            status=ChecklistStatus.DISPROVEN,
            reason="No dataflow",
        ),
        reachable=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Accessible",
        ),
        boundary_crossed=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Network boundary",
        ),
        not_only_misconfig=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Not misconfig",
        ),
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=70,
        exploit_confidence=60,
        proof_checklist=no_sink_checklist,
        reasoning=["User could be socially engineered"],
        category=VulnerabilityCategory.GENERIC,
    )

    result = gates.check_gates(social_eng_finding, basic_evidence, classification, strict_protocol)

    # Should return ValidationResult when filtering
    assert result is not None
    assert isinstance(result, ValidationResult)
    assert result.is_valid is False
    assert any("social" in r.lower() for r in result.reasoning)
    assert "pre_validation_gate" in result.categories
    assert "social_engineering" in result.categories


def test_all_gates_pass(gates, basic_finding, basic_evidence, valid_checklist, strict_protocol):
    """Test that a high-quality finding passes all pre-validation gates."""
    # Create a strong classification that should pass all gates
    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=95,
        exploit_confidence=90,
        proof_checklist=valid_checklist,
        reasoning=[
            "Clear SQL injection with user-controlled input",
            "Direct dataflow from network input to SQL query",
            "No parameterization or sanitization present",
        ],
        category=VulnerabilityCategory.SQL_INJECTION,
    )

    result = gates.check_gates(basic_finding, basic_evidence, classification, strict_protocol)

    # Should return None (pass all gates)
    assert result is None
