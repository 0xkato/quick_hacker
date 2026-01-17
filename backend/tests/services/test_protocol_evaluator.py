"""Tests for ProtocolEvaluator."""
from datetime import datetime

import pytest
from models.schemas import (
    Finding,
    Evidence,
    ProtocolPolicy,
    Disposition,
    ChecklistStatus,
    ChecklistItem,
    ProofChecklist,
    VulnerabilityCategory,
    InputChannel,
    SubmissionDecision,
    Severity,
)
from services.strict_classifier import ClassificationResult
from services.protocol_evaluator import ProtocolEvaluator


@pytest.fixture
def strict_policy():
    """Strict protocol policy (like osvrp_strict)."""
    return ProtocolPolicy(
        id="test_strict",
        display_name="Test Strict",
        min_disposition_to_submit={Disposition.VALID_SECURITY_ISSUE},
        require_cross_boundary_for_local_bugs=True,
        reject_social_engineering_only=True,
        require_realistic_attacker_model=True,
        min_checklist_proven_count=6,
        allow_unknown_in_checklist=False,
        category_rules={
            VulnerabilityCategory.COMMAND_INJECTION: {
                "requires_shell": True,
                "reject_argument_injection": True
            }
        },
        enable_evidence_quests=True,
        quest_categories=[]
    )


@pytest.fixture
def permissive_policy():
    """Permissive protocol policy (like internal)."""
    return ProtocolPolicy(
        id="test_permissive",
        display_name="Test Permissive",
        min_disposition_to_submit={
            Disposition.VALID_SECURITY_ISSUE,
            Disposition.HARDENING
        },
        require_cross_boundary_for_local_bugs=False,
        reject_social_engineering_only=False,
        require_realistic_attacker_model=False,
        min_checklist_proven_count=3,
        allow_unknown_in_checklist=True,
        category_rules={},
        enable_evidence_quests=False,
        quest_categories=[]
    )


@pytest.fixture
def valid_finding():
    """Finding with VALID_SECURITY_ISSUE disposition."""
    return Finding(
        id="test-001",
        agent_id="agent-1",
        repo_id="repo-1",
        severity=Severity.HIGH,
        title="Command Injection",
        description="User input flows to subprocess",
        vulnerability_type="command_injection",
        file_path="app/exec.py",
        line_start=100,
        confidence=0.9,
        created_at=datetime(2026, 1, 17, 12, 0, 0),
        disposition=Disposition.VALID_SECURITY_ISSUE,
        category=VulnerabilityCategory.COMMAND_INJECTION
    )


@pytest.fixture
def complete_checklist():
    """Proof checklist with all items PROVEN."""
    return ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Request param"
        ),
        sink_present=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="subprocess.run()"
        ),
        dataflow_evidenced=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Direct flow"
        ),
        reachable=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="@app.route"
        ),
        boundary_crossed=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="HTTP endpoint"
        ),
        not_only_misconfig=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Code-level bug"
        )
    )


@pytest.fixture
def network_evidence():
    """Evidence with network input channel."""
    return Evidence(
        finding_id="test-001",
        snippet="subprocess.run(cmd, shell=True)",
        input_channel=InputChannel.network,
        input_channel_deterministic=True,
        input_channel_signals=["route_registration"],
        input_channel_reason="HTTP request handler",
        matches=[]
    )


def test_reject_by_disposition_strict_policy(
    valid_finding, network_evidence, complete_checklist, strict_policy
):
    """Test that HARDENING is rejected by strict policy."""
    # Arrange
    finding = valid_finding
    finding.disposition = Disposition.HARDENING

    classification = ClassificationResult(
        disposition=Disposition.HARDENING,
        classification_confidence=80,
        exploit_confidence=None,
        proof_checklist=complete_checklist,
        reasoning=["Sink present but no dataflow"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.DONT_SUBMIT
    assert "Disposition is hardening" in result.reasons[0]
    assert new_disposition is None  # No override


def test_accept_hardening_permissive_policy(
    valid_finding, network_evidence, complete_checklist, permissive_policy
):
    """Test that HARDENING is accepted by permissive policy."""
    # Arrange
    finding = valid_finding
    finding.disposition = Disposition.HARDENING

    classification = ClassificationResult(
        disposition=Disposition.HARDENING,
        classification_confidence=80,
        exploit_confidence=None,
        proof_checklist=complete_checklist,
        reasoning=["Sink present"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        finding, network_evidence, classification, permissive_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.SUBMIT
    assert "All protocol gates passed" in result.reasons[0]


def test_reject_insufficient_checklist_items(
    valid_finding, network_evidence, strict_policy
):
    """Test that insufficient proven items triggers rejection."""
    # Arrange
    incomplete_checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        ),
        sink_present=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        ),
        dataflow_evidenced=ChecklistItem(
            value=False, status=ChecklistStatus.UNKNOWN, reason="Not found"
        ),
        reachable=ChecklistItem(
            value=False, status=ChecklistStatus.UNKNOWN, reason="Not found"
        ),
        boundary_crossed=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        ),
        not_only_misconfig=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Found"
        )
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=80,
        exploit_confidence=70,
        proof_checklist=incomplete_checklist,
        reasoning=["Some items proven"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.DONT_SUBMIT
    assert "4/6 checklist items proven" in result.reasons[0]
    assert result.disposition_modified is True
    assert new_disposition == Disposition.HARDENING


def test_reject_social_engineering(
    network_evidence, complete_checklist, strict_policy
):
    """Test that social engineering is rejected."""
    # Arrange
    social_eng_finding = Finding(
        id="test-002",
        agent_id="agent-1",
        repo_id="repo-1",
        severity=Severity.MEDIUM,
        title="XSS",
        description="User must paste malicious script into browser console",
        vulnerability_type="xss",
        file_path="app/api.py",
        line_start=50,
        confidence=0.9,
        created_at=datetime(2026, 1, 17, 12, 0, 0),
        disposition=Disposition.VALID_SECURITY_ISSUE,
        category=VulnerabilityCategory.XSS
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=80,
        proof_checklist=complete_checklist,
        reasoning=["All items proven"],
        category=VulnerabilityCategory.XSS
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        social_eng_finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.DONT_SUBMIT
    assert "social engineering" in result.reasons[0].lower()
    assert new_disposition == Disposition.HARDENING


def test_local_bug_needs_automation_boundary(
    valid_finding, complete_checklist, strict_policy
):
    """Test that local bugs without automation trigger needs_more_info."""
    # Arrange
    local_evidence = Evidence(
        finding_id="test-001",
        snippet="subprocess.run(cmd, shell=True)",
        input_channel=InputChannel.local_unprivileged,
        input_channel_deterministic=True,
        input_channel_signals=[],  # No automation signals
        input_channel_reason="CLI argument",
        matches=[]
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=80,
        proof_checklist=complete_checklist,
        reasoning=["All items proven"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, local_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.NEEDS_MORE_INFO
    assert "local_unprivileged without automation boundary" in result.reasons[0]
    assert result.quest_run is True
    assert "Is this tool invoked automatically" in result.missing_evidence[0]


def test_command_injection_rejects_argv_injection(
    valid_finding, network_evidence, complete_checklist, strict_policy
):
    """Test that shell=False is rejected as not true command injection."""
    # Arrange
    argv_evidence = Evidence(
        finding_id="test-001",
        snippet='subprocess.run(cmd.split(" "), shell=False)',
        input_channel=InputChannel.network,
        input_channel_deterministic=True,
        input_channel_signals=["route_registration"],
        input_channel_reason="HTTP endpoint",
        matches=[]
    )

    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=90,
        exploit_confidence=80,
        proof_checklist=complete_checklist,
        reasoning=["All items proven"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, argv_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.DONT_SUBMIT
    assert "argument injection" in result.reasons[1].lower()
    assert "not arbitrary command execution" in result.reasons[1].lower()
    assert new_disposition == Disposition.HARDENING


def test_accept_valid_finding_all_gates_pass(
    valid_finding, network_evidence, complete_checklist, strict_policy
):
    """Test that valid finding passing all gates is accepted."""
    # Arrange
    classification = ClassificationResult(
        disposition=Disposition.VALID_SECURITY_ISSUE,
        classification_confidence=95,
        exploit_confidence=90,
        proof_checklist=complete_checklist,
        reasoning=["All items proven", "Shell execution confirmed"],
        category=VulnerabilityCategory.COMMAND_INJECTION
    )

    evaluator = ProtocolEvaluator()

    # Act
    result, new_disposition = evaluator.evaluate(
        valid_finding, network_evidence, classification, strict_policy
    )

    # Assert
    assert result.decision == SubmissionDecision.SUBMIT
    assert "All protocol gates passed" in result.reasons[0]
    assert result.disposition_modified is False
    assert new_disposition is None
