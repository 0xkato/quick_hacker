"""
End-to-end integration tests for protocol-aware reportability layer.

Tests the complete flow from finding input → evidence gathering → classification →
protocol evaluation → submission decision with quest triggering and disposition overrides.
"""

import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.schemas import (
    Finding,
    Evidence,
    Disposition,
    Severity,
    FindingClassification,
    VulnerabilityCategory,
    InputChannel,
    SubmissionDecision,
    ChecklistStatus,
    ChecklistItem,
    ProofChecklist,
    BudgetConfig,
)
from services.finding_triage_service import FindingTriageService
from services.protocol_policies import get_osvrp_strict_policy, get_internal_policy
from services.classification import ClassificationResult


@pytest.fixture
def temp_repo():
    """Create a temporary repository for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)

        # Create sample vulnerable file
        test_file = repo_path / "cli.py"
        test_file.write_text("""
import os
import subprocess

def run_command(user_input):
    # Vulnerable: command injection
    os.system(f"echo {user_input}")

def run_safe_command(user_input):
    # Safe: using list arguments
    subprocess.run(["echo", user_input], shell=False)
""")

        yield str(repo_path)


@pytest.fixture
def finding_command_injection(temp_repo):
    """Create a sample command injection finding (local CLI bug)."""
    return Finding(
        id=f"finding_{uuid.uuid4().hex[:8]}",
        agent_id="test_agent",
        repo_id="test_repo",
        severity=Severity.HIGH,
        title="Command Injection in CLI Tool",
        description="User input passed to os.system() without validation. "
                    "The CLI tool accepts user input and executes it in a shell context.",
        file_path=f"{temp_repo}/cli.py",
        line_start=7,
        line_end=7,
        code_snippet='os.system(f"echo {user_input}")',
        vulnerable_code='os.system(f"echo {user_input}")',
        vulnerability_type="command_injection",
        cwe_id="CWE-78",
        attack_scenario="Attacker can inject shell metacharacters to execute arbitrary commands.",
        proof_of_concept='user_input = "; rm -rf /tmp/test"',
        recommended_fix="Use subprocess.run() with shell=False and argument list",
        confidence=0.9,
        source_trace=["user_input", "f-string", "os.system"],
        created_at=datetime.utcnow(),
        metadata={},
    )


@pytest.fixture
def finding_social_engineering(temp_repo):
    """Create a finding that requires social engineering."""
    return Finding(
        id=f"finding_{uuid.uuid4().hex[:8]}",
        agent_id="test_agent",
        repo_id="test_repo",
        severity=Severity.MEDIUM,
        title="Path Traversal via Paste Attack",
        description="User must manually paste malicious path into the application. "
                    "Requires convincing user to open a crafted file. "
                    "This is a social engineering attack vector.",
        file_path=f"{temp_repo}/cli.py",
        line_start=10,
        line_end=10,
        code_snippet='open(user_path, "r")',
        vulnerable_code='open(user_path, "r")',
        vulnerability_type="path_traversal",
        cwe_id="CWE-22",
        attack_scenario="Trick the user into pasting ../../etc/passwd",
        proof_of_concept='user_path = "../../etc/passwd"',
        recommended_fix="Validate and sanitize file paths",
        confidence=0.8,
        source_trace=["user_path", "open"],
        created_at=datetime.utcnow(),
        metadata={},
    )


@pytest.mark.asyncio
async def test_full_protocol_flow_with_quest(temp_repo, finding_command_injection):
    """
    Test complete triage flow where:
    - Finding is local CLI bug (command injection)
    - Protocol is osvrp_strict (requires cross-boundary for local bugs)
    - Result should be NEEDS_MORE_INFO
    - Quest should be triggered
    - Verify submission_result present with quest_run=True
    """
    service = FindingTriageService()
    policy = get_osvrp_strict_policy()

    # Mock the EvidenceGatherer to return predictable evidence
    with patch('services.finding_triage_service.EvidenceGatherer') as mock_gatherer_cls:
        # Create evidence for local CLI bug without automation signals
        mock_evidence = Evidence(
            finding_id=finding_command_injection.id,
            snippet='os.system(f"echo {user_input}")',
            handler_snippet="def run_command(user_input):\n    os.system(f\"echo {user_input}\")",
            symbol_info={"name": "run_command", "type": "function"},
            framework=None,
            input_channel=InputChannel.local_unprivileged,
            input_channel_deterministic=True,
            input_channel_signals=["cli_argument"],
            input_channel_reason="CLI tool invoked from command line",
            matches=[],
            timed_out=False,
        )

        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = mock_evidence
        mock_gatherer_cls.return_value = mock_gatherer

        # Mock the StrictClassifier to return valid security issue
        with patch('services.finding_triage_service.StrictClassifier') as mock_classifier_cls:
            mock_classification = ClassificationResult(
                disposition=Disposition.VALID_SECURITY_ISSUE,
                classification_confidence=85,
                exploit_confidence=80,
                proof_checklist=ProofChecklist(
                    source_controlled_input=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="CLI argument from user input",
                        tool_calls=["evidence_gatherer"]
                    ),
                    sink_present=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="os.system() call detected",
                        tool_calls=["pattern_match"]
                    ),
                    dataflow_evidenced=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Direct f-string interpolation",
                        tool_calls=["snippet_analysis"]
                    ),
                    reachable=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Function is exported and called",
                        tool_calls=[]
                    ),
                    boundary_crossed=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="User controls input directly",
                        tool_calls=[]
                    ),
                    not_only_misconfig=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Code-level vulnerability",
                        tool_calls=[]
                    ),
                ),
                reasoning=[
                    "Command injection via os.system()",
                    "User input flows directly to shell",
                    "Missing validation of shell metacharacters"
                ],
                category=VulnerabilityCategory.COMMAND_INJECTION
            )

            mock_classifier = MagicMock()
            mock_classifier.classify.return_value = mock_classification
            mock_classifier_cls.return_value = mock_classifier

            # Run triage with protocol evaluation
            result = await service.triage_with_protocol(
                repo_root=temp_repo,
                findings=[finding_command_injection],
                policy_version="1.0.0",
                protocol_policy=policy,
                db_conn=None,  # No DB for this test
            )

    # Assertions
    assert result.triaged_count == 1
    assert len(result.triaged_findings) == 1

    triaged_finding = result.triaged_findings[0]

    # Verify triage metadata attached
    # Note: Protocol evaluator checks local_boundary gate - local without automation
    # This triggers NEEDS_MORE_INFO with quest_run=True, but no disposition downgrade
    # since it's asking for more info, not rejecting
    assert triaged_finding.disposition == Disposition.VALID_SECURITY_ISSUE
    assert triaged_finding.classification_confidence == 85
    assert triaged_finding.proof_checklist is not None

    # Verify submission_result present
    assert triaged_finding.submission_result is not None
    submission = triaged_finding.submission_result

    # Key assertions for protocol evaluation
    assert submission.protocol_id == "osvrp_strict"
    assert submission.decision == SubmissionDecision.NEEDS_MORE_INFO

    # Verify quest was triggered
    assert submission.quest_run is True

    # Verify missing evidence is specified
    assert len(submission.missing_evidence) > 0
    # Should mention automation/CI/boundary
    missing_text = " ".join(submission.missing_evidence).lower()
    assert any(keyword in missing_text for keyword in ["automation", "ci", "untrusted", "boundary", "tool", "invoked"])

    # Verify reasons explain the decision
    assert len(submission.reasons) > 0
    reasons_text = " ".join(submission.reasons).lower()
    assert "local" in reasons_text or "unprivileged" in reasons_text or "boundary" in reasons_text

    # Disposition should NOT be modified in NEEDS_MORE_INFO case (still VALID_SECURITY_ISSUE)
    assert submission.disposition_modified is False


@pytest.mark.asyncio
async def test_protocol_disposition_override(temp_repo, finding_social_engineering):
    """
    Test that protocol evaluator can override disposition:
    - Finding classified as VALID_SECURITY_ISSUE
    - But requires social engineering
    - Protocol downgrades to HARDENING
    - Verify disposition_modified=True and reason explains downgrade
    """
    service = FindingTriageService()
    policy = get_osvrp_strict_policy()

    with patch('services.finding_triage_service.EvidenceGatherer') as mock_gatherer_cls:
        mock_evidence = Evidence(
            finding_id=finding_social_engineering.id,
            snippet='open(user_path, "r")',
            handler_snippet="def read_file(user_path):\n    return open(user_path, 'r').read()",
            symbol_info={"name": "read_file", "type": "function"},
            framework=None,
            input_channel=InputChannel.local_unprivileged,
            input_channel_deterministic=True,
            input_channel_signals=["cli_argument"],
            input_channel_reason="CLI input",
            matches=[],
            timed_out=False,
        )

        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = mock_evidence
        mock_gatherer_cls.return_value = mock_gatherer

        with patch('services.finding_triage_service.StrictClassifier') as mock_classifier_cls:
            # Classifier initially marks as VALID_SECURITY_ISSUE
            mock_classification = ClassificationResult(
                disposition=Disposition.VALID_SECURITY_ISSUE,
                classification_confidence=75,
                exploit_confidence=60,
                proof_checklist=ProofChecklist(
                    source_controlled_input=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="User-provided path",
                        tool_calls=[]
                    ),
                    sink_present=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="open() call present",
                        tool_calls=[]
                    ),
                    dataflow_evidenced=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Direct path usage",
                        tool_calls=[]
                    ),
                    reachable=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Function is exported",
                        tool_calls=[]
                    ),
                    boundary_crossed=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="User controls input",
                        tool_calls=[]
                    ),
                    not_only_misconfig=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Code vulnerability",
                        tool_calls=[]
                    ),
                ),
                reasoning=[
                    "Path traversal vulnerability",
                    "User input not sanitized",
                    "Can access arbitrary files"
                ],
                category=VulnerabilityCategory.PATH_TRAVERSAL
            )

            mock_classifier = MagicMock()
            mock_classifier.classify.return_value = mock_classification
            mock_classifier_cls.return_value = mock_classifier

            result = await service.triage_with_protocol(
                repo_root=temp_repo,
                findings=[finding_social_engineering],
                policy_version="1.0.0",
                protocol_policy=policy,
                db_conn=None,
            )

    # Assertions
    assert result.triaged_count == 1
    triaged_finding = result.triaged_findings[0]

    # Verify disposition was downgraded by protocol
    # The protocol evaluator detects social engineering keywords and downgrades
    assert triaged_finding.submission_result is not None
    submission = triaged_finding.submission_result

    assert submission.protocol_id == "osvrp_strict"
    assert submission.decision == SubmissionDecision.DONT_SUBMIT

    # Key assertion: disposition was modified
    assert submission.disposition_modified is True

    # Verify the new disposition is HARDENING (downgraded from VALID_SECURITY_ISSUE)
    assert triaged_finding.disposition == Disposition.HARDENING

    # Verify disposition_reason explains why
    assert submission.disposition_reason is not None
    reason_lower = submission.disposition_reason.lower()
    assert "social engineering" in reason_lower or "user cooperation" in reason_lower

    # Verify reasons mention social engineering
    reasons_text = " ".join(submission.reasons).lower()
    assert "social engineering" in reasons_text or "user" in reasons_text

    # Finding should NOT be in reportable list
    assert triaged_finding not in result.reportable_findings
    assert result.reportable_count == 0


@pytest.mark.asyncio
async def test_protocol_submission_accepted(temp_repo, finding_command_injection):
    """
    Test that a well-evidenced finding passes all protocol gates:
    - Use internal policy (permissive)
    - Provide complete checklist with all items PROVEN
    - Verify decision is SUBMIT
    """
    service = FindingTriageService()
    policy = get_internal_policy()  # More permissive policy

    with patch('services.finding_triage_service.EvidenceGatherer') as mock_gatherer_cls:
        mock_evidence = Evidence(
            finding_id=finding_command_injection.id,
            snippet='os.system(f"echo {user_input}")',
            handler_snippet="def run_command(user_input):\n    os.system(f\"echo {user_input}\")",
            symbol_info={"name": "run_command", "type": "function"},
            framework=None,
            input_channel=InputChannel.network,  # Network input (not local)
            input_channel_deterministic=True,
            input_channel_signals=["http_endpoint", "route_registration"],
            input_channel_reason="HTTP request handler",
            matches=[],
            timed_out=False,
        )

        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = mock_evidence
        mock_gatherer_cls.return_value = mock_gatherer

        with patch('services.finding_triage_service.StrictClassifier') as mock_classifier_cls:
            # All checklist items PROVEN
            mock_classification = ClassificationResult(
                disposition=Disposition.VALID_SECURITY_ISSUE,
                classification_confidence=95,
                exploit_confidence=90,
                proof_checklist=ProofChecklist(
                    source_controlled_input=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Network request data",
                        tool_calls=[]
                    ),
                    sink_present=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="os.system() shell execution",
                        tool_calls=[]
                    ),
                    dataflow_evidenced=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Direct data flow confirmed",
                        tool_calls=[]
                    ),
                    reachable=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="HTTP endpoint is reachable",
                        tool_calls=[]
                    ),
                    boundary_crossed=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Network to system command",
                        tool_calls=[]
                    ),
                    not_only_misconfig=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Code-level vulnerability",
                        tool_calls=[]
                    ),
                ),
                reasoning=[
                    "Remote command injection",
                    "Network-accessible endpoint",
                    "No input validation"
                ],
                category=VulnerabilityCategory.COMMAND_INJECTION
            )

            mock_classifier = MagicMock()
            mock_classifier.classify.return_value = mock_classification
            mock_classifier_cls.return_value = mock_classifier

            result = await service.triage_with_protocol(
                repo_root=temp_repo,
                findings=[finding_command_injection],
                policy_version="1.0.0",
                protocol_policy=policy,
                db_conn=None,
            )

    # Assertions
    assert result.triaged_count == 1
    triaged_finding = result.triaged_findings[0]

    # Verify submission accepted
    assert triaged_finding.submission_result is not None
    submission = triaged_finding.submission_result

    assert submission.protocol_id == "internal"
    assert submission.decision == SubmissionDecision.SUBMIT

    # No disposition modification needed
    assert submission.disposition_modified is False
    assert triaged_finding.disposition == Disposition.VALID_SECURITY_ISSUE

    # Should be in reportable findings
    assert triaged_finding in result.reportable_findings
    assert result.reportable_count == 1

    # Verify reasons are positive
    reasons_text = " ".join(submission.reasons).lower()
    assert "passed" in reasons_text or "ready" in reasons_text or "submit" in reasons_text


@pytest.mark.asyncio
async def test_protocol_checklist_quality_gate(temp_repo, finding_command_injection):
    """
    Test that insufficient checklist evidence triggers downgrade:
    - Only 3 items PROVEN
    - Policy requires 6 items (osvrp_strict)
    - Disposition should be downgraded to HARDENING
    - Decision should be DONT_SUBMIT
    """
    service = FindingTriageService()
    policy = get_osvrp_strict_policy()  # Requires 6 proven items

    with patch('services.finding_triage_service.EvidenceGatherer') as mock_gatherer_cls:
        mock_evidence = Evidence(
            finding_id=finding_command_injection.id,
            snippet='os.system(f"echo {user_input}")',
            handler_snippet="def run_command(user_input):\n    os.system(f\"echo {user_input}\")",
            symbol_info={"name": "run_command", "type": "function"},
            framework=None,
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["http_endpoint"],
            input_channel_reason="HTTP endpoint",
            matches=[],
            timed_out=False,
        )

        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = mock_evidence
        mock_gatherer_cls.return_value = mock_gatherer

        with patch('services.finding_triage_service.StrictClassifier') as mock_classifier_cls:
            # Only 3 items proven (insufficient for strict policy)
            mock_classification = ClassificationResult(
                disposition=Disposition.VALID_SECURITY_ISSUE,
                classification_confidence=70,
                exploit_confidence=65,
                proof_checklist=ProofChecklist(
                    source_controlled_input=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Network input",
                        tool_calls=[]
                    ),
                    sink_present=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="os.system() present",
                        tool_calls=[]
                    ),
                    dataflow_evidenced=ChecklistItem(
                        value=True,
                        status=ChecklistStatus.PROVEN,
                        reason="Variable flow observed",
                        tool_calls=[]
                    ),
                    reachable=ChecklistItem(
                        value=False,
                        status=ChecklistStatus.UNKNOWN,
                        reason="Cannot confirm reachability",
                        tool_calls=[]
                    ),
                    boundary_crossed=ChecklistItem(
                        value=False,
                        status=ChecklistStatus.UNKNOWN,
                        reason="Boundary unclear",
                        tool_calls=[]
                    ),
                    not_only_misconfig=ChecklistItem(
                        value=False,
                        status=ChecklistStatus.UNKNOWN,
                        reason="Need more investigation",
                        tool_calls=[]
                    ),
                ),
                reasoning=[
                    "Potential command injection",
                    "Evidence incomplete",
                    "More investigation needed"
                ],
                category=VulnerabilityCategory.COMMAND_INJECTION
            )

            mock_classifier = MagicMock()
            mock_classifier.classify.return_value = mock_classification
            mock_classifier_cls.return_value = mock_classifier

            result = await service.triage_with_protocol(
                repo_root=temp_repo,
                findings=[finding_command_injection],
                policy_version="1.0.0",
                protocol_policy=policy,
                db_conn=None,
            )

    # Assertions
    assert result.triaged_count == 1
    triaged_finding = result.triaged_findings[0]

    assert triaged_finding.submission_result is not None
    submission = triaged_finding.submission_result

    # Checklist quality gate should fail
    assert submission.decision == SubmissionDecision.DONT_SUBMIT

    # Disposition should be downgraded
    assert submission.disposition_modified is True
    assert triaged_finding.disposition == Disposition.HARDENING

    # Verify reason mentions insufficient evidence
    reasons_text = " ".join(submission.reasons).lower()
    assert "proven" in reasons_text or "evidence" in reasons_text or "insufficient" in reasons_text

    # Not reportable
    assert result.reportable_count == 0


def test_protocol_policies_structure():
    """
    Sanity test: verify protocol policies are properly structured.
    """
    osvrp = get_osvrp_strict_policy()
    internal = get_internal_policy()

    # OSVRP should be strict
    assert osvrp.id == "osvrp_strict"
    assert osvrp.min_checklist_proven_count == 6
    assert osvrp.allow_unknown_in_checklist is False
    assert osvrp.require_cross_boundary_for_local_bugs is True
    assert osvrp.reject_social_engineering_only is True
    assert Disposition.VALID_SECURITY_ISSUE in osvrp.min_disposition_to_submit

    # Internal should be permissive
    assert internal.id == "internal"
    assert internal.min_checklist_proven_count == 3
    assert internal.allow_unknown_in_checklist is True
    assert internal.require_cross_boundary_for_local_bugs is False
    assert internal.reject_social_engineering_only is False
    assert Disposition.HARDENING in internal.min_disposition_to_submit
