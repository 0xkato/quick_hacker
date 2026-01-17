"""Tests for PolicyEvaluator service."""
import pytest
from models.schemas import (
    Finding, Evidence, TriagePolicy, PolicyDecision, PathClassification,
    Disposition, VulnerabilityCategory, ChecklistStatus, ChecklistItem,
    ProofChecklist, InputChannel
)
from services.policy_evaluator import PolicyEvaluator
from services.strict_classifier import ClassificationResult


class TestPolicyEvaluatorInit:
    def test_policy_evaluator_can_be_instantiated(self):
        """Test PolicyEvaluator can be created."""
        evaluator = PolicyEvaluator()
        assert evaluator is not None


class TestPolicyEvaluatorDispositionMapping:
    """Test basic disposition to decision mapping."""

    def test_maps_valid_to_report_vrp(self):
        """Test VALID disposition maps to REPORT_VRP."""
        evaluator = PolicyEvaluator()

        # Create policy
        policy = TriagePolicy(name="test")

        # Create finding with path classification
        finding = Finding(
            id="f1",
            agent_id="a1",
            repo_id="r1",
            severity="high",
            title="SQL Injection",
            description="test",
            file_path="src/api/users.py",
            line_start=10,
            vulnerability_type="sql_injection",
            confidence=0.9,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime
        )

        # Create evidence
        evidence = Evidence(
            finding_id="f1",
            snippet="test snippet",
            input_channel=InputChannel.network
        )

        # Create classification result
        classification = ClassificationResult(
            disposition=Disposition.VALID_SECURITY_ISSUE,
            classification_confidence=90,
            exploit_confidence=85,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                boundary_crossed=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                )
            ),
            reasoning=["All checks passed"]
        )

        # Evaluate
        result = evaluator.evaluate(finding, evidence, classification, policy)

        # Verify decision
        assert result.decision == PolicyDecision.REPORT_SECURITY_VRP
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE

    def test_maps_bug_to_report_low(self):
        """Test BUG disposition maps to REPORT_LOW."""
        evaluator = PolicyEvaluator()

        policy = TriagePolicy(name="test")

        finding = Finding(
            id="f1",
            agent_id="a1",
            repo_id="r1",
            severity="medium",
            title="Auth Bypass",
            description="test",
            file_path="src/api/auth.py",
            line_start=20,
            vulnerability_type="authentication_bypass",
            confidence=0.8,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime
        )

        evidence = Evidence(
            finding_id="f1",
            snippet="test snippet",
            input_channel=InputChannel.network
        )

        classification = ClassificationResult(
            disposition=Disposition.BUG,
            classification_confidence=75,
            exploit_confidence=70,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="test"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                boundary_crossed=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                )
            ),
            reasoning=["Security control bypassed"]
        )

        result = evaluator.evaluate(finding, evidence, classification, policy)

        assert result.decision == PolicyDecision.REPORT_SECURITY_LOW_CONFIDENCE
        assert result.original_disposition == Disposition.BUG

    def test_maps_hardening_to_do_not_report_by_default(self):
        """Test HARDENING disposition maps to DO_NOT_REPORT by default."""
        evaluator = PolicyEvaluator()

        policy = TriagePolicy(name="test", report_hardening=False)

        finding = Finding(
            id="f1",
            agent_id="a1",
            repo_id="r1",
            severity="low",
            title="Potential SQL Injection",
            description="test",
            file_path="src/api/users.py",
            line_start=30,
            vulnerability_type="sql_injection",
            confidence=0.6,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime
        )

        evidence = Evidence(
            finding_id="f1",
            snippet="test snippet",
            input_channel=InputChannel.unknown
        )

        classification = ClassificationResult(
            disposition=Disposition.HARDENING,
            classification_confidence=50,
            exploit_confidence=None,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="test"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="test"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="test"
                ),
                boundary_crossed=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="test"
                ),
                not_only_misconfig=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="test"
                )
            ),
            reasoning=["Sink present but dataflow not proven"]
        )

        result = evaluator.evaluate(finding, evidence, classification, policy)

        assert result.decision == PolicyDecision.DO_NOT_REPORT
        assert result.original_disposition == Disposition.HARDENING


class TestCommandInjectionGate:
    """Test command injection evidence gate."""

    def test_passes_gate_with_shell_true_and_string_interpolation(self):
        """Test gate passes with shell=True + string interpolation + boundary."""
        evaluator = PolicyEvaluator()

        policy = TriagePolicy(name="test")

        # Create finding with command injection category
        finding = Finding(
            id="f1",
            agent_id="a1",
            repo_id="r1",
            severity="critical",
            title="Command Injection via Shell Execution",
            description="User input flows into shell command",
            file_path="src/api/exec.py",
            line_start=42,
            vulnerability_type="command_injection",
            confidence=0.95,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime,
            category=VulnerabilityCategory.COMMAND_INJECTION
        )

        # Evidence showing shell=True with f-string interpolation
        evidence = Evidence(
            finding_id="f1",
            snippet='subprocess.run(f"ping {user_input}", shell=True)',
            input_channel=InputChannel.network
        )

        # VALID classification
        classification = ClassificationResult(
            disposition=Disposition.VALID_SECURITY_ISSUE,
            classification_confidence=95,
            exploit_confidence=90,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="user_input from network request"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="subprocess.run with shell=True"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="f-string interpolation"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="API endpoint"
                ),
                boundary_crossed=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="network input channel"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="requires code change"
                )
            ),
            reasoning=["Shell execution with user-controlled interpolation"]
        )

        # Evaluate - should pass gate
        result = evaluator.evaluate(finding, evidence, classification, policy)

        # Verify decision
        assert result.decision == PolicyDecision.REPORT_SECURITY_VRP
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.gate_results.get("command_injection") is True
        assert result.overridden is False

    def test_fails_gate_without_shell_true(self):
        """Test gate fails without shell=True (argument injection only)."""
        evaluator = PolicyEvaluator()

        policy = TriagePolicy(name="test")

        # Create finding with command injection category
        finding = Finding(
            id="f2",
            agent_id="a1",
            repo_id="r1",
            severity="high",
            title="Potential Argument Injection",
            description="User input flows into command arguments",
            file_path="src/api/exec.py",
            line_start=50,
            vulnerability_type="command_injection",
            confidence=0.85,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime,
            category=VulnerabilityCategory.COMMAND_INJECTION
        )

        # Evidence showing list-based arguments (no shell=True)
        evidence = Evidence(
            finding_id="f2",
            snippet='subprocess.run(["ping", "-c", "1", user_input])',
            input_channel=InputChannel.network
        )

        # VALID classification from classifier
        classification = ClassificationResult(
            disposition=Disposition.VALID_SECURITY_ISSUE,
            classification_confidence=85,
            exploit_confidence=80,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="user_input from network request"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="subprocess.run"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="direct argument passing"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="API endpoint"
                ),
                boundary_crossed=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="network input channel"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="requires code change"
                )
            ),
            reasoning=["Argument injection without shell parsing"]
        )

        # Evaluate - should fail gate and downgrade
        result = evaluator.evaluate(finding, evidence, classification, policy)

        # Verify downgrade to HARDENING_ONLY
        assert result.decision == PolicyDecision.HARDENING_ONLY
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.gate_results.get("command_injection") is False
        assert result.overridden is True
        assert any("shell parsing" in r.lower() or "argument injection" in r.lower()
                   for r in result.reasoning)

    def test_fails_gate_without_string_interpolation(self):
        """Test gate fails without string interpolation (safe argument passing)."""
        evaluator = PolicyEvaluator()

        policy = TriagePolicy(name="test")

        # Create finding with command injection category
        finding = Finding(
            id="f3",
            agent_id="a1",
            repo_id="r1",
            severity="high",
            title="Potential Command Injection",
            description="User input flows into shell command",
            file_path="src/api/exec.py",
            line_start=60,
            vulnerability_type="command_injection",
            confidence=0.90,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime,
            category=VulnerabilityCategory.COMMAND_INJECTION
        )

        # Evidence showing shell=True but no interpolation (safe usage)
        evidence = Evidence(
            finding_id="f3",
            snippet='subprocess.run("ls -la", shell=True)',
            input_channel=InputChannel.ci_artifact
        )

        # VALID classification from classifier
        classification = ClassificationResult(
            disposition=Disposition.VALID_SECURITY_ISSUE,
            classification_confidence=90,
            exploit_confidence=85,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="artifact from CI pipeline"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="subprocess.run with shell=True"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="static command string"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="CI pipeline"
                ),
                boundary_crossed=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="ci_artifact input channel"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="requires code change"
                )
            ),
            reasoning=["Shell execution with static command"]
        )

        # Evaluate - should fail gate and downgrade
        result = evaluator.evaluate(finding, evidence, classification, policy)

        # Verify downgrade to HARDENING_ONLY
        assert result.decision == PolicyDecision.HARDENING_ONLY
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.gate_results.get("command_injection") is False
        assert result.overridden is True
        assert any("interpolation" in r.lower() or "string manipulation" in r.lower()
                   for r in result.reasoning)


class TestIntegerOverflowGate:
    """Test integer overflow evidence gate."""

    def test_passes_gate_with_all_requirements(self):
        """Test gate passes with attacker control + operation + allocation + mismatch."""
        evaluator = PolicyEvaluator()
        policy = TriagePolicy(name="test")

        # Create finding with integer overflow category
        finding = Finding(
            id="f1",
            agent_id="a1",
            repo_id="r1",
            severity="critical",
            title="Integer Overflow in Image Processing",
            description="Multiplication of user-controlled dimensions causes overflow in malloc size",
            file_path="src/image/parser.c",
            line_start=85,
            vulnerability_type="integer_overflow",
            confidence=0.95,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime,
            category=VulnerabilityCategory.INTEGER_OVERFLOW
        )

        # Evidence showing multiplication leading to malloc
        evidence = Evidence(
            finding_id="f1",
            snippet='size_t total = width * height; buf = malloc(total);',
            input_channel=InputChannel.network
        )

        # VALID classification with proven attacker control
        classification = ClassificationResult(
            disposition=Disposition.VALID_SECURITY_ISSUE,
            classification_confidence=95,
            exploit_confidence=90,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="Attacker controls width and height from network request"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="malloc with overflow result"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="width * height flows to malloc"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="API endpoint"
                ),
                boundary_crossed=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="network input channel"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="requires code change"
                )
            ),
            reasoning=["Integer overflow in multiplication used for allocation size"]
        )

        # Evaluate - should pass gate
        result = evaluator.evaluate(finding, evidence, classification, policy)

        # Verify decision
        assert result.decision == PolicyDecision.REPORT_SECURITY_VRP
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.gate_results.get("integer_overflow") is True
        assert result.overridden is False
        assert any("attacker control + overflow op + allocation use + mismatch" in r.lower()
                   for r in result.reasoning)

    def test_fails_gate_without_attacker_control(self):
        """Test gate fails without proven attacker control."""
        evaluator = PolicyEvaluator()
        policy = TriagePolicy(name="test")

        # Create finding with integer overflow category
        finding = Finding(
            id="f2",
            agent_id="a1",
            repo_id="r1",
            severity="high",
            title="Potential Integer Overflow",
            description="Multiplication may overflow",
            file_path="src/image/parser.c",
            line_start=90,
            vulnerability_type="integer_overflow",
            confidence=0.80,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime,
            category=VulnerabilityCategory.INTEGER_OVERFLOW
        )

        # Evidence showing multiplication + malloc
        evidence = Evidence(
            finding_id="f2",
            snippet='size_t total = width * height; buf = malloc(total);',
            input_channel=InputChannel.unknown
        )

        # VALID classification but no proven attacker control
        classification = ClassificationResult(
            disposition=Disposition.VALID_SECURITY_ISSUE,
            classification_confidence=80,
            exploit_confidence=75,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="No clear source of width and height"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="malloc present"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="multiplication flows to malloc"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="reachable code path"
                ),
                boundary_crossed=ChecklistItem(
                    value=False,
                    status=ChecklistStatus.UNKNOWN,
                    reason="unknown input source"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="requires code change"
                )
            ),
            reasoning=["Overflow possible but source unclear"]
        )

        # Evaluate - should fail gate and downgrade
        result = evaluator.evaluate(finding, evidence, classification, policy)

        # Verify downgrade to HARDENING_ONLY
        assert result.decision == PolicyDecision.HARDENING_ONLY
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.gate_results.get("integer_overflow") is False
        assert result.overridden is True
        assert any("no proven attacker control over operands" in r.lower()
                   for r in result.reasoning)

    def test_fails_gate_without_allocation(self):
        """Test gate fails without allocation/bounds use."""
        evaluator = PolicyEvaluator()
        policy = TriagePolicy(name="test")

        # Create finding with integer overflow category
        finding = Finding(
            id="f3",
            agent_id="a1",
            repo_id="r1",
            severity="medium",
            title="Integer Overflow Without Dangerous Use",
            description="Multiplication overflows but result not used dangerously",
            file_path="src/math/calc.c",
            line_start=42,
            vulnerability_type="integer_overflow",
            confidence=0.85,
            created_at="2024-01-01T00:00:00Z",
            path_classification=PathClassification.runtime,
            category=VulnerabilityCategory.INTEGER_OVERFLOW
        )

        # Evidence showing multiplication but NO allocation or array access
        evidence = Evidence(
            finding_id="f3",
            snippet='total = width * height;',  # No malloc, no array index
            input_channel=InputChannel.network
        )

        # VALID classification with proven attacker control
        classification = ClassificationResult(
            disposition=Disposition.VALID_SECURITY_ISSUE,
            classification_confidence=85,
            exploit_confidence=80,
            proof_checklist=ProofChecklist(
                source_controlled_input=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="Attacker controls width and height"
                ),
                sink_present=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="multiplication present"
                ),
                dataflow_evidenced=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="user input flows to multiplication"
                ),
                reachable=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="API endpoint"
                ),
                boundary_crossed=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="network input channel"
                ),
                not_only_misconfig=ChecklistItem(
                    value=True,
                    status=ChecklistStatus.PROVEN,
                    reason="requires code change"
                )
            ),
            reasoning=["Integer overflow in multiplication"]
        )

        # Evaluate - should fail gate and downgrade
        result = evaluator.evaluate(finding, evidence, classification, policy)

        # Verify downgrade to HARDENING_ONLY
        assert result.decision == PolicyDecision.HARDENING_ONLY
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.gate_results.get("integer_overflow") is False
        assert result.overridden is True
        assert any("no allocation/bounds use detected" in r.lower()
                   for r in result.reasoning)
