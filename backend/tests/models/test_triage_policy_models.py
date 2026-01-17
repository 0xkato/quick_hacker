"""Tests for TriagePolicy models."""
import pytest
from models.schemas import PathClassification, PolicyDecision, PathClassificationConfig, CommandInjectionGate, IntegerOverflowGate, EvidenceGates, MemoryCorruptionGate, DosGate, DeduplicationConfig, TriagePolicy, PolicyEvaluationResult, Disposition


class TestPathClassification:
    def test_path_classification_enum_values(self):
        """Test PathClassification enum has expected values."""
        assert PathClassification.runtime == "runtime"
        assert PathClassification.tooling == "tooling"
        assert PathClassification.third_party == "third_party"
        assert PathClassification.unknown == "unknown"

    def test_path_classification_is_string_enum(self):
        """Test PathClassification inherits from str."""
        assert isinstance(PathClassification.runtime, str)


class TestPolicyDecision:
    def test_policy_decision_enum_values(self):
        """Test PolicyDecision enum has expected values."""
        assert PolicyDecision.REPORT_SECURITY_VRP == "report_security_vrp"
        assert PolicyDecision.REPORT_SECURITY_LOW_CONFIDENCE == "report_security_low"
        assert PolicyDecision.HARDENING_ONLY == "hardening_only"
        assert PolicyDecision.DO_NOT_REPORT == "do_not_report"

    def test_policy_decision_is_string_enum(self):
        """Test PolicyDecision inherits from str."""
        assert isinstance(PolicyDecision.REPORT_SECURITY_VRP, str)


class TestPathClassificationConfig:
    def test_path_classification_config_defaults(self):
        """Test PathClassificationConfig has sensible defaults."""
        config = PathClassificationConfig()

        # Runtime roots
        assert "src/" in config.runtime_roots
        assert "app/" in config.runtime_roots
        assert "backend/" in config.runtime_roots

        # Tooling roots
        assert "tools/" in config.tooling_roots
        assert "scripts/" in config.tooling_roots

        # Third party roots
        assert "third_party/" in config.third_party_roots
        assert "vendor/" in config.third_party_roots
        assert "node_modules/" in config.third_party_roots

        # Test roots
        assert "test/" in config.test_roots
        assert "tests/" in config.test_roots

        # CI roots
        assert ".github/" in config.ci_roots
        assert ".gitlab/" in config.ci_roots

        # Docs roots
        assert "docs/" in config.docs_roots

        # Migration roots
        assert "migrations/" in config.migration_roots

    def test_path_classification_config_custom_roots(self):
        """Test PathClassificationConfig accepts custom roots."""
        config = PathClassificationConfig(
            runtime_roots=["custom/src/"],
            tooling_roots=["custom/tools/"]
        )

        assert config.runtime_roots == ["custom/src/"]
        assert config.tooling_roots == ["custom/tools/"]
        # Defaults preserved for others
        assert "third_party/" in config.third_party_roots

    def test_path_classification_config_rejects_empty_lists(self):
        """Test PathClassificationConfig rejects empty root lists."""
        with pytest.raises(ValueError, match="Path roots cannot be empty"):
            PathClassificationConfig(runtime_roots=[])

    def test_path_classification_config_requires_trailing_slash(self):
        """Test PathClassificationConfig requires paths to end with '/'."""
        with pytest.raises(ValueError, match="Path must end with '/'"):
            PathClassificationConfig(runtime_roots=["src"])


class TestCommandInjectionGate:
    def test_command_injection_gate_defaults(self):
        """Test CommandInjectionGate has strict defaults."""
        gate = CommandInjectionGate()

        assert gate.require_shell_execution is True
        assert gate.require_attacker_controls_shell_string is True
        assert "network" in gate.credible_boundaries
        assert "ci_artifact" in gate.credible_boundaries

    def test_command_injection_gate_custom_config(self):
        """Test CommandInjectionGate accepts custom config."""
        gate = CommandInjectionGate(
            require_shell_execution=False,
            credible_boundaries=["network"]
        )

        assert gate.require_shell_execution is False
        assert gate.credible_boundaries == ["network"]


class TestIntegerOverflowGate:
    def test_integer_overflow_gate_defaults(self):
        """Test IntegerOverflowGate has strict defaults."""
        gate = IntegerOverflowGate()

        assert gate.require_attacker_controlled_operands is True
        assert gate.require_overflow_prone_operation is True
        assert gate.require_allocation_or_bounds_use is True
        assert gate.require_proven_mismatch is True

    def test_integer_overflow_gate_custom_config(self):
        """Test IntegerOverflowGate accepts custom config."""
        gate = IntegerOverflowGate(
            require_proven_mismatch=False
        )

        assert gate.require_proven_mismatch is False
        # Others still default to True
        assert gate.require_attacker_controlled_operands is True


class TestMemoryCorruptionGate:
    def test_memory_corruption_gate_defaults(self):
        """Test MemoryCorruptionGate has correct defaults."""
        gate = MemoryCorruptionGate()

        assert gate.require_asan_trace is False
        assert gate.require_release_config is True
        assert gate.require_untrusted_input_path is True

    def test_memory_corruption_gate_custom_config(self):
        """Test MemoryCorruptionGate accepts custom config."""
        gate = MemoryCorruptionGate(
            require_asan_trace=True,
            require_release_config=False
        )

        assert gate.require_asan_trace is True
        assert gate.require_release_config is False
        assert gate.require_untrusted_input_path is True


class TestDosGate:
    def test_dos_gate_defaults(self):
        """Test DosGate has strict defaults."""
        gate = DosGate()

        assert gate.require_service_boundary is True

    def test_dos_gate_custom_config(self):
        """Test DosGate accepts custom config."""
        gate = DosGate(require_service_boundary=False)

        assert gate.require_service_boundary is False


class TestEvidenceGates:
    def test_evidence_gates_defaults(self):
        """Test EvidenceGates initializes all gate types."""
        gates = EvidenceGates()

        assert isinstance(gates.command_injection, CommandInjectionGate)
        assert isinstance(gates.integer_overflow, IntegerOverflowGate)
        assert isinstance(gates.memory_corruption, MemoryCorruptionGate)
        assert isinstance(gates.dos, DosGate)

    def test_evidence_gates_custom_gates(self):
        """Test EvidenceGates accepts custom gate configs."""
        gates = EvidenceGates(
            command_injection=CommandInjectionGate(require_shell_execution=False)
        )

        assert gates.command_injection.require_shell_execution is False
        # Others still use defaults
        assert gates.integer_overflow.require_attacker_controlled_operands is True


class TestDeduplicationConfig:
    def test_deduplication_config_defaults(self):
        """Test DeduplicationConfig has sensible defaults."""
        config = DeduplicationConfig()

        assert config.enabled is True
        assert config.strategy == "exact"
        assert "file_path" in config.exact_match_fields
        assert "line_start" in config.exact_match_fields
        assert "vulnerability_type" in config.exact_match_fields
        assert "title" in config.exact_match_fields

    def test_deduplication_config_can_be_disabled(self):
        """Test DeduplicationConfig can be disabled."""
        config = DeduplicationConfig(enabled=False)
        assert config.enabled is False


class TestTriagePolicy:
    def test_triage_policy_minimal_creation(self):
        """Test TriagePolicy can be created with just a name."""
        policy = TriagePolicy(name="test-policy")

        assert policy.name == "test-policy"
        assert isinstance(policy.path_classification, PathClassificationConfig)
        assert isinstance(policy.evidence_gates, EvidenceGates)
        assert isinstance(policy.deduplication, DeduplicationConfig)

    def test_triage_policy_filter_defaults(self):
        """Test TriagePolicy has strict filter defaults."""
        policy = TriagePolicy(name="test")

        assert policy.filter_third_party is True
        assert policy.filter_tests is True
        assert policy.filter_ci is True
        assert policy.filter_docs is True
        assert policy.filter_migrations is True
        assert policy.tooling_requires_ci_boundary is True

    def test_triage_policy_report_defaults(self):
        """Test TriagePolicy doesn't report hardening/by_design by default."""
        policy = TriagePolicy(name="test")

        assert policy.report_hardening is False
        assert policy.report_by_design is False

    def test_triage_policy_custom_config(self):
        """Test TriagePolicy accepts custom configuration."""
        policy = TriagePolicy(
            name="custom",
            filter_third_party=False,
            report_hardening=True,
            path_classification=PathClassificationConfig(
                runtime_roots=["custom/"]
            )
        )

        assert policy.filter_third_party is False
        assert policy.report_hardening is True
        assert policy.path_classification.runtime_roots == ["custom/"]


class TestPolicyEvaluationResult:
    def test_policy_evaluation_result_creation(self):
        """Test PolicyEvaluationResult can be created."""
        result = PolicyEvaluationResult(
            decision=PolicyDecision.REPORT_SECURITY_VRP,
            path_classification=PathClassification.runtime,
            gate_results={"command_injection": True},
            reasoning=["All gates passed"],
            original_disposition=Disposition.VALID_SECURITY_ISSUE,
            overridden=False
        )

        assert result.decision == PolicyDecision.REPORT_SECURITY_VRP
        assert result.path_classification == PathClassification.runtime
        assert result.gate_results["command_injection"] is True
        assert "All gates passed" in result.reasoning
        assert result.original_disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.overridden is False
