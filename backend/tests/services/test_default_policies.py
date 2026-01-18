"""Tests for default VRP policies."""
import pytest
from models.schemas import TriagePolicy
from services.default_policies import VRP_GOOGLE_OSS_STRICT


class TestVRPGoogleOSSStrict:
    def test_vrp_policy_name(self):
        """Verify policy name is vrp-google-oss-strict."""
        assert VRP_GOOGLE_OSS_STRICT.name == "vrp-google-oss-strict"

    def test_vrp_policy_filters_excluded_paths(self):
        """Verify all filters are enabled (third_party, tests, ci, docs, migrations)."""
        assert VRP_GOOGLE_OSS_STRICT.filter_third_party is True
        assert VRP_GOOGLE_OSS_STRICT.filter_tests is True
        assert VRP_GOOGLE_OSS_STRICT.filter_ci is True
        assert VRP_GOOGLE_OSS_STRICT.filter_docs is True
        assert VRP_GOOGLE_OSS_STRICT.filter_migrations is True

    def test_vrp_policy_tooling_requires_ci_boundary(self):
        """Verify tooling findings require CI/automated boundary."""
        assert VRP_GOOGLE_OSS_STRICT.tooling_requires_ci_boundary is True

    def test_vrp_policy_strict_command_injection_gate(self):
        """Verify command injection gate has strict settings."""
        gate = VRP_GOOGLE_OSS_STRICT.evidence_gates.command_injection

        # Must require shell=True or os.system
        assert gate.require_shell_execution is True

        # Must require attacker controls the shell string (not just args)
        assert gate.require_attacker_controls_shell_string is True

        # Credible boundaries should include network, ci_artifact, repo_checkout, file_input
        expected_boundaries = {"network", "ci_artifact", "repo_checkout", "file_input"}
        assert set(gate.credible_boundaries) == expected_boundaries

    def test_vrp_policy_strict_integer_overflow_gate(self):
        """Verify integer overflow gate has strict settings."""
        gate = VRP_GOOGLE_OSS_STRICT.evidence_gates.integer_overflow

        # Must require attacker-controlled operands
        assert gate.require_attacker_controlled_operands is True

        # Must require overflow-prone operation (multiplication/unchecked addition)
        assert gate.require_overflow_prone_operation is True

        # Must require allocation or bounds use (malloc, array index, buffer size)
        assert gate.require_allocation_or_bounds_use is True

        # Must require proven type mismatch (32-bit calc -> 64-bit size)
        assert gate.require_proven_mismatch is True

    def test_vrp_policy_deduplication_enabled(self):
        """Verify deduplication is enabled with exact strategy."""
        dedup = VRP_GOOGLE_OSS_STRICT.deduplication

        assert dedup.enabled is True
        assert dedup.strategy == "exact"

        # Should match on file_path, line_start, vulnerability_type, title
        expected_fields = {"file_path", "line_start", "vulnerability_type", "title"}
        assert set(dedup.exact_match_fields) == expected_fields

    def test_vrp_policy_does_not_report_hardening(self):
        """Verify HARDENING and BY_DESIGN dispositions are not reported."""
        assert VRP_GOOGLE_OSS_STRICT.report_hardening is False
        assert VRP_GOOGLE_OSS_STRICT.report_by_design is False

    def test_vrp_policy_path_classification_defaults(self):
        """Verify path classification has pragmatic defaults."""
        path_config = VRP_GOOGLE_OSS_STRICT.path_classification

        # Runtime roots should include common production code paths
        assert "src/" in path_config.runtime_roots
        assert "app/" in path_config.runtime_roots
        assert "backend/" in path_config.runtime_roots
        assert "frontend/" in path_config.runtime_roots

        # Third party roots should include common dependency paths
        assert "third_party/" in path_config.third_party_roots
        assert "vendor/" in path_config.third_party_roots
        assert "node_modules/" in path_config.third_party_roots

        # Test roots should include common test paths
        assert "test/" in path_config.test_roots
        assert "tests/" in path_config.test_roots

        # CI roots should include common CI paths
        assert ".github/" in path_config.ci_roots
        assert ".gitlab/" in path_config.ci_roots

        # Docs roots should include common documentation paths
        assert "docs/" in path_config.docs_roots

        # Migration roots should include common migration paths
        assert "migrations/" in path_config.migration_roots
