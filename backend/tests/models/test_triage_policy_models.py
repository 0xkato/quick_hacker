"""Tests for TriagePolicy models."""
import pytest
from models.schemas import PathClassification, PolicyDecision, PathClassificationConfig


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
