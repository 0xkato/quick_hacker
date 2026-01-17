"""Tests for TriagePolicy models."""
import pytest
from models.schemas import PathClassification, PolicyDecision


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
