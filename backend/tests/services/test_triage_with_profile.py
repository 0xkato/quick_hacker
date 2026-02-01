"""Tests for triage pipeline with ValidationProfile integration."""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from models.validation_profile import ValidationProfile, CategoryEvidenceGate


class TestTriageWithProfile:
    @pytest.fixture
    def sample_profile(self):
        return ValidationProfile(
            excluded_paths=["test/"],
            evidence_gates={
                "sql_injection": CategoryEvidenceGate(
                    required=["source_identified", "sink_identified"],
                    reject_if=["test_only"],
                ),
            },
        )

    @pytest.fixture
    def sample_finding(self):
        mock = MagicMock()
        mock.id = "finding-123"
        mock.file_path = "src/handler.py"
        mock.vulnerability_type = "sql_injection"
        mock.severity = "high"
        return mock

    @pytest.fixture
    def test_only_finding(self):
        mock = MagicMock()
        mock.id = "finding-456"
        mock.file_path = "test/test_handler.py"
        mock.vulnerability_type = "sql_injection"
        mock.severity = "high"
        return mock

    def test_triage_service_accepts_profile(self, sample_profile, sample_finding):
        """Verify triage service can accept validation profile parameter."""
        from services.finding_triage_service import should_skip_by_path

        # File not in excluded path should not be skipped
        result = should_skip_by_path(sample_finding.file_path, sample_profile)
        assert result is False

    def test_triage_skips_excluded_paths(self, sample_profile, test_only_finding):
        """Verify findings in excluded paths are skipped."""
        from services.finding_triage_service import should_skip_by_path

        result = should_skip_by_path(test_only_finding.file_path, sample_profile)
        assert result is True

    def test_triage_without_profile(self, sample_finding):
        """Verify triage works without profile (backwards compatible)."""
        from services.finding_triage_service import should_skip_by_path

        result = should_skip_by_path(sample_finding.file_path, None)
        assert result is False
