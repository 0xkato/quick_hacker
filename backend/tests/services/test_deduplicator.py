"""Tests for finding deduplication."""
import pytest
from models.schemas import Finding, DeduplicationConfig, Severity
from services.deduplicator import deduplicate_findings
from datetime import datetime


class TestDeduplicateFindings:
    def test_removes_exact_duplicates(self):
        """Test exact duplicates are removed, first occurrence preserved."""
        config = DeduplicationConfig()

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Unsafe SQL query",
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Unsafe SQL query",
                description="Different description",  # Only diff is description
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="3",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=11,  # Different line
                vulnerability_type="SQL Injection",
                title="Unsafe SQL query",
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        deduplicated = deduplicate_findings(findings, config)

        # Should keep finding 1 (first) and finding 3 (different line)
        assert len(deduplicated) == 2
        assert deduplicated[0].id == "1"
        assert deduplicated[1].id == "3"

    def test_preserves_different_findings(self):
        """Test different findings are all preserved."""
        config = DeduplicationConfig()

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test 1",
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=20,  # Different line
                vulnerability_type="SQL Injection",
                title="Test 2",  # Different title
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="3",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/other.py",  # Different file
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test 1",
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        deduplicated = deduplicate_findings(findings, config)

        assert len(deduplicated) == 3

    def test_handles_missing_fields_gracefully(self):
        """Test deduplication handles missing fields in fingerprint."""
        config = DeduplicationConfig()

        # This should not crash even if fields are missing
        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test",
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        deduplicated = deduplicate_findings(findings, config)

        assert len(deduplicated) == 1

    def test_deduplication_can_be_disabled(self):
        """Test deduplication can be disabled via config."""
        config = DeduplicationConfig(enabled=False)

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Unsafe SQL query",
                description="Test 1",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Unsafe SQL query",
                description="Test 2",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        deduplicated = deduplicate_findings(findings, config)

        # Both preserved when disabled
        assert len(deduplicated) == 2

    def test_raises_for_unsupported_strategy(self):
        """Test raises NotImplementedError for unsupported strategies."""
        config = DeduplicationConfig(strategy="fuzzy")

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test",
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        with pytest.raises(NotImplementedError, match="fuzzy"):
            deduplicate_findings(findings, config)

    def test_custom_match_fields(self):
        """Test deduplication with custom match fields."""
        config = DeduplicationConfig(
            exact_match_fields=["file_path", "vulnerability_type"]  # Ignore line and title
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test 1",
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path="src/main.py",
                line_start=20,  # Different line (but not in match fields)
                vulnerability_type="SQL Injection",
                title="Test 2",  # Different title (but not in match fields)
                description="Test",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        deduplicated = deduplicate_findings(findings, config)

        # Should dedupe because file_path and vulnerability_type match
        assert len(deduplicated) == 1
        assert deduplicated[0].id == "1"
