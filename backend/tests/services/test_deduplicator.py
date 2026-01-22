"""Tests for finding deduplication."""
import pytest
from models.schemas import Finding, DeduplicationConfig, Severity
from services.deduplicator import deduplicate_findings, normalize_path, normalize_vuln_type, get_line_range
from datetime import datetime, timezone


def test_normalize_path_strips_leading_dot_slash():
    """Test that leading ./ is stripped from paths."""
    assert normalize_path("./src/main.py") == "src/main.py"
    assert normalize_path("./app/test.py") == "app/test.py"


def test_normalize_path_lowercases():
    """Test that paths are lowercased."""
    assert normalize_path("Src/Main.py") == "src/main.py"
    assert normalize_path("APP/TEST.PY") == "app/test.py"


def test_normalize_path_normalizes_separators():
    """Test that backslashes are converted to forward slashes."""
    assert normalize_path("src\\main.py") == "src/main.py"
    assert normalize_path("app\\sub\\test.py") == "app/sub/test.py"


def test_normalize_path_handles_empty_and_none():
    """Test that empty strings and None are handled gracefully."""
    assert normalize_path("") == ""
    assert normalize_path(None) == ""


def test_normalize_vuln_type_lowercases():
    """Test that vulnerability types are lowercased."""
    assert normalize_vuln_type("SQL Injection") == "sql injection"
    assert normalize_vuln_type("XSS") == "xss"
    assert normalize_vuln_type("Command_Injection") == "command_injection"


def test_normalize_vuln_type_strips_whitespace():
    """Test that leading/trailing whitespace is stripped."""
    assert normalize_vuln_type("  SQL Injection  ") == "sql injection"
    assert normalize_vuln_type("\tXSS\n") == "xss"


def test_normalize_vuln_type_handles_empty_and_none():
    """Test that empty strings and None are handled gracefully."""
    assert normalize_vuln_type("") == ""
    assert normalize_vuln_type(None) == ""


def test_get_line_range_with_line_end():
    """Test that line range is extracted when line_end is present."""
    finding = Finding(
        id="1",
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="test.py",
        line_start=10,
        line_end=15,
        vulnerability_type="SQL Injection",
        title="Test",
        description="Test",
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )

    assert get_line_range(finding) == (10, 15)


def test_get_line_range_without_line_end():
    """Test that line_start is used for both when line_end is None."""
    finding = Finding(
        id="1",
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="test.py",
        line_start=10,
        line_end=None,
        vulnerability_type="SQL Injection",
        title="Test",
        description="Test",
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )

    assert get_line_range(finding) == (10, 10)


def test_get_line_range_handles_line_end_less_than_start():
    """Test that invalid ranges (end < start) are treated as single-line."""
    finding = Finding(
        id="1",
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="test.py",
        line_start=10,
        line_end=8,  # Invalid: less than start
        vulnerability_type="SQL Injection",
        title="Test",
        description="Test",
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )

    result = get_line_range(finding)
    assert result == (10, 10)


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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
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
                created_at=datetime.now(timezone.utc)
            )
        ]

        deduplicated = deduplicate_findings(findings, config)

        # Should dedupe because file_path and vulnerability_type match
        assert len(deduplicated) == 1
        assert deduplicated[0].id == "1"
