"""Tests for finding deduplication."""
import pytest
from models.schemas import Finding, Severity
from services.deduplicator import (
    deduplicate_findings,
    normalize_path,
    normalize_vuln_type,
    get_line_range,
    ranges_overlap
)
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


def test_ranges_overlap_exact_match():
    """Test that identical ranges overlap."""
    assert ranges_overlap((10, 15), (10, 15)) is True
    assert ranges_overlap((5, 5), (5, 5)) is True


def test_ranges_overlap_partial_overlap():
    """Test that partially overlapping ranges are detected."""
    assert ranges_overlap((10, 15), (12, 18)) is True  # Overlap 12-15
    assert ranges_overlap((10, 15), (5, 12)) is True   # Overlap 10-12
    assert ranges_overlap((10, 15), (8, 20)) is True   # One contains other


def test_ranges_overlap_containment():
    """Test that contained ranges overlap."""
    assert ranges_overlap((10, 20), (12, 15)) is True  # (12,15) inside (10,20)
    assert ranges_overlap((12, 15), (10, 20)) is True  # Symmetric


def test_ranges_overlap_adjacent_no_overlap():
    """Test that adjacent ranges don't overlap."""
    assert ranges_overlap((10, 15), (16, 20)) is False
    assert ranges_overlap((16, 20), (10, 15)) is False


def test_ranges_overlap_separated_no_overlap():
    """Test that separated ranges don't overlap."""
    assert ranges_overlap((10, 15), (20, 25)) is False
    assert ranges_overlap((20, 25), (10, 15)) is False


def test_ranges_overlap_touching_boundary():
    """Test that ranges touching at boundary overlap."""
    # Touching at 15 should overlap (inclusive)
    assert ranges_overlap((10, 15), (15, 20)) is True
    assert ranges_overlap((15, 20), (10, 15)) is True


# Helper function to create findings
def create_finding(
    id: str,
    file_path: str,
    line_start: int,
    line_end: int | None,
    vulnerability_type: str,
    title: str = "Test Finding",
    description: str = "Test description"
) -> Finding:
    """Helper to create test findings."""
    return Finding(
        id=id,
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        vulnerability_type=vulnerability_type,
        title=title,
        description=description,
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )


class TestDeduplicateFindings:
    """Test overlap-based deduplication."""

    def test_empty_list_returns_empty(self):
        """Test that empty list returns empty."""
        result = deduplicate_findings([])
        assert result == []

    def test_single_finding_returns_as_is(self):
        """Test that single finding is returned as-is."""
        finding = create_finding("1", "src/main.py", 10, 15, "SQL Injection")
        result = deduplicate_findings([finding])
        assert len(result) == 1
        assert result[0].id == "1"

    def test_different_files_no_dedup(self):
        """Test that findings in different files are not deduplicated."""
        findings = [
            create_finding("1", "src/main.py", 10, 15, "SQL Injection"),
            create_finding("2", "src/other.py", 10, 15, "SQL Injection")
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_different_vuln_types_no_dedup(self):
        """Test that different vulnerability types are not deduplicated."""
        findings = [
            create_finding("1", "src/main.py", 10, 15, "SQL Injection"),
            create_finding("2", "src/main.py", 10, 15, "XSS")
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_non_overlapping_lines_no_dedup(self):
        """Test that non-overlapping line ranges are not deduplicated."""
        findings = [
            create_finding("1", "src/main.py", 10, 15, "SQL Injection"),
            create_finding("2", "src/main.py", 20, 25, "SQL Injection")
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_exact_same_line_deduplicates(self):
        """Test that exact same line is deduplicated (first preserved)."""
        findings = [
            create_finding("1", "src/main.py", 10, 10, "SQL Injection", "Finding 1"),
            create_finding("2", "src/main.py", 10, 10, "SQL Injection", "Finding 2")
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].id == "1"
        assert result[0].title == "Finding 1"

    def test_overlapping_line_ranges_deduplicates(self):
        """Test that overlapping line ranges are deduplicated."""
        findings = [
            create_finding("1", "src/main.py", 10, 15, "SQL Injection"),
            create_finding("2", "src/main.py", 12, 18, "SQL Injection")  # Overlaps 12-15
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].id == "1"

    def test_contained_range_deduplicates(self):
        """Test that contained ranges are deduplicated."""
        findings = [
            create_finding("1", "src/main.py", 10, 20, "SQL Injection"),
            create_finding("2", "src/main.py", 12, 15, "SQL Injection")  # Contained
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].id == "1"

    def test_path_normalization_deduplicates(self):
        """Test that path normalization enables deduplication."""
        findings = [
            create_finding("1", "src/main.py", 10, 15, "SQL Injection"),
            create_finding("2", "./src/main.py", 10, 15, "SQL Injection"),  # Same after normalization
            create_finding("3", "SRC/MAIN.PY", 10, 15, "SQL Injection")  # Same after case normalization
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].id == "1"

    def test_vuln_type_normalization_deduplicates(self):
        """Test that vulnerability type normalization enables deduplication."""
        findings = [
            create_finding("1", "src/main.py", 10, 15, "SQL Injection"),
            create_finding("2", "src/main.py", 10, 15, "sql injection"),  # Same after normalization
            create_finding("3", "src/main.py", 10, 15, "  SQL INJECTION  ")  # Same after strip+lowercase
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].id == "1"

    def test_multi_agent_same_finding_deduplicates(self):
        """Test that same finding from different agents is deduplicated."""
        finding1 = create_finding("1", "src/main.py", 10, 15, "SQL Injection")
        finding1.agent_id = "agent1"

        finding2 = create_finding("2", "src/main.py", 10, 15, "SQL Injection")
        finding2.agent_id = "agent2"

        result = deduplicate_findings([finding1, finding2])
        assert len(result) == 1
        assert result[0].id == "1"

    def test_preserves_distinct_findings_in_same_file(self):
        """Test that distinct findings in same file are preserved."""
        findings = [
            create_finding("1", "src/main.py", 10, 15, "SQL Injection"),
            create_finding("2", "src/main.py", 20, 25, "SQL Injection"),  # Different lines
            create_finding("3", "src/main.py", 10, 15, "XSS"),  # Different type
            create_finding("4", "src/main.py", 30, 35, "Command Injection")  # Different type and lines
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 4
