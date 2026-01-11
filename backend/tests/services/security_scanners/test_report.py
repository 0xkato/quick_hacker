"""Tests for security_scanners report generator."""
import json
import pytest

from services.security_scanners.base import (
    Severity,
    ScannerTool,
    ScanFinding,
)
from services.security_scanners.report import (
    generate_report,
    _generate_markdown,
    _generate_json,
    _generate_sarif,
    _count_by_severity,
    _count_by_tool,
    _group_by_file,
    _severity_to_sarif_level,
)


@pytest.fixture
def sample_findings():
    """Sample findings for testing report generation."""
    return [
        ScanFinding(
            tool=ScannerTool.SECRETS,
            severity=Severity.CRITICAL,
            title="AWS Access Key detected",
            file_path="src/config.py",
            line_start=10,
            line_end=None,
            snippet="AKIA...MPLE",
            confidence=0.9,
            details={"fingerprint": "abc123", "pattern_name": "aws_access_key"},
        ),
        ScanFinding(
            tool=ScannerTool.SECRETS,
            severity=Severity.HIGH,
            title="Private Key detected",
            file_path="src/config.py",
            line_start=25,
            line_end=30,
            snippet="-----BEGIN RSA PRIVATE KEY-----",
            confidence=1.0,
            details={"fingerprint": "def456", "pattern_name": "private_key"},
        ),
        ScanFinding(
            tool=ScannerTool.DEPENDENCIES,
            severity=Severity.HIGH,
            title="Vulnerable dependency: requests",
            file_path="requirements.txt",
            line_start=5,
            line_end=None,
            snippet="requests==2.25.0",
            confidence=1.0,
            details={"cve_id": "CVE-2024-1234", "fixed_version": "2.31.0"},
        ),
        ScanFinding(
            tool=ScannerTool.GREP,
            severity=Severity.MEDIUM,
            title="SQL injection pattern",
            file_path="src/db.py",
            line_start=42,
            line_end=None,
            snippet="query = f\"SELECT * FROM users WHERE id = {user_id}\"",
            confidence=0.8,
            details={"pattern": "f-string SQL"},
        ),
        ScanFinding(
            tool=ScannerTool.GREP,
            severity=Severity.LOW,
            title="Debug logging",
            file_path="src/utils.py",
            line_start=15,
            line_end=None,
            snippet="logger.debug(f\"Password: {password}\")",
            confidence=0.7,
            details={"pattern": "password_logging"},
        ),
        ScanFinding(
            tool=ScannerTool.GREP,
            severity=Severity.INFO,
            title="TODO comment found",
            file_path="src/utils.py",
            line_start=100,
            line_end=None,
            snippet="# TODO: fix this security issue",
            confidence=1.0,
            details={"pattern": "todo_security"},
        ),
    ]


class TestGenerateReport:
    """Tests for the main generate_report function."""

    def test_generate_report_markdown(self, sample_findings):
        """generate_report returns markdown for 'markdown' format."""
        result = generate_report(sample_findings, "markdown")
        assert isinstance(result, str)
        assert "# Security Scan Report" in result

    def test_generate_report_json(self, sample_findings):
        """generate_report returns valid JSON for 'json' format."""
        result = generate_report(sample_findings, "json")
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "findings" in parsed

    def test_generate_report_sarif(self, sample_findings):
        """generate_report returns valid SARIF for 'sarif' format."""
        result = generate_report(sample_findings, "sarif")
        parsed = json.loads(result)
        assert parsed["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert parsed["version"] == "2.1.0"

    def test_generate_report_invalid_format_raises(self, sample_findings):
        """generate_report raises ValueError for unknown format."""
        with pytest.raises(ValueError) as exc_info:
            generate_report(sample_findings, "invalid_format")
        assert "invalid_format" in str(exc_info.value).lower()


class TestGenerateMarkdown:
    """Tests for Markdown report generation."""

    def test_markdown_contains_summary_table(self, sample_findings):
        """Markdown report includes a summary table with severity counts."""
        result = _generate_markdown(sample_findings)
        # Check for severity counts in the summary
        assert "critical" in result.lower()
        assert "high" in result.lower()
        assert "medium" in result.lower()
        assert "low" in result.lower()

    def test_markdown_contains_findings_count(self, sample_findings):
        """Markdown report includes total findings count."""
        result = _generate_markdown(sample_findings)
        # 6 findings total
        assert "6" in result

    def test_markdown_groups_by_file(self, sample_findings):
        """Markdown report groups findings by file path."""
        result = _generate_markdown(sample_findings)
        # Each file should appear as a section
        assert "src/config.py" in result
        assert "requirements.txt" in result
        assert "src/db.py" in result
        assert "src/utils.py" in result

    def test_markdown_includes_finding_details(self, sample_findings):
        """Markdown report includes finding titles and snippets."""
        result = _generate_markdown(sample_findings)
        assert "AWS Access Key detected" in result
        assert "Private Key detected" in result
        assert "SQL injection pattern" in result

    def test_markdown_includes_line_numbers(self, sample_findings):
        """Markdown report includes line numbers."""
        result = _generate_markdown(sample_findings)
        # Line 10 from first finding
        assert "10" in result
        # Line 42 from SQL injection finding
        assert "42" in result

    def test_markdown_valid_format(self, sample_findings):
        """Markdown report uses valid markdown syntax."""
        result = _generate_markdown(sample_findings)
        # Should start with a header
        assert result.strip().startswith("#")
        # Should have code blocks for snippets
        assert "```" in result

    def test_markdown_empty_findings(self):
        """Markdown report handles empty findings list."""
        result = _generate_markdown([])
        assert "# Security Scan Report" in result
        assert "0" in result or "No findings" in result.lower()


class TestGenerateJson:
    """Tests for JSON report generation."""

    def test_json_valid_format(self, sample_findings):
        """JSON report is valid JSON."""
        result = _generate_json(sample_findings)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_json_contains_total(self, sample_findings):
        """JSON report includes total findings count."""
        result = _generate_json(sample_findings)
        parsed = json.loads(result)
        assert parsed["total"] == 6

    def test_json_contains_severity_counts(self, sample_findings):
        """JSON report includes severity breakdown."""
        result = _generate_json(sample_findings)
        parsed = json.loads(result)
        assert "by_severity" in parsed
        assert parsed["by_severity"]["critical"] == 1
        assert parsed["by_severity"]["high"] == 2
        assert parsed["by_severity"]["medium"] == 1
        assert parsed["by_severity"]["low"] == 1
        assert parsed["by_severity"]["info"] == 1

    def test_json_contains_tool_counts(self, sample_findings):
        """JSON report includes tool breakdown."""
        result = _generate_json(sample_findings)
        parsed = json.loads(result)
        assert "by_tool" in parsed
        assert parsed["by_tool"]["secrets"] == 2
        assert parsed["by_tool"]["dependencies"] == 1
        assert parsed["by_tool"]["grep"] == 3

    def test_json_contains_findings_list(self, sample_findings):
        """JSON report includes full findings list."""
        result = _generate_json(sample_findings)
        parsed = json.loads(result)
        assert "findings" in parsed
        assert len(parsed["findings"]) == 6
        # Check first finding structure
        first_finding = parsed["findings"][0]
        assert "tool" in first_finding
        assert "severity" in first_finding
        assert "title" in first_finding
        assert "file_path" in first_finding
        assert "line_start" in first_finding

    def test_json_empty_findings(self):
        """JSON report handles empty findings list."""
        result = _generate_json([])
        parsed = json.loads(result)
        assert parsed["total"] == 0
        assert parsed["findings"] == []
        # All severity counts should be 0
        for severity in ["critical", "high", "medium", "low", "info"]:
            assert parsed["by_severity"][severity] == 0


class TestGenerateSarif:
    """Tests for SARIF report generation."""

    def test_sarif_valid_schema(self, sample_findings):
        """SARIF report follows SARIF 2.1.0 schema."""
        result = _generate_sarif(sample_findings)
        parsed = json.loads(result)
        assert parsed["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert parsed["version"] == "2.1.0"

    def test_sarif_contains_runs(self, sample_findings):
        """SARIF report contains runs array."""
        result = _generate_sarif(sample_findings)
        parsed = json.loads(result)
        assert "runs" in parsed
        assert isinstance(parsed["runs"], list)
        assert len(parsed["runs"]) >= 1

    def test_sarif_tool_info(self, sample_findings):
        """SARIF report contains tool information."""
        result = _generate_sarif(sample_findings)
        parsed = json.loads(result)
        run = parsed["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "name" in run["tool"]["driver"]

    def test_sarif_results_count(self, sample_findings):
        """SARIF report contains correct number of results."""
        result = _generate_sarif(sample_findings)
        parsed = json.loads(result)
        run = parsed["runs"][0]
        assert "results" in run
        assert len(run["results"]) == 6

    def test_sarif_result_structure(self, sample_findings):
        """SARIF results have required structure."""
        result = _generate_sarif(sample_findings)
        parsed = json.loads(result)
        run = parsed["runs"][0]
        first_result = run["results"][0]

        # Required SARIF result fields
        assert "ruleId" in first_result
        assert "message" in first_result
        assert "text" in first_result["message"]
        assert "level" in first_result
        assert "locations" in first_result

    def test_sarif_location_structure(self, sample_findings):
        """SARIF locations have required structure."""
        result = _generate_sarif(sample_findings)
        parsed = json.loads(result)
        run = parsed["runs"][0]
        first_result = run["results"][0]

        assert len(first_result["locations"]) > 0
        location = first_result["locations"][0]
        assert "physicalLocation" in location
        assert "artifactLocation" in location["physicalLocation"]
        assert "uri" in location["physicalLocation"]["artifactLocation"]
        assert "region" in location["physicalLocation"]
        assert "startLine" in location["physicalLocation"]["region"]

    def test_sarif_severity_to_level_mapping(self, sample_findings):
        """SARIF maps severity levels correctly."""
        result = _generate_sarif(sample_findings)
        parsed = json.loads(result)
        run = parsed["runs"][0]

        # Find results by their rule IDs and check levels
        levels = {}
        for r in run["results"]:
            # Find by checking the message contains the severity-related title
            levels[r["message"]["text"]] = r["level"]

        # CRITICAL -> error
        assert levels["AWS Access Key detected"] == "error"
        # HIGH -> error
        assert levels["Private Key detected"] == "error"
        assert levels["Vulnerable dependency: requests"] == "error"
        # MEDIUM -> warning
        assert levels["SQL injection pattern"] == "warning"
        # LOW -> note
        assert levels["Debug logging"] == "note"
        # INFO -> note
        assert levels["TODO comment found"] == "note"

    def test_sarif_empty_findings(self):
        """SARIF report handles empty findings list."""
        result = _generate_sarif([])
        parsed = json.loads(result)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) >= 1
        run = parsed["runs"][0]
        assert run["results"] == []


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_count_by_severity(self, sample_findings):
        """_count_by_severity returns correct counts."""
        counts = _count_by_severity(sample_findings)
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 1

    def test_count_by_severity_empty(self):
        """_count_by_severity returns zeros for empty list."""
        counts = _count_by_severity([])
        for severity in ["critical", "high", "medium", "low", "info"]:
            assert counts[severity] == 0

    def test_count_by_tool(self, sample_findings):
        """_count_by_tool returns correct counts."""
        counts = _count_by_tool(sample_findings)
        assert counts["secrets"] == 2
        assert counts["dependencies"] == 1
        assert counts["grep"] == 3

    def test_count_by_tool_empty(self):
        """_count_by_tool returns zeros for empty list."""
        counts = _count_by_tool([])
        for tool in ["secrets", "dependencies", "grep"]:
            assert counts[tool] == 0

    def test_group_by_file(self, sample_findings):
        """_group_by_file groups findings correctly."""
        grouped = _group_by_file(sample_findings)
        assert "src/config.py" in grouped
        assert "requirements.txt" in grouped
        assert "src/db.py" in grouped
        assert "src/utils.py" in grouped

        # Check counts per file
        assert len(grouped["src/config.py"]) == 2
        assert len(grouped["requirements.txt"]) == 1
        assert len(grouped["src/db.py"]) == 1
        assert len(grouped["src/utils.py"]) == 2

    def test_group_by_file_empty(self):
        """_group_by_file returns empty dict for empty list."""
        grouped = _group_by_file([])
        assert grouped == {}

    def test_severity_to_sarif_level_critical(self):
        """CRITICAL severity maps to 'error'."""
        assert _severity_to_sarif_level(Severity.CRITICAL) == "error"

    def test_severity_to_sarif_level_high(self):
        """HIGH severity maps to 'error'."""
        assert _severity_to_sarif_level(Severity.HIGH) == "error"

    def test_severity_to_sarif_level_medium(self):
        """MEDIUM severity maps to 'warning'."""
        assert _severity_to_sarif_level(Severity.MEDIUM) == "warning"

    def test_severity_to_sarif_level_low(self):
        """LOW severity maps to 'note'."""
        assert _severity_to_sarif_level(Severity.LOW) == "note"

    def test_severity_to_sarif_level_info(self):
        """INFO severity maps to 'note'."""
        assert _severity_to_sarif_level(Severity.INFO) == "note"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_finding_with_line_range(self, sample_findings):
        """Reports handle findings with line_end specified."""
        # Find a finding with line_end set
        finding_with_range = [f for f in sample_findings if f.line_end is not None][0]
        assert finding_with_range.line_start == 25
        assert finding_with_range.line_end == 30

        # Test in markdown
        md_result = _generate_markdown([finding_with_range])
        assert "25" in md_result

        # Test in JSON
        json_result = _generate_json([finding_with_range])
        parsed = json.loads(json_result)
        assert parsed["findings"][0]["line_end"] == 30

        # Test in SARIF
        sarif_result = _generate_sarif([finding_with_range])
        parsed = json.loads(sarif_result)
        location = parsed["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["region"]["startLine"] == 25
        assert location["physicalLocation"]["region"]["endLine"] == 30

    def test_finding_with_special_characters(self):
        """Reports handle findings with special characters in snippet."""
        finding = ScanFinding(
            tool=ScannerTool.GREP,
            severity=Severity.HIGH,
            title="Test with special chars",
            file_path="test.py",
            line_start=1,
            line_end=None,
            snippet='query = f"SELECT * FROM users WHERE id = \'{user_id}\'"',
            confidence=1.0,
            details={},
        )

        # Should not raise
        md_result = _generate_markdown([finding])
        json_result = _generate_json([finding])
        sarif_result = _generate_sarif([finding])

        assert isinstance(md_result, str)
        # JSON should be valid
        json.loads(json_result)
        json.loads(sarif_result)

    def test_finding_with_empty_details(self):
        """Reports handle findings with empty details dict."""
        finding = ScanFinding(
            tool=ScannerTool.SECRETS,
            severity=Severity.HIGH,
            title="Test finding",
            file_path="test.py",
            line_start=1,
            line_end=None,
            snippet="secret_value",
            confidence=0.9,
            details={},
        )

        # Should not raise
        md_result = _generate_markdown([finding])
        json_result = _generate_json([finding])
        sarif_result = _generate_sarif([finding])

        assert isinstance(md_result, str)
        json.loads(json_result)
        json.loads(sarif_result)
