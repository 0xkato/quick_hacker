"""Tests for security scanner tool integration in ToolExecutor."""
import pytest
import time
import tempfile
import os
from pathlib import Path

from agents.tools import (
    AGENT_TOOLS,
    TOOL_DEFINITIONS,
    ToolExecutor,
    ToolResult,
)


class TestSecurityScannerToolDefinitions:
    """Test that security scanner tools are defined in AGENT_TOOLS."""

    def test_scan_repo_for_secrets_defined(self):
        """scan_repo_for_secrets should be in AGENT_TOOLS."""
        assert "scan_repo_for_secrets" in TOOL_DEFINITIONS
        tool = TOOL_DEFINITIONS["scan_repo_for_secrets"]
        assert "entropy_threshold" in tool["parameters"]["properties"]

    def test_dependency_audit_defined(self):
        """dependency_audit should be in AGENT_TOOLS."""
        assert "dependency_audit" in TOOL_DEFINITIONS
        tool = TOOL_DEFINITIONS["dependency_audit"]
        assert "lockfile_path" in tool["parameters"]["properties"]

    def test_grep_semantic_defined(self):
        """grep_semantic should be in AGENT_TOOLS."""
        assert "grep_semantic" in TOOL_DEFINITIONS
        tool = TOOL_DEFINITIONS["grep_semantic"]
        params = tool["parameters"]
        assert "pattern" in params["properties"]
        assert "context_lines" in params["properties"]
        assert "file_glob" in params["properties"]
        # pattern is required
        assert "pattern" in params.get("required", [])

    def test_generate_security_report_defined(self):
        """generate_security_report should be in AGENT_TOOLS."""
        assert "generate_security_report" in TOOL_DEFINITIONS
        tool = TOOL_DEFINITIONS["generate_security_report"]
        assert "output_format" in tool["parameters"]["properties"]


class TestToolExecutorSecurityScannerInit:
    """Test ToolExecutor initialization for security scanner support."""

    def test_session_start_initialized(self):
        """ToolExecutor should initialize _session_start."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            assert hasattr(executor, "_session_start")
            assert executor._session_start > 0

    def test_total_budget_s_initialized(self):
        """ToolExecutor should initialize _total_budget_s from time_budget_ms."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            assert hasattr(executor, "_total_budget_s")
            assert executor._total_budget_s == 60.0

    def test_security_scan_findings_initialized(self):
        """ToolExecutor should initialize empty _security_scan_findings dict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            assert hasattr(executor, "_security_scan_findings")
            assert executor._security_scan_findings == {}

    def test_findings_cap_initialized(self):
        """ToolExecutor should initialize _findings_cap to 500."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            assert hasattr(executor, "_findings_cap")
            assert executor._findings_cap == 500


class TestToolExecutorSecurityScannerHelpers:
    """Test ToolExecutor helper methods for security scanners."""

    def test_remaining_budget_s(self):
        """_remaining_budget_s should return remaining time."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            remaining = executor._remaining_budget_s()
            # Should be close to 60 seconds (minus small elapsed time)
            assert 58.0 <= remaining <= 60.0

    def test_make_scan_limits(self):
        """_make_scan_limits should create ScanLimits with deadline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            limits = executor._make_scan_limits()

            # Should have a deadline set
            assert limits.deadline is not None
            # Deadline should be in the future
            assert limits.deadline > time.monotonic()

    def test_accumulate_security_findings_dedupes(self):
        """_accumulate_security_findings should dedupe by fingerprint."""
        from services.security_scanners import ScanFinding, ScannerTool, Severity

        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)

            finding = ScanFinding(
                tool=ScannerTool.SECRETS,
                severity=Severity.HIGH,
                title="Test finding",
                file_path="test.py",
                line_start=1,
                line_end=None,
                snippet="secret = 'abc'",
                confidence=0.9,
                details={"fingerprint": "abc123"},
            )

            # Add same finding twice
            executor._accumulate_security_findings([finding])
            executor._accumulate_security_findings([finding])

            # Should only have one entry
            assert len(executor._security_scan_findings) == 1

    def test_accumulate_security_findings_caps_at_limit(self):
        """_accumulate_security_findings should cap at _findings_cap."""
        from services.security_scanners import ScanFinding, ScannerTool, Severity

        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            executor._findings_cap = 5  # Low cap for testing

            findings = []
            for i in range(10):
                findings.append(ScanFinding(
                    tool=ScannerTool.GREP,
                    severity=Severity.INFO,
                    title=f"Finding {i}",
                    file_path="test.py",
                    line_start=i,
                    line_end=None,
                    snippet=f"line {i}",
                    confidence=1.0,
                    details={"fingerprint": f"fp_{i}"},
                ))

            executor._accumulate_security_findings(findings)

            # Should be capped at 5
            assert len(executor._security_scan_findings) == 5

    def test_format_security_scan_result_structure(self):
        """_format_security_scan_result should return proper structure."""
        from services.security_scanners import ScanResult, ScanFinding, ScannerTool, Severity

        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)

            result = ScanResult(
                success=True,
                findings=[],
                files_scanned=10,
                files_skipped=2,
                bytes_scanned=1000,
                duration_ms=100,
            )

            formatted = executor._format_security_scan_result(result)

            assert formatted["success"] is True
            assert formatted["files_scanned"] == 10
            assert formatted["files_skipped"] == 2
            assert formatted["bytes_scanned"] == 1000
            assert formatted["duration_ms"] == 100
            assert "findings" in formatted
            assert "total_accumulated" in formatted


class TestToolExecutorSecretsScanning:
    """Test secrets scanning tool execution."""

    @pytest.mark.asyncio
    async def test_scan_repo_for_secrets_executes(self):
        """scan_repo_for_secrets tool should execute without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with a potential secret
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text('API_KEY = "sk-1234567890abcdef1234567890abcdef"')

            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("scan_repo_for_secrets", {})

            assert isinstance(result, ToolResult)
            assert result.success is True
            assert "files_scanned" in result.data

    @pytest.mark.asyncio
    async def test_scan_repo_for_secrets_custom_threshold(self):
        """scan_repo_for_secrets should accept entropy_threshold parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("scan_repo_for_secrets", {
                "entropy_threshold": 5.0
            })

            assert result.success is True


class TestToolExecutorDependencyAudit:
    """Test dependency audit tool execution."""

    @pytest.mark.asyncio
    async def test_dependency_audit_executes(self):
        """dependency_audit tool should execute without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a requirements.txt
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests==2.28.0\nflask==2.0.0\n")

            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("dependency_audit", {})

            assert isinstance(result, ToolResult)
            assert result.success is True

    @pytest.mark.asyncio
    async def test_dependency_audit_specific_lockfile(self):
        """dependency_audit should accept lockfile_path parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text("requests==2.28.0\n")

            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("dependency_audit", {
                "lockfile_path": "requirements.txt"
            })

            assert result.success is True


class TestToolExecutorGrepSemantic:
    """Test semantic grep tool execution."""

    @pytest.mark.asyncio
    async def test_grep_semantic_requires_pattern(self):
        """grep_semantic should fail without pattern parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("grep_semantic", {})

            assert result.success is False
            assert "pattern" in result.error.lower() or "required" in result.error.lower()

    @pytest.mark.asyncio
    async def test_grep_semantic_executes_with_pattern(self):
        """grep_semantic tool should execute with pattern."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text('def dangerous_function():\n    eval(input())\n')

            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("grep_semantic", {
                "pattern": "eval"
            })

            assert isinstance(result, ToolResult)
            assert result.success is True
            assert "findings" in result.data

    @pytest.mark.asyncio
    async def test_grep_semantic_accepts_context_lines(self):
        """grep_semantic should accept context_lines parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text('line1\neval()\nline3\n')

            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("grep_semantic", {
                "pattern": "eval",
                "context_lines": 1
            })

            assert result.success is True

    @pytest.mark.asyncio
    async def test_grep_semantic_accepts_file_glob(self):
        """grep_semantic should accept file_glob parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text('eval()\n')

            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("grep_semantic", {
                "pattern": "eval",
                "file_glob": "*.py"
            })

            assert result.success is True


class TestToolExecutorSecurityReport:
    """Test security report generation tool."""

    @pytest.mark.asyncio
    async def test_generate_security_report_markdown(self):
        """generate_security_report should generate markdown report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("generate_security_report", {
                "output_format": "markdown"
            })

            assert isinstance(result, ToolResult)
            assert result.success is True
            assert "report" in result.data or isinstance(result.data, str)

    @pytest.mark.asyncio
    async def test_generate_security_report_json(self):
        """generate_security_report should generate JSON report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("generate_security_report", {
                "output_format": "json"
            })

            assert result.success is True

    @pytest.mark.asyncio
    async def test_generate_security_report_sarif(self):
        """generate_security_report should generate SARIF report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)
            result = await executor.execute("generate_security_report", {
                "output_format": "sarif"
            })

            assert result.success is True


class TestFindingsAccumulationAcrossScans:
    """Test that findings accumulate across multiple scans."""

    @pytest.mark.asyncio
    async def test_findings_accumulate_across_scans(self):
        """Findings should accumulate across different scan types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files that will produce findings
            config_file = Path(tmpdir) / "config.py"
            config_file.write_text('API_KEY = "AKIA1234567890ABCDEF"\n')

            test_file = Path(tmpdir) / "dangerous.py"
            test_file.write_text('eval(user_input)\n')

            req_file = Path(tmpdir) / "requirements.txt"
            req_file.write_text('requests==2.0.0\n')

            executor = ToolExecutor(tmpdir, time_budget_ms=60000)

            # Run secrets scan
            await executor.execute("scan_repo_for_secrets", {})
            initial_count = len(executor._security_scan_findings)

            # Run grep scan
            await executor.execute("grep_semantic", {"pattern": "eval"})
            after_grep_count = len(executor._security_scan_findings)

            # Findings should accumulate
            assert after_grep_count >= initial_count


class TestBudgetTracking:
    """Test time budget tracking functionality."""

    def test_budget_decreases_over_time(self):
        """Remaining budget should decrease as time passes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir, time_budget_ms=60000)

            initial_remaining = executor._remaining_budget_s()

            # Small delay
            time.sleep(0.1)

            later_remaining = executor._remaining_budget_s()

            # Later remaining should be less
            assert later_remaining < initial_remaining

    def test_budget_defaults_to_large_value_when_not_specified(self):
        """When time_budget_ms is not specified, should use reasonable default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ToolExecutor(tmpdir)

            # Should not raise and should have a reasonable default
            remaining = executor._remaining_budget_s()
            assert remaining > 0
