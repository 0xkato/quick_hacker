"""Tests for Semgrep integration."""
import pytest
from unittest import mock
import subprocess
import shutil
from pathlib import Path
from services.security_scanners.base import ScannerTool, ScanResult, Severity
from services.security_scanners.semgrep import SemgrepScanner, SemgrepNotAvailableError
from services.security_scanners.base import WorkspacePolicy, ScanLimits


def test_semgrep_tool_enum_exists():
    """Verify SEMGREP exists in ScannerTool enum."""
    assert hasattr(ScannerTool, "SEMGREP")
    assert ScannerTool.SEMGREP == "semgrep"
    assert str(ScannerTool.SEMGREP) == "semgrep"


def test_semgrep_scanner_initializes(tmp_path):
    """Verify SemgrepScanner can be initialized."""
    # Mock Semgrep being available
    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))
        assert scanner.workspace_root == tmp_path
        assert scanner.get_tool_name() == ScannerTool.SEMGREP


def test_semgrep_checks_availability_on_init(tmp_path):
    """Verify scanner checks if Semgrep is installed."""
    # Mock Semgrep available
    with mock.patch('subprocess.run') as mock_run:
        mock_run.return_value = mock.Mock(returncode=0)
        scanner = SemgrepScanner(workspace_root=str(tmp_path))
        mock_run.assert_called_once()
        assert "semgrep" in mock_run.call_args[0][0]
        assert "--version" in mock_run.call_args[0][0]


def test_semgrep_raises_when_not_found(tmp_path):
    """Verify error raised when Semgrep not installed."""
    with mock.patch('subprocess.run', side_effect=FileNotFoundError):
        with pytest.raises(SemgrepNotAvailableError, match="not found"):
            SemgrepScanner(workspace_root=str(tmp_path))


def test_semgrep_raises_when_fails(tmp_path):
    """Verify error raised when Semgrep fails to execute."""
    with mock.patch('subprocess.run') as mock_run:
        mock_run.return_value = mock.Mock(returncode=1)
        with pytest.raises(SemgrepNotAvailableError, match="failed"):
            SemgrepScanner(workspace_root=str(tmp_path))


def test_semgrep_raises_on_timeout(tmp_path):
    """Verify error raised when version check times out."""
    with mock.patch('subprocess.run', side_effect=subprocess.TimeoutExpired("semgrep", 5)):
        with pytest.raises(SemgrepNotAvailableError, match="timed out"):
            SemgrepScanner(workspace_root=str(tmp_path))


def test_scan_method_exists(tmp_path):
    """Verify scan method signature."""
    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

        policy = WorkspacePolicy(
            workspace_root=str(tmp_path),
            max_file_size=10_000_000,
            excluded_dirs={"node_modules", ".git"}
        )
        limits = ScanLimits()

        # Should accept all parameters
        result = scanner.scan(
            workspace_policy=policy,
            limits=limits,
            language="python",
            severity=["high", "critical"],
            category="sql-injection",
            path="app/"
        )

        assert isinstance(result, ScanResult)


@pytest.mark.skipif(not shutil.which("semgrep"), reason="Semgrep not installed")
def test_semgrep_finds_sql_injection(tmp_path):
    """Verify Semgrep detects SQL injection patterns (REAL SCAN)."""
    # Copy fixture to tmp workspace
    fixture_src = Path("tests/fixtures/vulnerable_code/python/sql_injection.py")
    fixture_dst = tmp_path / "sql_injection.py"
    shutil.copy(fixture_src, fixture_dst)

    scanner = SemgrepScanner(workspace_root=str(tmp_path))

    policy = WorkspacePolicy(
        workspace_root=str(tmp_path),
        max_file_size=10_000_000,
        excluded_dirs=set()
    )
    limits = ScanLimits()

    result = scanner.scan(
        workspace_policy=policy,
        limits=limits,
        language="python",
        severity=["high", "critical"]
    )

    # Should find at least 3 SQL injection vulnerabilities
    assert result.success is True
    assert len(result.findings) >= 3

    # Check finding properties
    finding = result.findings[0]
    assert finding.tool == ScannerTool.SEMGREP
    assert finding.severity in [Severity.HIGH, Severity.CRITICAL]
    assert "sql" in finding.title.lower() or "injection" in finding.title.lower()
    assert finding.file_path == "sql_injection.py"
    assert finding.line_start > 0
    assert len(finding.snippet) > 0
