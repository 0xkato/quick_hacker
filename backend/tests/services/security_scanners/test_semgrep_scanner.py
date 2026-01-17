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


def test_build_command_basic(tmp_path):
    """Verify basic Semgrep command structure."""
    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

        cmd = scanner._build_command(
            language=None,
            severity=["high", "critical"],
            category=None,
            scan_path=str(tmp_path)
        )

        assert cmd[0] == "semgrep"
        assert "--json" in cmd
        assert "--config" in cmd
        assert str(tmp_path) in cmd


def test_build_command_with_language_filter(tmp_path):
    """Verify language filtering in command."""
    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

        cmd = scanner._build_command(
            language="python",
            severity=["high"],
            category=None,
            scan_path=str(tmp_path)
        )

        # Should only scan Python rules
        assert "--config" in cmd
        config_idx = cmd.index("--config")
        config_path = cmd[config_idx + 1]
        assert "python" in config_path.lower()


def test_parse_semgrep_output():
    """Verify Semgrep JSON output parsing."""
    # Sample Semgrep JSON output
    semgrep_json = """{
      "results": [
        {
          "check_id": "python-sql-injection-fstring",
          "path": "app/db.py",
          "start": {"line": 10, "col": 5},
          "end": {"line": 10, "col": 60},
          "extra": {
            "message": "SQL injection via f-string",
            "severity": "WARNING",
            "metadata": {
              "cwe": "CWE-89",
              "owasp": "A03:2021",
              "confidence": "HIGH"
            },
            "lines": "    cursor.execute(f\\"SELECT * FROM users WHERE id={user_id}\\")"
          }
        }
      ],
      "errors": []
    }"""

    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root="/tmp")
        findings = scanner._parse_semgrep_output(semgrep_json)

        assert len(findings) == 1
        finding = findings[0]

        assert finding.tool == ScannerTool.SEMGREP
        assert finding.file_path == "app/db.py"
        assert finding.line_start == 10
        assert finding.line_end == 10
        assert finding.severity == Severity.HIGH
        assert "sql" in finding.title.lower()
        assert "cwe" in finding.details
        assert finding.details["cwe"] == "CWE-89"


def test_scan_execution_with_mock(tmp_path):
    """Verify scan executes Semgrep and parses results."""
    # Mock Semgrep execution
    mock_output = """{
      "results": [
        {
          "check_id": "test-rule",
          "path": "test.py",
          "start": {"line": 1, "col": 1},
          "end": {"line": 1, "col": 10},
          "extra": {
            "message": "Test finding",
            "severity": "WARNING",
            "metadata": {},
            "lines": "test code"
          }
        }
      ]
    }"""

    with mock.patch('subprocess.run', return_value=mock.Mock(returncode=0)):
        scanner = SemgrepScanner(workspace_root=str(tmp_path))

    with mock.patch('subprocess.Popen') as mock_popen:
        mock_process = mock.Mock()
        mock_process.poll.side_effect = [None, None, 0]  # Running, then done
        mock_process.communicate.return_value = (mock_output, "")
        mock_popen.return_value = mock_process

        policy = WorkspacePolicy(
            workspace_root=str(tmp_path),
            max_file_size=10_000_000,
            excluded_dirs=set()
        )
        limits = ScanLimits()

        result = scanner.scan(
            workspace_policy=policy,
            limits=limits,
        )

        assert result.success is True
        assert len(result.findings) == 1
        assert result.findings[0].file_path == "test.py"
