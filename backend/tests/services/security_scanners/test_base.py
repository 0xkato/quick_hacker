"""Tests for security_scanners base types and utilities."""
import pytest
import tempfile
import os
import time
from pathlib import Path
from unittest.mock import patch

from services.security_scanners.base import (
    Severity,
    ScannerTool,
    WorkspacePolicy,
    ScanLimits,
    ScanFinding,
    ScanResult,
    redact_secret,
    fingerprint_secret,
    normalize_path,
    read_file_safe,
)


class TestSeverityEnum:
    """Tests for Severity enumeration."""

    def test_severity_values(self):
        """Verify all severity levels exist with correct string values."""
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_severity_ordering(self):
        """Severity levels should be comparable for sorting."""
        severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH, Severity.INFO]
        # When sorted by value alphabetically, we get a consistent order
        sorted_sevs = sorted(severities, key=lambda s: s.value)
        assert len(sorted_sevs) == 5

    def test_severity_is_string_enum(self):
        """Severity should be usable as a string."""
        assert str(Severity.CRITICAL) == "critical"
        assert f"Level: {Severity.HIGH}" == "Level: high"


class TestScannerToolEnum:
    """Tests for ScannerTool enumeration."""

    def test_scanner_tool_values(self):
        """Verify all scanner tools exist with correct string values."""
        assert ScannerTool.SECRETS == "secrets"
        assert ScannerTool.DEPENDENCIES == "dependencies"
        assert ScannerTool.GREP == "grep"

    def test_scanner_tool_is_string_enum(self):
        """ScannerTool should be usable as a string."""
        assert str(ScannerTool.SECRETS) == "secrets"
        assert f"Tool: {ScannerTool.DEPENDENCIES}" == "Tool: dependencies"


class TestWorkspacePolicy:
    """Tests for WorkspacePolicy class."""

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some test files
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("print('hello')")

            # Create a subdirectory with a file
            subdir = Path(tmpdir) / "src"
            subdir.mkdir()
            (subdir / "main.py").write_text("def main(): pass")

            # Create an excluded directory
            node_modules = Path(tmpdir) / "node_modules"
            node_modules.mkdir()
            (node_modules / "package.json").write_text("{}")

            yield tmpdir

    def test_validate_path_valid_file(self, temp_workspace):
        """validate_path returns (True, None) for valid files within workspace."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs={"node_modules", ".git", "__pycache__"},
        )
        test_file = Path(temp_workspace) / "test.py"
        is_valid, error = policy.validate_path(test_file)
        assert is_valid is True
        assert error is None

    def test_validate_path_rejects_outside_workspace(self, temp_workspace):
        """validate_path returns (False, error) for files outside workspace."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs={"node_modules", ".git"},
        )
        outside_file = Path("/etc/passwd")
        is_valid, error = policy.validate_path(outside_file)
        assert is_valid is False
        assert error is not None

    def test_validate_path_rejects_excluded_dirs(self, temp_workspace):
        """validate_path returns (False, error) for files in excluded directories."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs={"node_modules", ".git"},
        )
        excluded_file = Path(temp_workspace) / "node_modules" / "package.json"
        is_valid, error = policy.validate_path(excluded_file)
        assert is_valid is False
        assert "excluded" in error.lower()

    def test_validate_path_rejects_oversized_files(self, temp_workspace):
        """validate_path returns (False, error) for files exceeding max size."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=10,  # Very small limit
            excluded_dirs=set(),
        )
        test_file = Path(temp_workspace) / "test.py"
        # File content is "print('hello')" which is > 10 bytes
        is_valid, error = policy.validate_path(test_file)
        assert is_valid is False
        assert "size" in error.lower()

    def test_validate_path_rejects_symlinks(self, temp_workspace):
        """validate_path returns (False, error) for symlinks."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        symlink_path = Path(temp_workspace) / "link.py"
        target_path = Path(temp_workspace) / "test.py"
        symlink_path.symlink_to(target_path)
        is_valid, error = policy.validate_path(symlink_path)
        assert is_valid is False
        assert "symlink" in error.lower()

    def test_validate_path_rejects_nonexistent_files(self, temp_workspace):
        """validate_path returns (False, error) for non-existent files."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        nonexistent = Path(temp_workspace) / "does_not_exist.py"
        is_valid, error = policy.validate_path(nonexistent)
        assert is_valid is False
        assert "exist" in error.lower()

    def test_iter_files_yields_valid_files(self, temp_workspace):
        """iter_files yields only valid files."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs={"node_modules", ".git"},
        )
        files = list(policy.iter_files())
        file_names = {f.name for f in files}
        assert "test.py" in file_names
        assert "main.py" in file_names
        assert "package.json" not in file_names  # In excluded node_modules

    def test_iter_files_with_pattern(self, temp_workspace):
        """iter_files respects glob patterns."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs={"node_modules"},
        )
        py_files = list(policy.iter_files(pattern="*.py"))
        assert all(f.suffix == ".py" for f in py_files)


class TestScanLimits:
    """Tests for ScanLimits class."""

    def test_is_cancelled_false_initially(self):
        """is_cancelled returns False when not cancelled."""
        limits = ScanLimits(
            deadline=time.monotonic() + 300,  # 5 minutes from now
            cancelled=None,
        )
        assert limits.is_cancelled() is False

    def test_is_cancelled_true_when_callable_returns_true(self):
        """is_cancelled returns True when cancelled callable returns True."""
        limits = ScanLimits(
            deadline=time.monotonic() + 300,
            cancelled=lambda: True,
        )
        assert limits.is_cancelled() is True

    def test_is_cancelled_false_when_callable_returns_false(self):
        """is_cancelled returns False when cancelled callable returns False."""
        limits = ScanLimits(
            deadline=time.monotonic() + 300,
            cancelled=lambda: False,
        )
        assert limits.is_cancelled() is False

    def test_is_cancelled_true_when_deadline_passed(self):
        """is_cancelled returns True when deadline has passed."""
        limits = ScanLimits(
            deadline=time.monotonic() - 1,  # 1 second in the past
            cancelled=None,
        )
        assert limits.is_cancelled() is True

    def test_scan_limits_with_no_deadline(self):
        """ScanLimits works with None deadline."""
        limits = ScanLimits(deadline=None, cancelled=None)
        assert limits.is_cancelled() is False

    def test_scan_limits_default_values(self):
        """ScanLimits has correct default values."""
        limits = ScanLimits()
        assert limits.cancelled is None
        assert limits.deadline is None
        assert limits.max_files == 10000
        assert limits.max_matches_total == 1000
        assert limits.max_matches_per_file == 100
        assert limits.regex_timeout_ms == 5000


class TestScanFinding:
    """Tests for ScanFinding dataclass."""

    def test_scan_finding_creation(self):
        """ScanFinding can be created with required fields."""
        finding = ScanFinding(
            tool=ScannerTool.SECRETS,
            severity=Severity.HIGH,
            title="Hardcoded API Key",
            file_path="/app/config.py",
            line_start=42,
            line_end=None,
            snippet="sk-live-xxxxx",
            confidence=0.9,
        )
        assert finding.tool == ScannerTool.SECRETS
        assert finding.severity == Severity.HIGH
        assert finding.line_start == 42
        assert finding.line_end is None
        assert finding.confidence == 0.9

    def test_scan_finding_to_dict(self):
        """ScanFinding.to_dict returns proper dictionary."""
        finding = ScanFinding(
            tool=ScannerTool.GREP,
            severity=Severity.MEDIUM,
            title="SQL Query Pattern",
            file_path="/app/db.py",
            line_start=10,
            line_end=12,
            snippet="SELECT * FROM users",
            confidence=1.0,
        )
        result = finding.to_dict()
        assert isinstance(result, dict)
        assert result["tool"] == "grep"
        assert result["severity"] == "medium"
        assert result["title"] == "SQL Query Pattern"
        assert result["file_path"] == "/app/db.py"
        assert result["line_start"] == 10
        assert result["line_end"] == 12
        assert result["snippet"] == "SELECT * FROM users"
        assert result["confidence"] == 1.0

    def test_scan_finding_with_details(self):
        """ScanFinding handles details field."""
        finding = ScanFinding(
            tool=ScannerTool.DEPENDENCIES,
            severity=Severity.CRITICAL,
            title="Vulnerable Dependency",
            file_path="/app/requirements.txt",
            line_start=5,
            line_end=None,
            snippet="requests==2.25.0",
            confidence=1.0,
            details={"cve_id": "CVE-2024-1234", "fixed_version": "2.31.0"},
        )
        result = finding.to_dict()
        assert result["details"]["cve_id"] == "CVE-2024-1234"

    def test_scan_finding_default_details(self):
        """ScanFinding has empty dict as default for details."""
        finding = ScanFinding(
            tool=ScannerTool.SECRETS,
            severity=Severity.HIGH,
            title="Test",
            file_path="/test.py",
            line_start=1,
            line_end=None,
            snippet="test",
            confidence=0.8,
        )
        assert finding.details == {}


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_creation(self):
        """ScanResult can be created with findings."""
        finding = ScanFinding(
            tool=ScannerTool.SECRETS,
            severity=Severity.HIGH,
            title="Test Finding",
            file_path="/test.py",
            line_start=1,
            line_end=None,
            snippet="secret",
            confidence=0.9,
        )
        result = ScanResult(
            success=True,
            findings=[finding],
            files_scanned=10,
            files_skipped=2,
            bytes_scanned=1024,
            duration_ms=150,
        )
        assert result.success is True
        assert len(result.findings) == 1
        assert result.files_scanned == 10
        assert result.files_skipped == 2
        assert result.bytes_scanned == 1024
        assert result.cancelled is False  # Default value

    def test_scan_result_to_dict(self):
        """ScanResult.to_dict returns proper dictionary."""
        result = ScanResult(
            success=True,
            findings=[],
            files_scanned=5,
            files_skipped=1,
            bytes_scanned=2048,
            duration_ms=100,
            error=None,
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["success"] is True
        assert d["findings"] == []
        assert d["files_scanned"] == 5
        assert d["files_skipped"] == 1
        assert d["bytes_scanned"] == 2048
        assert d["duration_ms"] == 100
        assert d["cancelled"] is False

    def test_scan_result_with_error(self):
        """ScanResult can capture errors."""
        result = ScanResult(
            success=False,
            findings=[],
            files_scanned=0,
            files_skipped=0,
            bytes_scanned=0,
            duration_ms=50,
            error="Timeout exceeded",
        )
        d = result.to_dict()
        assert d["success"] is False
        assert d["error"] == "Timeout exceeded"

    def test_scan_result_with_cancellation(self):
        """ScanResult can capture cancellation state."""
        result = ScanResult(
            success=True,
            findings=[],
            files_scanned=5,
            files_skipped=0,
            bytes_scanned=512,
            duration_ms=25,
            cancelled=True,
        )
        assert result.cancelled is True
        d = result.to_dict()
        assert d["cancelled"] is True

    def test_scan_result_all_fields_in_to_dict(self):
        """ScanResult.to_dict includes all required fields."""
        finding = ScanFinding(
            tool=ScannerTool.SECRETS,
            severity=Severity.MEDIUM,
            title="Test",
            file_path="/test.py",
            line_start=1,
            line_end=None,
            snippet="test",
            confidence=0.8,
        )
        result = ScanResult(
            success=True,
            findings=[finding],
            files_scanned=10,
            files_skipped=3,
            bytes_scanned=4096,
            duration_ms=200,
            cancelled=False,
            error=None,
        )
        d = result.to_dict()
        # Verify all expected fields are present
        expected_fields = {"success", "findings", "files_scanned", "files_skipped",
                          "bytes_scanned", "duration_ms", "cancelled", "error"}
        assert set(d.keys()) == expected_fields


class TestRedactSecret:
    """Tests for redact_secret utility function."""

    def test_redact_secret_short_string(self):
        """Short secrets are fully redacted."""
        assert redact_secret("abc") == "***"

    def test_redact_secret_medium_string(self):
        """Medium secrets show prefix and suffix."""
        result = redact_secret("sk-live-1234567890")
        assert result.startswith("sk")
        assert result.endswith("90")
        assert "***" in result

    def test_redact_secret_preserves_length_hint(self):
        """Redacted secret indicates original length."""
        original = "super-secret-api-key-1234567890"
        result = redact_secret(original)
        # Should contain asterisks indicating redaction
        assert "***" in result

    def test_redact_empty_string(self):
        """Empty string returns empty string."""
        assert redact_secret("") == ""


class TestFingerprintSecret:
    """Tests for fingerprint_secret utility function."""

    def test_fingerprint_secret_consistent(self):
        """Same secret always produces same fingerprint."""
        secret = "my-api-key-12345"
        fp1 = fingerprint_secret(secret)
        fp2 = fingerprint_secret(secret)
        assert fp1 == fp2

    def test_fingerprint_secret_different_for_different_secrets(self):
        """Different secrets produce different fingerprints."""
        fp1 = fingerprint_secret("secret-a")
        fp2 = fingerprint_secret("secret-b")
        assert fp1 != fp2

    def test_fingerprint_secret_is_short_hash(self):
        """Fingerprint should be a short hash (not full SHA)."""
        fp = fingerprint_secret("some-secret")
        assert len(fp) <= 16  # Should be truncated
        assert len(fp) >= 8   # But not too short


class TestNormalizePath:
    """Tests for normalize_path utility function."""

    def test_normalize_path_resolves_relative(self):
        """normalize_path resolves relative paths."""
        result = normalize_path("./foo/../bar/baz.py", "/workspace")
        assert "/workspace" in str(result)
        assert "bar/baz.py" in str(result)
        assert ".." not in str(result)

    def test_normalize_path_handles_absolute(self):
        """normalize_path handles absolute paths."""
        result = normalize_path("/absolute/path/file.py", "/workspace")
        assert str(result) == "/absolute/path/file.py"

    def test_normalize_path_returns_path_object(self):
        """normalize_path returns a Path object."""
        result = normalize_path("file.py", "/workspace")
        assert isinstance(result, Path)


class TestReadFileSafe:
    """Tests for read_file_safe utility function."""

    def test_read_file_safe_reads_content(self):
        """read_file_safe reads file content and returns (content, None)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello, World!")
            f.flush()
            try:
                content, error = read_file_safe(Path(f.name))
                assert content == "Hello, World!"
                assert error is None
            finally:
                os.unlink(f.name)

    def test_read_file_safe_returns_error_for_missing(self):
        """read_file_safe returns (None, error) for missing files."""
        content, error = read_file_safe(Path("/nonexistent/file.txt"))
        assert content is None
        assert error is not None
        assert "exist" in error.lower()

    def test_read_file_safe_returns_error_for_binary(self):
        """read_file_safe returns (None, error) for binary files."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"\x00\x01\x02\xff\xfe\xfd")
            f.flush()
            try:
                content, error = read_file_safe(Path(f.name))
                assert content is None
                assert error is not None
                assert "binary" in error.lower()
            finally:
                os.unlink(f.name)

    def test_read_file_safe_respects_max_size(self):
        """read_file_safe returns (None, error) for files exceeding max_size."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("x" * 1000)
            f.flush()
            try:
                content, error = read_file_safe(Path(f.name), max_size=100)
                assert content is None
                assert error is not None
                assert "size" in error.lower()
            finally:
                os.unlink(f.name)
