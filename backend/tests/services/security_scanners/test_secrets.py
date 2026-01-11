"""Tests for secrets scanner module."""
import pytest
import tempfile
import os
import asyncio
from pathlib import Path
from datetime import datetime, timedelta

from services.security_scanners.base import (
    WorkspacePolicy,
    ScanLimits,
    ScannerTool,
    Severity,
    redact_secret,
    fingerprint_secret,
)

# Import will fail initially (TDD - tests first)
try:
    from services.security_scanners.secrets import (
        shannon_entropy,
        SECRET_PATTERNS,
        scan_for_secrets,
        _scan_for_secrets_sync,
    )
except ImportError:
    # Placeholders for TDD - tests should fail initially
    shannon_entropy = None
    SECRET_PATTERNS = None
    scan_for_secrets = None
    _scan_for_secrets_sync = None


class TestShannonEntropy:
    """Tests for shannon_entropy function."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if shannon_entropy is not implemented."""
        if shannon_entropy is None:
            pytest.skip("shannon_entropy not implemented yet")

    def test_entropy_empty_string(self):
        """Empty string should have 0 entropy."""
        assert shannon_entropy("") == 0.0

    def test_entropy_single_character(self):
        """Single character repeated should have 0 entropy."""
        assert shannon_entropy("aaaaaaaaa") == 0.0

    def test_entropy_two_characters_equal(self):
        """Two characters with equal frequency should have entropy of 1.0."""
        # "ab" repeated gives 0.5 probability for each
        result = shannon_entropy("abababab")
        assert abs(result - 1.0) < 0.01  # Allow small floating point error

    def test_entropy_high_randomness(self):
        """High randomness string should have high entropy."""
        # Mix of many different characters
        random_str = "aB3$xZ9@mK"
        result = shannon_entropy(random_str)
        # Should be high (close to log2 of unique chars)
        assert result > 3.0

    def test_entropy_typical_api_key(self):
        """Typical API key should have high entropy."""
        # Simulated AWS-style key
        api_key = "AKIAIOSFODNN7EXAMPLE"
        result = shannon_entropy(api_key)
        assert result > 3.5  # API keys typically have high entropy

    def test_entropy_low_randomness(self):
        """Repeated patterns should have low entropy."""
        repeated = "hellohellohello"
        result = shannon_entropy(repeated)
        # Should be lower than random strings
        assert result < 3.0


class TestSecretPatterns:
    """Tests for SECRET_PATTERNS list."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if SECRET_PATTERNS is not implemented."""
        if SECRET_PATTERNS is None:
            pytest.skip("SECRET_PATTERNS not implemented yet")

    def test_patterns_exist(self):
        """SECRET_PATTERNS should be a non-empty list."""
        assert isinstance(SECRET_PATTERNS, list)
        assert len(SECRET_PATTERNS) > 0

    def test_aws_access_key_pattern_exists(self):
        """AWS access key pattern should exist with critical severity."""
        pattern_names = [p["name"] for p in SECRET_PATTERNS]
        assert "aws_access_key" in pattern_names

        pattern = next(p for p in SECRET_PATTERNS if p["name"] == "aws_access_key")
        assert pattern["severity"] == Severity.CRITICAL

    def test_aws_secret_key_pattern_exists(self):
        """AWS secret key pattern should exist with critical severity."""
        pattern_names = [p["name"] for p in SECRET_PATTERNS]
        assert "aws_secret_key" in pattern_names

        pattern = next(p for p in SECRET_PATTERNS if p["name"] == "aws_secret_key")
        assert pattern["severity"] == Severity.CRITICAL

    def test_github_token_pattern_exists(self):
        """GitHub token pattern should exist with critical severity."""
        pattern_names = [p["name"] for p in SECRET_PATTERNS]
        assert "github_token" in pattern_names

        pattern = next(p for p in SECRET_PATTERNS if p["name"] == "github_token")
        assert pattern["severity"] == Severity.CRITICAL

    def test_generic_api_key_pattern_exists(self):
        """Generic API key pattern should exist with high severity."""
        pattern_names = [p["name"] for p in SECRET_PATTERNS]
        assert "generic_api_key" in pattern_names

        pattern = next(p for p in SECRET_PATTERNS if p["name"] == "generic_api_key")
        assert pattern["severity"] == Severity.HIGH

    def test_generic_secret_pattern_exists(self):
        """Generic secret pattern should exist with high severity."""
        pattern_names = [p["name"] for p in SECRET_PATTERNS]
        assert "generic_secret" in pattern_names

        pattern = next(p for p in SECRET_PATTERNS if p["name"] == "generic_secret")
        assert pattern["severity"] == Severity.HIGH

    def test_private_key_pattern_exists(self):
        """Private key pattern should exist with critical severity."""
        pattern_names = [p["name"] for p in SECRET_PATTERNS]
        assert "private_key" in pattern_names

        pattern = next(p for p in SECRET_PATTERNS if p["name"] == "private_key")
        assert pattern["severity"] == Severity.CRITICAL

    def test_jwt_pattern_exists(self):
        """JWT pattern should exist with high severity."""
        pattern_names = [p["name"] for p in SECRET_PATTERNS]
        assert "jwt" in pattern_names

        pattern = next(p for p in SECRET_PATTERNS if p["name"] == "jwt")
        assert pattern["severity"] == Severity.HIGH

    def test_each_pattern_has_required_fields(self):
        """Each pattern should have name, pattern, severity, and description."""
        for p in SECRET_PATTERNS:
            assert "name" in p, f"Pattern missing 'name': {p}"
            assert "pattern" in p, f"Pattern missing 'pattern': {p}"
            assert "severity" in p, f"Pattern missing 'severity': {p}"
            assert "description" in p, f"Pattern missing 'description': {p}"


class TestPatternDetection:
    """Tests for pattern-based detection."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_detect_aws_access_key(self, temp_workspace):
        """Should detect AWS access key pattern."""
        # Create file with AWS access key
        test_file = Path(temp_workspace) / "config.py"
        test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        assert result.tool == ScannerTool.SECRETS
        assert len(result.findings) >= 1

        # Find the AWS key finding
        aws_findings = [f for f in result.findings if "aws" in f.title.lower() or "AKIA" in f.matched_text]
        assert len(aws_findings) >= 1

    def test_detect_github_token(self, temp_workspace):
        """Should detect GitHub token pattern."""
        test_file = Path(temp_workspace) / "config.py"
        test_file.write_text('GITHUB_TOKEN = "ghp_1234567890abcdefghij1234567890abcdef"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        github_findings = [f for f in result.findings if "github" in f.title.lower() or "ghp_" in f.matched_text]
        assert len(github_findings) >= 1

    def test_detect_generic_api_key(self, temp_workspace):
        """Should detect generic API key pattern."""
        test_file = Path(temp_workspace) / "config.py"
        test_file.write_text('api_key = "sk_live_1234567890abcdefghijklmnop"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        assert len(result.findings) >= 1


class TestSecretRedaction:
    """Tests for secret redaction in snippets."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_secret_is_redacted_in_matched_text(self, temp_workspace):
        """Matched text should have the secret redacted."""
        test_file = Path(temp_workspace) / "config.py"
        secret = "AKIAIOSFODNN7EXAMPLE"
        test_file.write_text(f'AWS_KEY = "{secret}"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        for finding in result.findings:
            # Full secret should not appear in matched_text
            if "AKIA" in finding.matched_text:
                # Should be redacted
                assert "***" in finding.matched_text or secret not in finding.matched_text


class TestFingerprintInDetails:
    """Tests for fingerprint in finding details."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_fingerprint_included_in_metadata(self, temp_workspace):
        """Finding metadata should include fingerprint."""
        test_file = Path(temp_workspace) / "config.py"
        test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        for finding in result.findings:
            assert finding.metadata is not None
            assert "fingerprint" in finding.metadata
            # Fingerprint should be a non-empty string
            assert isinstance(finding.metadata["fingerprint"], str)
            assert len(finding.metadata["fingerprint"]) > 0


class TestCancellationSupport:
    """Tests for scan cancellation support."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace_with_many_files(self):
        """Create a workspace with many files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(20):
                (Path(tmpdir) / f"file_{i}.py").write_text(f'# File {i}\ndata = "value"')
            yield tmpdir

    def test_scan_respects_cancellation(self, temp_workspace_with_many_files):
        """Scan should stop when cancelled."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace_with_many_files,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        # Pre-cancel the scan
        limits = ScanLimits(cancelled=True)

        result = _scan_for_secrets_sync(policy, limits)

        # Should have scanned 0 or very few files due to cancellation
        assert result.files_scanned < 20

    def test_scan_respects_deadline(self, temp_workspace_with_many_files):
        """Scan should stop when deadline is passed."""
        policy = WorkspacePolicy(
            workspace_root=temp_workspace_with_many_files,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        # Deadline already passed
        limits = ScanLimits(deadline=datetime.now() - timedelta(seconds=1))

        result = _scan_for_secrets_sync(policy, limits)

        # Should have scanned 0 or very few files due to deadline
        assert result.files_scanned < 20


class TestEntropyDetection:
    """Tests for entropy-based detection."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_high_entropy_string_detected(self, temp_workspace):
        """High entropy strings should be detected."""
        test_file = Path(temp_workspace) / "config.py"
        # High entropy string that doesn't match specific patterns
        high_entropy = "xK9#mZq!pL2@nW4$vB6^cH8&jF0*tR3"
        test_file.write_text(f'SECRET_VALUE = "{high_entropy}"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits, entropy_threshold=3.5)

        # Should detect the high entropy string
        entropy_findings = [f for f in result.findings if "entropy" in f.title.lower()]
        assert len(entropy_findings) >= 1

    def test_low_entropy_string_not_detected_as_entropy(self, temp_workspace):
        """Low entropy strings should not be flagged by entropy detection."""
        test_file = Path(temp_workspace) / "config.py"
        # Low entropy string
        low_entropy = "hellohellohello"
        test_file.write_text(f'GREETING = "{low_entropy}"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits, entropy_threshold=4.5)

        # Should not detect as high entropy
        entropy_findings = [f for f in result.findings if "entropy" in f.title.lower()]
        assert len(entropy_findings) == 0


class TestBinaryFileSkipping:
    """Tests for binary file skipping."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_binary_files_are_skipped(self, temp_workspace):
        """Binary files should be skipped."""
        # Create a binary file with null bytes
        binary_file = Path(temp_workspace) / "image.png"
        binary_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

        # Create a text file for comparison
        text_file = Path(temp_workspace) / "config.py"
        text_file.write_text('# Normal text file')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        # Should have scanned the text file but skipped the binary
        # files_scanned should be 1 (just the text file)
        assert result.files_scanned >= 1
        # No findings from binary file
        for finding in result.findings:
            assert "image.png" not in finding.file_path


class TestScanMetrics:
    """Tests for scan metrics tracking."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_files_scanned_tracked(self, temp_workspace):
        """files_scanned should be tracked."""
        # Create some files
        for i in range(3):
            (Path(temp_workspace) / f"file_{i}.py").write_text(f"# File {i}")

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        assert result.files_scanned == 3

    def test_duration_ms_tracked(self, temp_workspace):
        """duration_ms should be tracked."""
        (Path(temp_workspace) / "test.py").write_text("# Test")

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        # Duration should be a non-negative integer
        assert isinstance(result.duration_ms, int)
        assert result.duration_ms >= 0


class TestAsyncWrapper:
    """Tests for async wrapper function."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if scan_for_secrets is not implemented."""
        if scan_for_secrets is None:
            pytest.skip("scan_for_secrets not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.mark.asyncio
    async def test_async_wrapper_returns_result(self, temp_workspace):
        """Async wrapper should return a ScanResult."""
        (Path(temp_workspace) / "test.py").write_text('API_KEY = "test123"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = await scan_for_secrets(policy, limits)

        assert result.tool == ScannerTool.SECRETS
        assert isinstance(result.findings, list)
        assert isinstance(result.files_scanned, int)

    @pytest.mark.asyncio
    async def test_async_wrapper_is_awaitable(self, temp_workspace):
        """scan_for_secrets should be awaitable."""
        (Path(temp_workspace) / "test.py").write_text("# Test")

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        # Should not raise
        result = await scan_for_secrets(policy, limits)
        assert result is not None


class TestPrivateKeyDetection:
    """Tests for private key detection."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_detect_rsa_private_key(self, temp_workspace):
        """Should detect RSA private key."""
        test_file = Path(temp_workspace) / "key.pem"
        test_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8gM...
-----END RSA PRIVATE KEY-----""")

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        key_findings = [f for f in result.findings if "private key" in f.title.lower() or "PRIVATE KEY" in f.matched_text]
        assert len(key_findings) >= 1


class TestJWTDetection:
    """Tests for JWT detection."""

    @pytest.fixture(autouse=True)
    def skip_if_not_implemented(self):
        """Skip tests if _scan_for_secrets_sync is not implemented."""
        if _scan_for_secrets_sync is None:
            pytest.skip("_scan_for_secrets_sync not implemented yet")

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_detect_jwt_token(self, temp_workspace):
        """Should detect JWT token."""
        test_file = Path(temp_workspace) / "config.py"
        # Example JWT (base64 encoded header.payload.signature)
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        test_file.write_text(f'TOKEN = "{jwt}"')

        policy = WorkspacePolicy(
            workspace_root=temp_workspace,
            max_file_size=1024 * 1024,
            excluded_dirs=set(),
        )
        limits = ScanLimits(cancelled=False)

        result = _scan_for_secrets_sync(policy, limits)

        jwt_findings = [f for f in result.findings if "jwt" in f.title.lower() or "eyJ" in f.matched_text]
        assert len(jwt_findings) >= 1
