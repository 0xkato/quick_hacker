"""Base types and utilities for security scanners.

This module provides the foundational types used by all security scanners:
- Severity and ScannerTool enums for classification
- WorkspacePolicy for enforcing security boundaries during scans
- ScanLimits for resource control (time budgets, cancellation)
- ScanFinding and ScanResult dataclasses for results
- Utility functions for secret handling and safe file operations
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator


class Severity(str, Enum):
    """Severity levels for security findings.

    Inherits from str to allow direct string comparison and serialization.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


class ScannerTool(str, Enum):
    """Available scanner tools.

    Inherits from str to allow direct string comparison and serialization.
    """
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    GREP = "grep"

    def __str__(self) -> str:
        return self.value


@dataclass
class WorkspacePolicy:
    """Policy for validating and iterating workspace files.

    Enforces security boundaries during scanning:
    - Files must be within the workspace root
    - Files in excluded directories are rejected
    - Oversized files are rejected
    - Symlinks are rejected (to prevent escape attacks)

    Attributes:
        workspace_root: Root directory of the workspace
        max_file_size: Maximum allowed file size in bytes
        excluded_dirs: Set of directory names to exclude (e.g., node_modules, .git)
    """
    workspace_root: str
    max_file_size: int
    excluded_dirs: set[str] = field(default_factory=set)

    def __post_init__(self):
        """Convert workspace_root to resolved Path."""
        self._root_path = Path(self.workspace_root).resolve()

    def validate_path(self, path: Path) -> tuple[bool, str | None]:
        """Check if a file path is valid for scanning.

        Args:
            path: Path to validate

        Returns:
            Tuple of (is_valid, error_message). If valid, error_message is None.
        """
        try:
            resolved = Path(path).resolve()

            # Must exist and be a file
            if not resolved.exists():
                return False, "File does not exist"
            if not resolved.is_file():
                return False, "Path is not a file"

            # Reject symlinks
            if Path(path).is_symlink():
                return False, "Symlinks are not allowed"

            # Must be within workspace
            try:
                resolved.relative_to(self._root_path)
            except ValueError:
                return False, "File is outside workspace"

            # Check excluded directories
            for part in resolved.relative_to(self._root_path).parts:
                if part in self.excluded_dirs:
                    return False, f"File is in excluded directory: {part}"

            # Check file size
            file_size = resolved.stat().st_size
            if file_size > self.max_file_size:
                return False, f"File size {file_size} exceeds max {self.max_file_size}"

            return True, None

        except (OSError, PermissionError) as e:
            return False, f"Cannot access file: {e}"

    def iter_files(self, pattern: str = "*") -> Iterator[Path]:
        """Iterate over valid files in the workspace.

        Args:
            pattern: Glob pattern to filter files (default: all files)

        Yields:
            Path objects for each valid file
        """
        for path in self._root_path.rglob(pattern):
            is_valid, _ = self.validate_path(path)
            if path.is_file() and is_valid:
                yield path


@dataclass
class ScanLimits:
    """Resource limits for a scan operation.

    Provides time-budgeted scanning with cancellation support.

    Attributes:
        cancelled: Callable that returns True if scan should be cancelled, or None
        deadline: Optional monotonic time when the scan should stop (time.monotonic())
        max_files: Maximum number of files to scan
        max_matches_total: Maximum total matches to return
        max_matches_per_file: Maximum matches per file
        regex_timeout_ms: Timeout in milliseconds for regex operations
    """
    cancelled: Callable[[], bool] | None = None
    deadline: float | None = None
    max_files: int = 10000
    max_matches_total: int = 1000
    max_matches_per_file: int = 100
    regex_timeout_ms: int = 5000

    def is_cancelled(self) -> bool:
        """Check if the scan should stop.

        Returns:
            True if cancelled or deadline exceeded, False otherwise
        """
        if self.cancelled is not None and self.cancelled():
            return True
        if self.deadline is not None and time.monotonic() > self.deadline:
            return True
        return False


@dataclass
class ScanFinding:
    """A single finding from a security scan.

    Attributes:
        tool: The scanner tool that produced this finding
        severity: Severity level of the finding
        title: Short title describing the finding
        file_path: Path to the file containing the finding
        line_start: Line number where the finding starts
        line_end: Line number where the finding ends (None if single line)
        snippet: Code snippet containing the finding
        confidence: Confidence score (0.0 to 1.0)
        details: Additional details (e.g., CVE IDs, fix versions)
    """
    tool: ScannerTool
    severity: Severity
    title: str
    file_path: str
    line_start: int
    line_end: int | None
    snippet: str
    confidence: float
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the finding
        """
        return {
            "tool": str(self.tool),
            "severity": str(self.severity),
            "title": self.title,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "snippet": self.snippet,
            "confidence": self.confidence,
            "details": self.details,
        }


@dataclass
class ScanResult:
    """Result of a scan operation.

    Attributes:
        success: Whether the scan completed successfully
        findings: List of findings from the scan
        files_scanned: Number of files processed
        files_skipped: Number of files skipped (binary, unreadable, etc.)
        bytes_scanned: Total bytes scanned
        duration_ms: Time taken in milliseconds
        cancelled: Whether the scan was cancelled before completion
        error: Optional error message if scan failed
    """
    success: bool
    findings: list[ScanFinding]
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    duration_ms: int
    cancelled: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert result to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the result
        """
        return {
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "duration_ms": self.duration_ms,
            "cancelled": self.cancelled,
            "error": self.error,
        }


def redact_secret(secret: str, prefix_len: int = 2, suffix_len: int = 2) -> str:
    """Redact a secret string for safe logging.

    Shows only the first few and last few characters, with asterisks in between.

    Args:
        secret: The secret string to redact
        prefix_len: Number of characters to show at the start
        suffix_len: Number of characters to show at the end

    Returns:
        Redacted string, or "***" for short strings
    """
    if not secret:
        return ""

    min_visible = prefix_len + suffix_len
    if len(secret) <= min_visible + 4:  # Too short to show anything meaningful
        return "***"

    return f"{secret[:prefix_len]}***{secret[-suffix_len:]}"


def fingerprint_secret(secret: str) -> str:
    """Generate a short fingerprint for a secret.

    Used to identify duplicate secrets without storing the full value.

    Args:
        secret: The secret to fingerprint

    Returns:
        Short hash string (first 12 characters of SHA-256)
    """
    hash_obj = hashlib.sha256(secret.encode("utf-8"))
    return hash_obj.hexdigest()[:12]


def normalize_path(path: str, workspace_root: str) -> Path:
    """Normalize a file path relative to a workspace.

    Resolves relative paths and removes .. components.

    Args:
        path: Path to normalize (can be relative or absolute)
        workspace_root: Root directory for resolving relative paths

    Returns:
        Normalized Path object
    """
    p = Path(path)
    if p.is_absolute():
        return p.resolve()
    return (Path(workspace_root) / p).resolve()


def read_file_safe(
    path: Path,
    max_size: int = 10 * 1024 * 1024,  # 10MB default
    encoding: str = "utf-8",
) -> tuple[str | None, str | None]:
    """Safely read a text file.

    Returns (None, error) for:
    - Missing files
    - Binary files (containing null bytes)
    - Files exceeding max_size
    - Permission errors

    Args:
        path: Path to the file
        max_size: Maximum file size in bytes
        encoding: Text encoding to use

    Returns:
        Tuple of (content, error). If successful, error is None.
        If failed, content is None and error contains the reason.
    """
    try:
        if not path.exists():
            return None, "File does not exist"

        # Check size before reading
        file_size = path.stat().st_size
        if file_size > max_size:
            return None, f"File size {file_size} exceeds max {max_size}"

        # Read as bytes first to detect binary content
        raw_bytes = path.read_bytes()

        # Check for null bytes (binary file indicator)
        if b"\x00" in raw_bytes:
            return None, "Binary file detected"

        # Decode to string
        return raw_bytes.decode(encoding), None

    except PermissionError:
        return None, "Permission denied"
    except OSError as e:
        return None, f"OS error: {e}"
    except UnicodeDecodeError as e:
        return None, f"Encoding error: {e}"
