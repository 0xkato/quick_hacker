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
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional


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

    def validate_path(self, path: Path) -> bool:
        """Check if a file path is valid for scanning.

        Args:
            path: Path to validate

        Returns:
            True if the path is valid for scanning, False otherwise
        """
        try:
            resolved = Path(path).resolve()

            # Must exist and be a file
            if not resolved.exists() or not resolved.is_file():
                return False

            # Reject symlinks
            if Path(path).is_symlink():
                return False

            # Must be within workspace
            try:
                resolved.relative_to(self._root_path)
            except ValueError:
                return False

            # Check excluded directories
            for part in resolved.relative_to(self._root_path).parts:
                if part in self.excluded_dirs:
                    return False

            # Check file size
            if resolved.stat().st_size > self.max_file_size:
                return False

            return True

        except (OSError, PermissionError):
            return False

    def iter_files(self, pattern: str = "*") -> Iterator[Path]:
        """Iterate over valid files in the workspace.

        Args:
            pattern: Glob pattern to filter files (default: all files)

        Yields:
            Path objects for each valid file
        """
        for path in self._root_path.rglob(pattern):
            if path.is_file() and self.validate_path(path):
                yield path


@dataclass
class ScanLimits:
    """Resource limits for a scan operation.

    Provides time-budgeted scanning with cancellation support.

    Attributes:
        deadline: Optional datetime when the scan should stop
        cancelled: Flag to indicate manual cancellation
    """
    deadline: Optional[datetime] = None
    cancelled: bool = False

    def is_cancelled(self) -> bool:
        """Check if the scan should stop.

        Returns:
            True if cancelled or deadline exceeded, False otherwise
        """
        if self.cancelled:
            return True
        if self.deadline is not None and datetime.now() > self.deadline:
            return True
        return False


@dataclass
class ScanFinding:
    """A single finding from a security scan.

    Attributes:
        tool: The scanner tool that produced this finding
        severity: Severity level of the finding
        title: Short title describing the finding
        description: Detailed description
        file_path: Path to the file containing the finding
        line_number: Line number where the finding was detected
        matched_text: The actual text that triggered the finding
        metadata: Optional additional metadata (e.g., CVE IDs, fix versions)
    """
    tool: ScannerTool
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    matched_text: str
    metadata: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the finding
        """
        result = {
            "tool": str(self.tool),
            "severity": str(self.severity),
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_text": self.matched_text,
        }
        if self.metadata is not None:
            result["metadata"] = self.metadata
        return result


@dataclass
class ScanResult:
    """Result of a scan operation.

    Attributes:
        tool: The scanner tool that produced this result
        findings: List of findings from the scan
        files_scanned: Number of files processed
        duration_ms: Time taken in milliseconds
        error: Optional error message if scan failed
    """
    tool: ScannerTool
    findings: list[ScanFinding]
    files_scanned: int
    duration_ms: int
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert result to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the result
        """
        return {
            "tool": str(self.tool),
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "duration_ms": self.duration_ms,
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
) -> Optional[str]:
    """Safely read a text file.

    Returns None for:
    - Missing files
    - Binary files (containing null bytes)
    - Files exceeding max_size
    - Permission errors

    Args:
        path: Path to the file
        max_size: Maximum file size in bytes
        encoding: Text encoding to use

    Returns:
        File contents as string, or None if file cannot be read safely
    """
    try:
        if not path.exists():
            return None

        # Check size before reading
        if path.stat().st_size > max_size:
            return None

        # Read as bytes first to detect binary content
        raw_bytes = path.read_bytes()

        # Check for null bytes (binary file indicator)
        if b"\x00" in raw_bytes:
            return None

        # Decode to string
        return raw_bytes.decode(encoding)

    except (OSError, PermissionError, UnicodeDecodeError):
        return None
