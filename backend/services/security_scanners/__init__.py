"""Security scanners module for vulnerability detection.

This module provides scanners for:
- Secrets detection (API keys, passwords, tokens)
- Dependency vulnerability scanning
- Pattern-based grep scanning
- Consolidated reporting
"""
from .base import (
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
from .secrets import (
    shannon_entropy,
    SECRET_PATTERNS,
    scan_for_secrets,
)

__all__ = [
    # Base types
    "Severity",
    "ScannerTool",
    "WorkspacePolicy",
    "ScanLimits",
    "ScanFinding",
    "ScanResult",
    "redact_secret",
    "fingerprint_secret",
    "normalize_path",
    "read_file_safe",
    # Secrets scanner
    "shannon_entropy",
    "SECRET_PATTERNS",
    "scan_for_secrets",
]
