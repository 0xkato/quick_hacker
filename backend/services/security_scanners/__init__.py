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
from .dependencies import (
    audit_dependencies,
    _parse_npm_lockfile,
    _parse_yarn_lockfile,
    _parse_pnpm_lockfile,
    _parse_requirements_txt,
    _parse_pipfile_lock,
    _check_version_in_range,
    _audit_dependencies_sync,
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
    # Dependency scanner
    "audit_dependencies",
    "_parse_npm_lockfile",
    "_parse_yarn_lockfile",
    "_parse_pnpm_lockfile",
    "_parse_requirements_txt",
    "_parse_pipfile_lock",
    "_check_version_in_range",
    "_audit_dependencies_sync",
]
