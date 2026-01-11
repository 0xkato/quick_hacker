"""Security scanners module - provides security analysis tools for the agent loop."""
from __future__ import annotations

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
from .secrets import scan_for_secrets
from .dependencies import audit_dependencies
from .grep import semantic_grep
from .report import generate_report

__all__ = [
    # Types
    "Severity",
    "ScannerTool",
    "WorkspacePolicy",
    "ScanLimits",
    "ScanFinding",
    "ScanResult",
    # Scanner functions
    "scan_for_secrets",
    "audit_dependencies",
    "semantic_grep",
    "generate_report",
    # Utilities
    "redact_secret",
    "fingerprint_secret",
    "normalize_path",
    "read_file_safe",
]
