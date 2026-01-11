"""Tests for module exports."""
from __future__ import annotations


def test_can_import_all_public_api():
    from services.security_scanners import (
        # Types
        Severity,
        ScannerTool,
        WorkspacePolicy,
        ScanLimits,
        ScanFinding,
        ScanResult,
        # Functions
        scan_for_secrets,
        audit_dependencies,
        semantic_grep,
        generate_report,
        # Utilities
        redact_secret,
        fingerprint_secret,
        normalize_path,
        read_file_safe,
    )

    # Verify they're the correct types
    assert Severity.CRITICAL.value == "critical"
    assert ScannerTool.SECRETS.value == "secrets"
