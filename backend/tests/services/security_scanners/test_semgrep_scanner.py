"""Tests for Semgrep integration."""
import pytest
from services.security_scanners.base import ScannerTool
from services.security_scanners.semgrep import SemgrepScanner
from services.security_scanners.base import WorkspacePolicy, ScanLimits
from pathlib import Path


def test_semgrep_tool_enum_exists():
    """Verify SEMGREP exists in ScannerTool enum."""
    assert hasattr(ScannerTool, "SEMGREP")
    assert ScannerTool.SEMGREP == "semgrep"
    assert str(ScannerTool.SEMGREP) == "semgrep"


def test_semgrep_scanner_initializes(tmp_path):
    """Verify SemgrepScanner can be initialized."""
    scanner = SemgrepScanner(workspace_root=str(tmp_path))
    assert scanner.workspace_root == tmp_path
    assert scanner.get_tool_name() == ScannerTool.SEMGREP
