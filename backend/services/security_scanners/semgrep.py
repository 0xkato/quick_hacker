"""Semgrep-based vulnerability pattern scanner."""
from __future__ import annotations

import subprocess
from pathlib import Path

from services.security_scanners.base import (
    ScannerTool,
    WorkspacePolicy,
    ScanLimits,
    ScanResult,
    ScanFinding,
    Severity,
)


class SemgrepNotAvailableError(Exception):
    """Raised when Semgrep is not available."""
    pass


class SemgrepScanner:
    """Semgrep-based vulnerability pattern scanner.

    Executes Semgrep with curated rule sets and returns structured findings
    with rich context for LLM analysis.
    """

    def __init__(self, workspace_root: str, rules_dir: str | None = None):
        """Initialize Semgrep scanner.

        Args:
            workspace_root: Root directory of the workspace to scan
            rules_dir: Optional custom rules directory (default: bundled rules)

        Raises:
            SemgrepNotAvailableError: If Semgrep is not installed or not working
        """
        self.workspace_root = Path(workspace_root).resolve()
        self.rules_dir = rules_dir
        self._check_semgrep_available()

    def _check_semgrep_available(self) -> None:
        """Verify Semgrep is installed and accessible.

        Raises:
            SemgrepNotAvailableError: If Semgrep is not available
        """
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode != 0:
                raise SemgrepNotAvailableError("Semgrep failed to execute")
        except FileNotFoundError:
            raise SemgrepNotAvailableError("Semgrep not found in PATH")
        except subprocess.TimeoutExpired:
            raise SemgrepNotAvailableError("Semgrep version check timed out")

    def get_tool_name(self) -> ScannerTool:
        """Return the scanner tool identifier."""
        return ScannerTool.SEMGREP

    def scan(
        self,
        workspace_policy: WorkspacePolicy,
        limits: ScanLimits,
        language: str | None = None,
        severity: list[str] | None = None,
        category: str | None = None,
        path: str | None = None,
    ) -> ScanResult:
        """Run Semgrep scan with filters.

        Args:
            workspace_policy: Security boundaries (inherits excluded_dirs)
            limits: Timeout and cancellation support
            language: Filter by language (python, javascript, c, cpp, java)
            severity: Filter by severity (default: ["high", "critical"])
            category: Filter by category (sql-injection, command-injection, etc.)
            path: Specific file/directory to scan (relative to workspace_root)

        Returns:
            ScanResult with findings containing rich context
        """
        # Minimal stub - return empty successful result
        return ScanResult(
            success=True,
            findings=[],
            files_scanned=0,
            files_skipped=0,
            bytes_scanned=0,
            duration_ms=0,
        )
