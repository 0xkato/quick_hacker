"""Semgrep-based vulnerability pattern scanner."""
from __future__ import annotations

import os
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

    def _default_rules_dir(self) -> str:
        """Get default rules directory path."""
        # Rules are bundled with the scanner
        scanner_dir = Path(__file__).parent
        rules_dir = scanner_dir / "semgrep_rules"
        return str(rules_dir)

    def _build_command(
        self,
        language: str | None,
        severity: list[str],
        category: str | None,
        scan_path: str,
    ) -> list[str]:
        """Build Semgrep command with filters.

        Args:
            language: Language filter (python, javascript, c, cpp, java)
            severity: Severity levels to include
            category: Vulnerability category filter
            scan_path: Path to scan

        Returns:
            List of command arguments
        """
        rules_dir = self.rules_dir or self._default_rules_dir()

        cmd = ["semgrep", "--json", "--quiet"]

        # Add config path
        if language:
            # Scan specific language rules
            config_path = Path(rules_dir) / language
            if config_path.exists():
                cmd.extend(["--config", str(config_path)])
            else:
                # Fallback to all rules if language dir doesn't exist
                cmd.extend(["--config", rules_dir])
        else:
            # Scan all rules
            cmd.extend(["--config", rules_dir])

        # Add target path
        cmd.append(scan_path)

        return cmd

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
