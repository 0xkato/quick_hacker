"""Semgrep-based vulnerability pattern scanner."""
from __future__ import annotations

import json
import os
import subprocess
import time
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

    def _map_severity(self, semgrep_severity: str) -> Severity:
        """Map Semgrep severity to scanner Severity enum.

        Args:
            semgrep_severity: Semgrep severity (INFO, WARNING, ERROR)

        Returns:
            Mapped Severity enum value
        """
        severity_map = {
            "ERROR": Severity.CRITICAL,
            "WARNING": Severity.HIGH,
            "INFO": Severity.MEDIUM,
        }
        return severity_map.get(semgrep_severity.upper(), Severity.MEDIUM)

    def _extract_category(self, rule_id: str) -> str:
        """Extract vulnerability category from rule ID.

        Args:
            rule_id: Semgrep rule identifier

        Returns:
            Category string (e.g., "sql-injection")
        """
        # Extract from rule ID pattern like "python-sql-injection-fstring"
        parts = rule_id.lower().split("-")

        # Common patterns
        if "sql" in parts:
            return "sql-injection"
        elif "command" in parts:
            return "command-injection"
        elif "xss" in parts:
            return "xss"
        elif "buffer" in parts:
            return "buffer-overflow"
        elif "deserial" in parts:
            return "deserialization"

        # Fallback: use rule ID as category
        return rule_id

    def _parse_semgrep_output(self, output: str) -> list[ScanFinding]:
        """Parse Semgrep JSON output into ScanFinding objects.

        Args:
            output: Semgrep JSON output string

        Returns:
            List of ScanFinding objects
        """
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        findings = []
        for result in data.get("results", []):
            # Extract rich context
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            finding = ScanFinding(
                tool=ScannerTool.SEMGREP,
                severity=self._map_severity(extra.get("severity", "WARNING")),
                title=result.get("check_id", "Unknown"),
                file_path=result.get("path", ""),
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line", 0),
                snippet=extra.get("lines", ""),
                confidence=0.9,  # Semgrep rules are high confidence
                details={
                    "rule_id": result.get("check_id"),
                    "category": self._extract_category(result.get("check_id", "")),
                    "message": extra.get("message", ""),
                    "cwe": metadata.get("cwe"),
                    "owasp": metadata.get("owasp"),
                },
            )
            findings.append(finding)

        return findings

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
        severity = severity or ["high", "critical"]
        scan_path = path or str(self.workspace_root)
        if not os.path.isabs(scan_path):
            scan_path = str(self.workspace_root / scan_path)

        start_time = time.time()

        # Build Semgrep command
        cmd = self._build_command(language, severity, category, scan_path)

        # Execute with timeout and cancellation support
        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            findings = []
            while process.poll() is None:
                # Check cancellation
                if limits.is_cancelled():
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    duration_ms = int((time.time() - start_time) * 1000)
                    return ScanResult(
                        success=False,
                        findings=findings,
                        files_scanned=0,
                        files_skipped=0,
                        bytes_scanned=0,
                        duration_ms=duration_ms,
                        cancelled=True,
                    )

                time.sleep(0.1)

            # Parse results
            stdout, stderr = process.communicate()
            findings = self._parse_semgrep_output(stdout)

            duration_ms = int((time.time() - start_time) * 1000)

            return ScanResult(
                success=True,
                findings=findings,
                files_scanned=len(findings),  # Approximate
                files_skipped=0,
                bytes_scanned=0,
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return ScanResult(
                success=False,
                findings=[],
                files_scanned=0,
                files_skipped=0,
                bytes_scanned=0,
                duration_ms=duration_ms,
                error=str(e),
            )
        finally:
            # Ensure subprocess is cleaned up even on unexpected exceptions
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
