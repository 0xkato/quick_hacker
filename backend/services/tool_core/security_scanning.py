"""Security scanning operations for ToolCore."""
from __future__ import annotations

import re
from typing import Any

from services.security_scanners import (
    ScanFinding,
    ScanResult,
    scan_for_secrets,
    audit_dependencies,
    semantic_grep,
    generate_report,
)


class SecurityScanningMixin:
    """Mixin for security scanning operations.

    This mixin provides methods for scanning code for secrets, auditing
    dependencies, semantic grep, and generating security reports.
    It requires the following attributes to be set:
    - workspace_policy: WorkspacePolicy instance
    - _get_scan_limits: Callable that returns ScanLimits
    - _validate_path: Method to validate file paths
    """

    async def scan_for_secrets(
        self,
        entropy_threshold: float = 4.5,
    ) -> dict[str, Any]:
        """Scan repository for hardcoded secrets.

        Args:
            entropy_threshold: Minimum Shannon entropy for detection

        Returns:
            Scan result dict with findings
        """
        limits = self._get_scan_limits()

        result = await scan_for_secrets(
            policy=self.workspace_policy,
            limits=limits,
            entropy_threshold=entropy_threshold,
        )

        return self._format_scan_result(result)

    async def dependency_audit(
        self,
        lockfile_path: str | None = None,
    ) -> dict[str, Any]:
        """Audit dependencies for known vulnerabilities.

        Args:
            lockfile_path: Optional specific lockfile to audit

        Returns:
            Audit result dict with findings
        """
        limits = self._get_scan_limits()

        # Convert relative path to absolute if provided
        abs_path = None
        if lockfile_path:
            abs_path = str(self._validate_path(lockfile_path))

        result = await audit_dependencies(
            policy=self.workspace_policy,
            limits=limits,
            lockfile_path=abs_path,
        )

        return self._format_scan_result(result)

    async def grep_semantic(
        self,
        pattern: str,
        context_lines: int = 3,
        file_glob: str = "**/*",
    ) -> dict[str, Any]:
        """Search code with regex pattern and context.

        Args:
            pattern: Regex pattern to search
            context_lines: Lines of context around matches
            file_glob: Glob pattern to filter files

        Returns:
            Search result dict with findings

        Raises:
            ValueError: If pattern is not a valid regex
        """
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

        limits = self._get_scan_limits()

        result = await semantic_grep(
            policy=self.workspace_policy,
            pattern=pattern,
            limits=limits,
            context_lines=context_lines,
            file_glob=file_glob,
        )

        return self._format_scan_result(result)

    async def generate_security_report(
        self,
        findings: list[ScanFinding],
        output_format: str = "markdown",
    ) -> str:
        """Generate security report from findings.

        Args:
            findings: List of ScanFinding objects
            output_format: Output format (markdown, json, sarif)

        Returns:
            Report string in requested format

        Raises:
            ValueError: If output_format is not valid
        """
        valid_formats = {"markdown", "json", "sarif"}
        if output_format.lower() not in valid_formats:
            raise ValueError(f"Invalid format '{output_format}'. Must be one of: {valid_formats}")
        return generate_report(findings, output_format)

    def _format_scan_result(self, result: ScanResult) -> dict[str, Any]:
        """Format ScanResult to dict."""
        return {
            "success": result.success,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "bytes_scanned": result.bytes_scanned,
            "duration_ms": result.duration_ms,
            "cancelled": result.cancelled,
            "error": result.error,
            "findings": [f.to_dict() for f in result.findings],
        }
