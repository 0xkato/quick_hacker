"""Semgrep-based vulnerability pattern scanner."""
from __future__ import annotations

from pathlib import Path

from services.security_scanners.base import ScannerTool


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
        """
        self.workspace_root = Path(workspace_root).resolve()
        self.rules_dir = rules_dir

    def get_tool_name(self) -> ScannerTool:
        """Return the scanner tool identifier."""
        return ScannerTool.SEMGREP
