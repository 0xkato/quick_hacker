"""Shared tool implementations for both MCP tools and legacy ToolExecutor.

This module provides the core logic for all agent tools, ensuring consistent
behavior between Claude SDK (MCP) and legacy ReAct providers.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from services.security_scanners.base import WorkspacePolicy, ScanLimits


class ToolCore:
    """Shared tool implementations for security research agents.

    This class contains the actual implementations of all tools, which are
    called by both:
    - MCP tool handlers (for Claude SDK provider)
    - ToolExecutor methods (for legacy ReAct providers)

    Attributes:
        repo_path: Resolved path to the repository root
        project_id: Project identifier for persistence
        workspace_policy: Policy enforcing security boundaries
    """

    # Default excluded directories
    DEFAULT_EXCLUDED_DIRS = frozenset({
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", ".nuxt", "coverage", "target",
        ".idea", ".vscode", ".cache", ".nyc_output",
    })

    # Maximum file size for reads (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(
        self,
        repo_path: str,
        project_id: str,
        get_scan_limits: Callable[[], ScanLimits] | None = None,
    ):
        """Initialize ToolCore.

        Args:
            repo_path: Path to the repository root
            project_id: Project identifier for persistence services
            get_scan_limits: Factory function that returns fresh ScanLimits
                            with current remaining budget
        """
        self.repo_path = Path(repo_path).resolve()
        self.project_id = project_id
        self._get_scan_limits = get_scan_limits or (lambda: ScanLimits())

        # Create workspace policy
        self.workspace_policy = WorkspacePolicy(
            workspace_root=str(self.repo_path),
            max_file_size=self.MAX_FILE_SIZE,
            excluded_dirs=set(self.DEFAULT_EXCLUDED_DIRS),
        )

    def _validate_path(self, path: str) -> Path:
        """Validate a file path and return resolved Path.

        Args:
            path: Relative path from repo root

        Returns:
            Resolved absolute Path

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path escapes workspace or is in excluded dir
        """
        # Build candidate path WITHOUT resolving yet
        candidate = self.repo_path / path

        # Check path traversal BEFORE checking existence
        # (WorkspacePolicy checks existence first, which would mask traversal attacks)
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Path escapes workspace: {path}")

        # Use WorkspacePolicy for remaining validation (existence, excluded dirs, size)
        ok, reason = self.workspace_policy.validate_path(candidate)
        if not ok:
            if reason and "not exist" in reason.lower():
                raise FileNotFoundError(f"File not found: {path}")
            if reason and "excluded" in reason.lower():
                raise ValueError(f"Path in excluded directory: {path}")
            raise ValueError(f"Path rejected: {reason}")

        return resolved

    def _validate_dir(self, path: str) -> Path:
        """Validate a directory path and return resolved Path.

        Args:
            path: Relative path from repo root (use "." for root)

        Returns:
            Resolved absolute Path

        Raises:
            NotADirectoryError: If path is not a directory
            ValueError: If path escapes workspace or is symlink
        """
        candidate = self.repo_path / path

        # Check symlink BEFORE resolving
        if candidate.is_symlink():
            raise ValueError(f"Symlink directories not allowed: {path}")

        resolved = candidate.resolve()

        # Must be within workspace
        try:
            resolved.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Path escapes workspace: {path}")

        # Must be a directory
        if not resolved.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        return resolved
