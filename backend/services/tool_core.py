"""Shared tool implementations for both MCP tools and legacy ToolExecutor.

This module provides the core logic for all agent tools, ensuring consistent
behavior between Claude SDK (MCP) and legacy ReAct providers.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Callable

from services.security_scanners import (
    ScanFinding,
    ScanResult,
    scan_for_secrets,
    audit_dependencies,
    semantic_grep,
    generate_report,
)
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

    async def read_file(
        self,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> str:
        """Read file contents with optional line range.

        Args:
            path: Relative path from repo root
            start_line: Starting line (1-indexed, inclusive)
            end_line: Ending line (1-indexed, inclusive)

        Returns:
            File content as string, with line numbers if range specified

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path is invalid
        """
        file_path = self._validate_path(path)

        # Read file in thread to avoid blocking
        content = await asyncio.to_thread(file_path.read_text, errors="ignore")
        lines = content.split("\n")

        # No line range specified - return full content
        if start_line is None and end_line is None:
            return content

        # Apply line slicing with clamping
        total_lines = len(lines)

        # Convert to 0-indexed and clamp
        start_idx = 0
        if start_line is not None:
            start_idx = max(0, min(start_line - 1, total_lines))

        end_idx = total_lines
        if end_line is not None:
            end_idx = max(0, min(end_line, total_lines))

        # Guard against start >= end
        if start_idx >= end_idx:
            return ""

        sliced = lines[start_idx:end_idx]

        # Add line numbers
        numbered = [f"{i + start_idx + 1}: {line}" for i, line in enumerate(sliced)]
        return "\n".join(numbered)

    async def list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        pattern: str | None = None,
        max_items: int = 500,
    ) -> dict[str, Any]:
        """List directory contents.

        Args:
            path: Relative path from repo root (use "." for root)
            recursive: If True, list all files recursively
            pattern: Optional glob pattern to filter files
            max_items: Maximum items to return

        Returns:
            Dict with items list and metadata
        """
        dir_path = self._validate_dir(path)

        # Check if starting path is an excluded directory
        if dir_path != self.repo_path:  # Don't check root
            rel_parts = dir_path.relative_to(self.repo_path).parts
            for part in rel_parts:
                if part in self.DEFAULT_EXCLUDED_DIRS:
                    raise ValueError(f"Path in excluded directory: {path}")

        items: list[str] = []

        def collect_items():
            nonlocal items
            if recursive:
                for root, dirs, files in os.walk(dir_path):
                    # Filter excluded dirs
                    dirs[:] = [d for d in dirs
                              if not d.startswith(".")
                              and d not in self.DEFAULT_EXCLUDED_DIRS]

                    for f in files:
                        if f.startswith("."):
                            continue
                        if pattern and not Path(f).match(pattern):
                            continue
                        rel = (Path(root) / f).relative_to(self.repo_path)
                        items.append(str(rel))
                        if len(items) >= max_items:
                            return
            else:
                for item in sorted(dir_path.iterdir()):
                    if item.name.startswith("."):
                        continue
                    if pattern and not item.match(pattern):
                        continue
                    rel = item.relative_to(self.repo_path)
                    suffix = "/" if item.is_dir() else ""
                    items.append(f"{rel}{suffix}")
                    if len(items) >= max_items:
                        return

        await asyncio.to_thread(collect_items)

        return {
            "path": path,
            "items": items[:max_items],
            "count": len(items),
            "truncated": len(items) >= max_items,
        }

    async def search_code(
        self,
        pattern: str,
        file_pattern: str | None = None,
        max_results: int = 50,
    ) -> dict[str, Any]:
        """Search for regex pattern across codebase.

        Args:
            pattern: Regex pattern to search for
            file_pattern: Optional glob to filter files
            max_results: Maximum matches to return

        Returns:
            Dict with matches list and metadata
        """
        import re

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

        results: list[dict] = []
        files_searched = 0

        def search_files():
            nonlocal results, files_searched

            for root, dirs, files in os.walk(self.repo_path):
                # Skip excluded directories
                dirs[:] = [d for d in dirs
                          if not d.startswith(".")
                          and d not in self.DEFAULT_EXCLUDED_DIRS]

                for filename in files:
                    if filename.startswith("."):
                        continue
                    if file_pattern and not Path(filename).match(file_pattern.replace("**/", "")):
                        continue

                    file_path = Path(root) / filename
                    rel_path = file_path.relative_to(self.repo_path)

                    # Skip binary files
                    if file_path.suffix in {".png", ".jpg", ".gif", ".ico", ".woff",
                                           ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz"}:
                        continue

                    try:
                        content = file_path.read_text(errors="ignore")
                        files_searched += 1

                        for i, line in enumerate(content.split("\n"), 1):
                            if regex.search(line):
                                results.append({
                                    "file": str(rel_path),
                                    "line": i,
                                    "content": line.strip()[:200]
                                })
                                if len(results) >= max_results:
                                    return
                    except Exception:
                        continue

                if len(results) >= max_results:
                    return

        await asyncio.to_thread(search_files)

        return {
            "matches": results,
            "count": len(results),
            "files_searched": files_searched,
            "truncated": len(results) >= max_results,
        }

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
        """
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
        """
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
