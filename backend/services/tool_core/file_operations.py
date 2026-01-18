"""File and directory operations for ToolCore."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from services.security_scanners import semantic_grep
from services.security_scanners.base import WorkspacePolicy, ScanLimits
from services.redaction_service import redaction_service
from services.artifact_service import artifact_service
from models.investigation_trace import Artifact, ArtifactType, generate_artifact_id


class FileOperationsMixin:
    """Mixin for file and directory operations.

    This mixin provides methods for reading files, listing directories,
    and searching code. It requires the following attributes to be set:
    - repo_path: Path to repository root
    - workspace_policy: WorkspacePolicy instance
    - DEFAULT_EXCLUDED_DIRS: Set of excluded directory names
    - _get_scan_limits: Callable that returns ScanLimits
    - cache: Optional ToolCache instance
    - git_head_tracker: Optional GitHeadTracker instance
    """

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

        # Fast lexical traversal check that doesn't follow symlinks.
        # This ensures we reject escapes even when the target path does not exist.
        normalized = Path(os.path.normpath(str(candidate)))
        try:
            normalized.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Path escapes workspace: {path}")

        # WorkspacePolicy must validate BEFORE we resolve for use.
        ok, reason = self.workspace_policy.validate_path(candidate)
        if not ok:
            if reason and "not exist" in reason.lower():
                raise FileNotFoundError(f"File not found: {path}")
            if reason and "excluded" in reason.lower():
                raise ValueError(f"Path in excluded directory: {path}")
            raise ValueError(f"Path rejected: {reason}")

        # Now resolve for use (safe after policy validation).
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Path escapes workspace: {path}")

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
    ) -> dict[str, Any]:
        """Read file contents with optional line range.

        This method is automatically cached if cache is enabled.
        Creates FILE_SNIPPET artifact for investigation trace.

        Args:
            path: Relative path from repo root
            start_line: Starting line (1-indexed, inclusive)
            end_line: Ending line (1-indexed, inclusive)

        Returns:
            Dict with:
                - content: File content as string
                - artifact_id: ID of created artifact

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path is invalid
        """
        # If cache is enabled, check cache first
        cache_key = None
        git_head = None
        if self.cache is not None:
            git_head = self.git_head_tracker.get_current_head()
            if git_head is None:
                import logging
                logger = logging.getLogger(__name__)
                logger.debug(
                    "Cache disabled for read_file: git HEAD unavailable for path=%s",
                    path
                )
            else:
                cache_key = self.cache.generate_key(
                    tool_name="read_file",
                    args={"path": path, "start_line": start_line, "end_line": end_line},
                    git_head=git_head
                )
                cached_result = self.cache.get(cache_key)
                if cached_result is not None:
                    # Cached results are still strings - convert to dict format
                    # Create artifact for cached content too
                    artifact = self._create_file_artifact(
                        content=cached_result,
                        file_path=path,
                        line_start=start_line,
                        line_end=end_line
                    )
                    # Track provenance in current span
                    self._track_artifact_provenance(artifact.artifact_id)
                    return {
                        "content": cached_result,
                        "artifact_id": artifact.artifact_id
                    }

        # Cache miss or caching disabled - execute tool
        file_path = self._validate_path(path)

        # Read file in thread to avoid blocking
        content = await asyncio.to_thread(file_path.read_text, errors="ignore")
        lines = content.split("\n")

        # No line range specified - return full content
        if start_line is None and end_line is None:
            result_content = content
            actual_start = None
            actual_end = None
        else:
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
                result_content = ""
                actual_start = start_line
                actual_end = end_line
            else:
                sliced = lines[start_idx:end_idx]
                # Add line numbers
                numbered = [f"{i + start_idx + 1}: {line}" for i, line in enumerate(sliced)]
                result_content = "\n".join(numbered)
                actual_start = start_idx + 1
                actual_end = end_idx

        # Redact secrets before returning/storing artifacts (LLMs should not receive raw secrets).
        result_content = redaction_service.redact(result_content)

        # Create artifact
        artifact = self._create_file_artifact(
            content=result_content,
            file_path=path,
            line_start=actual_start,
            line_end=actual_end
        )

        # Track provenance in current span
        self._track_artifact_provenance(artifact.artifact_id)

        # Store in cache if enabled (store content string)
        if self.cache is not None and cache_key is not None:
            self.cache.set(cache_key, result_content)

        return {
            "content": result_content,
            "artifact_id": artifact.artifact_id
        }

    async def list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        pattern: str | None = None,
        max_items: int = 500,
    ) -> dict[str, Any]:
        """List directory contents.

        This method is automatically cached if cache is enabled.

        Args:
            path: Relative path from repo root (use "." for root)
            recursive: If True, list all files recursively
            pattern: Optional glob pattern to filter files
            max_items: Maximum items to return

        Returns:
            Dict with items list and metadata
        """
        # Cache check
        cache_key = None
        git_head = None
        if self.cache is not None:
            git_head = self.git_head_tracker.get_current_head()
            if git_head is None:
                # Log degraded state - caching disabled due to git failure
                import logging
                logger = logging.getLogger(__name__)
                logger.debug(
                    "Cache disabled for list_directory: git HEAD unavailable for path=%s",
                    path
                )
            else:
                cache_key = self.cache.generate_key(
                    tool_name="list_directory",
                    args={
                        "path": path,
                        "recursive": recursive,
                        "pattern": pattern,
                        "max_items": max_items,
                    },
                    git_head=git_head
                )
                cached_result = self.cache.get(cache_key)
                if cached_result is not None:
                    return cached_result

        # Cache miss or caching disabled - execute tool
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

        result = {
            "path": path,
            "items": items[:max_items],
            "count": len(items),
            "truncated": len(items) >= max_items,
        }

        # Store in cache if enabled
        if self.cache is not None and cache_key is not None:
            self.cache.set(cache_key, result)

        return result

    async def search_code(
        self,
        pattern: str,
        file_pattern: str | None = None,
        max_results: int = 50,
    ) -> dict[str, Any]:
        """Search for regex pattern across codebase.

        This method is automatically cached if cache is enabled.

        Args:
            pattern: Regex pattern to search for
            file_pattern: Optional glob to filter files
            max_results: Maximum matches to return

        Returns:
            Dict with matches list and metadata
        """
        # Cache check
        cache_key = None
        git_head = None
        if self.cache is not None:
            git_head = self.git_head_tracker.get_current_head()
            if git_head is None:
                # Log degraded state - caching disabled due to git failure
                import logging
                logger = logging.getLogger(__name__)
                logger.debug(
                    "Cache disabled for search_code: git HEAD unavailable for pattern=%s",
                    pattern
                )
            else:
                cache_key = self.cache.generate_key(
                    tool_name="search_code",
                    args={
                        "pattern": pattern,
                        "file_pattern": file_pattern,
                        "max_results": max_results,
                    },
                    git_head=git_head
                )
                cached_result = self.cache.get(cache_key)
                if cached_result is not None:
                    return cached_result

        # Cache miss or caching disabled - execute tool
        limits = self._get_scan_limits()

        # Translate file_pattern to semantic_grep's file_glob.
        file_glob = file_pattern or "**/*"

        scan = await semantic_grep(
            policy=self.workspace_policy,
            pattern=pattern,
            limits=limits,
            context_lines=0,
            file_glob=file_glob,
            max_matches=max_results,
        )

        if not scan.success:
            raise ValueError(scan.error or "search_code failed")

        results: list[dict[str, Any]] = []
        for finding in scan.findings[:max_results]:
            # Convert absolute paths to repo-relative for UI consistency.
            file_str = str(finding.file_path)
            try:
                file_str = str(Path(file_str).resolve().relative_to(self.repo_path))
            except Exception:
                pass

            snippet = (finding.snippet or "").splitlines()
            line_preview = snippet[0].strip() if snippet else ""

            results.append(
                {
                    "file": file_str,
                    "line": int(finding.line_start or 1),
                    "content": line_preview[:200],
                }
            )

        result = {
            "matches": results,
            "count": len(results),
            "files_searched": int(scan.files_scanned or 0),
            "truncated": len(scan.findings) > len(results),
        }

        # Store in cache if enabled
        if self.cache is not None and cache_key is not None:
            self.cache.set(cache_key, result)

        return result

    def _create_file_artifact(
        self,
        content: str,
        file_path: str,
        line_start: int | None = None,
        line_end: int | None = None
    ) -> Artifact:
        """
        Create FILE_SNIPPET artifact.

        Args:
            content: File content
            file_path: Path to file (relative to repo root)
            line_start: Optional starting line
            line_end: Optional ending line

        Returns:
            Created artifact
        """
        # Generate deterministic artifact ID
        artifact_id = generate_artifact_id(content)

        # Generate summary
        if line_start and line_end:
            summary = f"File snippet from {file_path}:{line_start}-{line_end}"
        else:
            summary = f"File content from {file_path}"

        # Truncate summary to 200 chars
        if len(summary) > 200:
            summary = summary[:197] + "..."

        # Create artifact (idempotent)
        artifact = artifact_service.create_artifact(
            artifact_id=artifact_id,
            artifact_type=ArtifactType.FILE_SNIPPET,
            content=content,
            summary=summary,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end
        )

        # Calculate size
        artifact.size_bytes = len(content.encode('utf-8'))

        return artifact

    def _create_tool_output_artifact(
        self,
        content: str,
        tool_name: str,
        query: str | None = None
    ) -> Artifact:
        """
        Create TOOL_OUTPUT artifact.

        Args:
            content: Tool output content
            tool_name: Name of tool that produced output
            query: Optional query/pattern used

        Returns:
            Created artifact
        """
        # Generate deterministic artifact ID
        artifact_id = generate_artifact_id(content)

        # Generate summary
        if query:
            summary = f"{tool_name} output for '{query}'"
        else:
            summary = f"{tool_name} output"

        # Truncate summary to 200 chars
        if len(summary) > 200:
            summary = summary[:197] + "..."

        # Create artifact (idempotent)
        artifact = artifact_service.create_artifact(
            artifact_id=artifact_id,
            artifact_type=ArtifactType.TOOL_OUTPUT,
            content=content,
            summary=summary
        )

        # Calculate size
        artifact.size_bytes = len(content.encode('utf-8'))

        return artifact
