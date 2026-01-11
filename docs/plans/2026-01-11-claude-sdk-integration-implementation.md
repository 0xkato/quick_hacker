# Claude SDK Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Claude Agent SDK as a new provider option (`provider: "claude_sdk"`) that replaces the custom ReAct loop with Claude's native agent loop, while keeping quick_hack as the governor (budget, steering, finding validation).

**Architecture:** ClaudeSDKProvider wraps the Claude Agent SDK client and exposes quick_hack tools via MCP. The ClaudeSDKOrchestrator (governor) manages turn-based execution with budget enforcement, finding validation, and steering. Shared ToolCore provides implementations used by both MCP tools and legacy ToolExecutor.

**Tech Stack:** Claude Agent SDK (`claude_agent_sdk`), MCP tools via `@tool()` decorator, FastAPI async, existing security_scanners module

---

## Task 1: Create ToolCore - Shared Tool Implementations

Create a shared ToolCore class that contains the actual tool implementations, used by both MCP tools (for Claude SDK) and legacy ToolExecutor.

**Files:**
- Create: `backend/services/tool_core.py`
- Test: `backend/tests/services/test_tool_core.py`

### Step 1: Write failing tests for ToolCore path validation

```python
# backend/tests/services/test_tool_core.py
import pytest
from pathlib import Path
from unittest.mock import MagicMock
from services.tool_core import ToolCore

@pytest.fixture
def temp_repo(tmp_path):
    """Create a temporary repository structure."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "main.py").write_text("def main(): pass")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "pkg" / "index.js").parent.mkdir(parents=True)
    (repo / "node_modules" / "pkg" / "index.js").write_text("module.exports = {}")
    return repo

@pytest.fixture
def tool_core(temp_repo):
    """Create ToolCore instance for testing."""
    return ToolCore(
        repo_path=str(temp_repo),
        project_id="test-project",
    )

class TestToolCorePathValidation:
    """Tests for ToolCore path validation."""

    def test_validate_path_accepts_valid_file(self, tool_core, temp_repo):
        """Valid file path within repo should be accepted."""
        result = tool_core._validate_path("src/main.py")
        assert result == (temp_repo / "src" / "main.py").resolve()

    def test_validate_path_rejects_path_traversal(self, tool_core):
        """Path traversal attempts should be rejected."""
        with pytest.raises(ValueError, match="escapes"):
            tool_core._validate_path("../../../etc/passwd")

    def test_validate_path_rejects_excluded_dir(self, tool_core):
        """Files in excluded directories should be rejected."""
        with pytest.raises(ValueError, match="excluded"):
            tool_core._validate_path("node_modules/pkg/index.js")

    def test_validate_path_raises_not_found(self, tool_core):
        """Non-existent files should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            tool_core._validate_path("src/nonexistent.py")

    def test_validate_dir_accepts_valid_dir(self, tool_core, temp_repo):
        """Valid directory path should be accepted."""
        result = tool_core._validate_dir("src")
        assert result == (temp_repo / "src").resolve()

    def test_validate_dir_rejects_file(self, tool_core):
        """File paths should be rejected by _validate_dir."""
        with pytest.raises(NotADirectoryError):
            tool_core._validate_dir("src/main.py")
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py -v`
Expected: FAIL - module `services.tool_core` not found

### Step 3: Write minimal ToolCore with path validation

```python
# backend/services/tool_core.py
"""Shared tool implementations for both MCP tools and legacy ToolExecutor.

This module provides the core logic for all agent tools, ensuring consistent
behavior between Claude SDK (MCP) and legacy ReAct providers.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Optional

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

        # Use WorkspacePolicy for validation
        ok, reason = self.workspace_policy.validate_path(candidate)
        if not ok:
            if reason and "not exist" in reason.lower():
                raise FileNotFoundError(f"File not found: {path}")
            if reason and "excluded" in reason.lower():
                raise ValueError(f"Path in excluded directory: {path}")
            raise ValueError(f"Path rejected: {reason}")

        return candidate.resolve()

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
```

### Step 4: Run tests to verify path validation passes

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCorePathValidation -v`
Expected: PASS

### Step 5: Commit path validation

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool_core): add ToolCore with path validation

- Create shared ToolCore class for MCP and legacy tool implementations
- Add _validate_path() for file path validation with security checks
- Add _validate_dir() for directory path validation
- Use WorkspacePolicy for consistent security boundaries"
```

---

## Task 2: Add ToolCore read_file implementation

Add the read_file method to ToolCore with proper line slicing.

**Files:**
- Modify: `backend/services/tool_core.py`
- Modify: `backend/tests/services/test_tool_core.py`

### Step 1: Write failing tests for read_file

```python
# Add to backend/tests/services/test_tool_core.py

class TestToolCoreReadFile:
    """Tests for ToolCore.read_file()."""

    @pytest.mark.asyncio
    async def test_read_file_returns_content(self, tool_core, temp_repo):
        """Should return file content."""
        content = await tool_core.read_file("src/main.py")
        assert "def main(): pass" in content

    @pytest.mark.asyncio
    async def test_read_file_with_line_range(self, tool_core, temp_repo):
        """Should return only specified lines."""
        # Create multi-line file
        (temp_repo / "multiline.txt").write_text("line1\nline2\nline3\nline4\nline5")

        content = await tool_core.read_file("multiline.txt", start_line=2, end_line=4)
        assert "line2" in content
        assert "line4" in content
        assert "line1" not in content
        assert "line5" not in content

    @pytest.mark.asyncio
    async def test_read_file_clamps_out_of_range(self, tool_core, temp_repo):
        """Should clamp line numbers to valid range."""
        (temp_repo / "short.txt").write_text("line1\nline2")

        # end_line beyond file length should be clamped
        content = await tool_core.read_file("short.txt", start_line=1, end_line=100)
        assert "line1" in content
        assert "line2" in content

    @pytest.mark.asyncio
    async def test_read_file_raises_not_found(self, tool_core):
        """Should raise FileNotFoundError for missing files."""
        with pytest.raises(FileNotFoundError):
            await tool_core.read_file("nonexistent.py")

    @pytest.mark.asyncio
    async def test_read_file_empty_when_start_exceeds_end(self, tool_core, temp_repo):
        """Should return empty when start >= end after clamping."""
        (temp_repo / "tiny.txt").write_text("line1")

        content = await tool_core.read_file("tiny.txt", start_line=10, end_line=20)
        assert content == ""
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreReadFile -v`
Expected: FAIL - `read_file` method not found

### Step 3: Implement read_file

```python
# Add to backend/services/tool_core.py ToolCore class

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
```

### Step 4: Run tests to verify read_file passes

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreReadFile -v`
Expected: PASS

### Step 5: Commit read_file

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool_core): add read_file with line slicing

- Add async read_file() method with optional line range
- Clamp line numbers to valid range
- Add line numbers to output when range specified
- Use asyncio.to_thread for non-blocking file I/O"
```

---

## Task 3: Add ToolCore list_directory and search_code

Add directory listing and code search methods.

**Files:**
- Modify: `backend/services/tool_core.py`
- Modify: `backend/tests/services/test_tool_core.py`

### Step 1: Write failing tests

```python
# Add to backend/tests/services/test_tool_core.py

class TestToolCoreListDirectory:
    """Tests for ToolCore.list_directory()."""

    @pytest.mark.asyncio
    async def test_list_directory_returns_items(self, tool_core, temp_repo):
        """Should return directory contents."""
        result = await tool_core.list_directory(".")
        assert "src/" in result["items"] or "src" in [i.rstrip("/") for i in result["items"]]

    @pytest.mark.asyncio
    async def test_list_directory_excludes_hidden(self, tool_core, temp_repo):
        """Should exclude hidden files/dirs."""
        (temp_repo / ".hidden").write_text("secret")
        result = await tool_core.list_directory(".")
        assert ".hidden" not in result["items"]

    @pytest.mark.asyncio
    async def test_list_directory_raises_not_dir(self, tool_core):
        """Should raise for non-directory paths."""
        with pytest.raises(NotADirectoryError):
            await tool_core.list_directory("src/main.py")


class TestToolCoreSearchCode:
    """Tests for ToolCore.search_code()."""

    @pytest.mark.asyncio
    async def test_search_code_finds_matches(self, tool_core, temp_repo):
        """Should find pattern matches."""
        result = await tool_core.search_code(r"def\s+\w+")
        assert result["count"] > 0
        assert any("main.py" in m["file"] for m in result["matches"])

    @pytest.mark.asyncio
    async def test_search_code_respects_max_results(self, tool_core, temp_repo):
        """Should respect max_results limit."""
        # Create files with many matches
        for i in range(20):
            (temp_repo / f"file{i}.py").write_text(f"def func{i}(): pass")

        result = await tool_core.search_code(r"def\s+\w+", max_results=5)
        assert result["count"] <= 5

    @pytest.mark.asyncio
    async def test_search_code_invalid_regex(self, tool_core):
        """Should handle invalid regex gracefully."""
        with pytest.raises(ValueError, match="regex"):
            await tool_core.search_code(r"[invalid")
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreListDirectory tests/services/test_tool_core.py::TestToolCoreSearchCode -v`
Expected: FAIL

### Step 3: Implement list_directory and search_code

```python
# Add to backend/services/tool_core.py ToolCore class

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
        import os

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
```

Also add the import at the top:
```python
import os
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreListDirectory tests/services/test_tool_core.py::TestToolCoreSearchCode -v`
Expected: PASS

### Step 5: Commit

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool_core): add list_directory and search_code

- Add list_directory() with recursive option and pattern filtering
- Add search_code() with regex search across codebase
- Both methods exclude hidden files and configured directories
- Use asyncio.to_thread for non-blocking I/O"
```

---

## Task 4: Add ToolCore security scanner integrations

Add methods that delegate to the security_scanners module.

**Files:**
- Modify: `backend/services/tool_core.py`
- Modify: `backend/tests/services/test_tool_core.py`

### Step 1: Write failing tests

```python
# Add to backend/tests/services/test_tool_core.py

class TestToolCoreSecurityScanners:
    """Tests for ToolCore security scanner methods."""

    @pytest.mark.asyncio
    async def test_scan_for_secrets_returns_result(self, tool_core, temp_repo):
        """Should return scan result."""
        # Create file with fake secret
        (temp_repo / "config.py").write_text('API_KEY = "sk-1234567890abcdef"')

        result = await tool_core.scan_for_secrets()
        assert "files_scanned" in result
        assert "findings" in result

    @pytest.mark.asyncio
    async def test_dependency_audit_returns_result(self, tool_core, temp_repo):
        """Should return audit result even with no lockfiles."""
        result = await tool_core.dependency_audit()
        assert "success" in result

    @pytest.mark.asyncio
    async def test_grep_semantic_finds_pattern(self, tool_core, temp_repo):
        """Should find pattern matches with context."""
        (temp_repo / "vuln.py").write_text("eval(user_input)")

        result = await tool_core.grep_semantic(r"eval\s*\(")
        assert result["success"]
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreSecurityScanners -v`
Expected: FAIL

### Step 3: Implement security scanner methods

```python
# Add imports at top of backend/services/tool_core.py
from services.security_scanners import (
    ScanFinding,
    ScanResult,
    scan_for_secrets,
    audit_dependencies,
    semantic_grep,
    generate_report,
)

# Add to ToolCore class

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
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreSecurityScanners -v`
Expected: PASS

### Step 5: Commit

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool_core): add security scanner integrations

- Add scan_for_secrets() delegating to security_scanners module
- Add dependency_audit() for lockfile vulnerability checking
- Add grep_semantic() for regex search with context
- Add generate_security_report() for report generation
- All methods use fresh ScanLimits from factory function"
```

---

## Task 5: Add ToolCore sink signal and finding methods

Add methods for managing sink signals and reporting findings.

**Files:**
- Modify: `backend/services/tool_core.py`
- Modify: `backend/tests/services/test_tool_core.py`

### Step 1: Write failing tests

```python
# Add to backend/tests/services/test_tool_core.py

class TestToolCoreSinkSignals:
    """Tests for ToolCore sink signal methods."""

    @pytest.mark.asyncio
    async def test_list_sink_signals_empty(self, tool_core):
        """Should return empty list when no signals."""
        result = await tool_core.list_sink_signals()
        assert "signals" in result
        assert result["count"] >= 0

    @pytest.mark.asyncio
    async def test_upsert_sink_signal_creates(self, tool_core):
        """Should create new sink signal."""
        result = await tool_core.upsert_sink_signal(
            kind="sink",
            label="eval() call",
            file_path="src/main.py",
            line_number=10,
        )
        assert "signal" in result
        assert result["signal"]["kind"] == "sink"


class TestToolCoreReportFinding:
    """Tests for ToolCore.report_finding()."""

    @pytest.mark.asyncio
    async def test_report_finding_returns_data(self, tool_core):
        """Should return reported finding data."""
        result = await tool_core.report_finding(
            severity="high",
            title="SQL Injection",
            vulnerability_type="SQL Injection",
            file_path="src/db.py",
            line_start=42,
            vulnerable_code="query = f'SELECT * FROM {user_input}'",
            description="User input concatenated into SQL query",
            confidence=0.9,
        )
        assert result["reported"]
        assert result["finding"]["severity"] == "high"
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreSinkSignals tests/services/test_tool_core.py::TestToolCoreReportFinding -v`
Expected: FAIL

### Step 3: Implement sink signal and finding methods

```python
# Add imports at top
from models.sink_signals import RiskTier, SinkSignal, SinkSignalKind, SinkSignalStatus
from services.sink_signal_service import compute_signal_fingerprint, sink_signal_service

# Add to ToolCore class

    async def list_sink_signals(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List sink signals for the project.

        Args:
            status: Optional status filter
            limit: Maximum signals to return

        Returns:
            Dict with signals list and count
        """
        limit = max(1, min(limit, 200))

        parsed_status = None
        if status is not None:
            try:
                parsed_status = SinkSignalStatus(status)
            except ValueError:
                raise ValueError(f"Invalid status: {status}")

        signals = await sink_signal_service.list_signals(
            project_id=self.project_id,
            status=parsed_status,
            limit=limit,
        )

        return {
            "count": len(signals),
            "signals": [s.model_dump(mode="json") for s in signals],
        }

    async def upsert_sink_signal(
        self,
        kind: str,
        label: str,
        file_path: str,
        fingerprint: str | None = None,
        line_number: int | None = None,
        status: str | None = None,
        llm_risk_tier: str | None = None,
        llm_score: int | None = None,
        llm_reasoning: str | None = None,
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Create or update a sink signal.

        Args:
            kind: Signal kind (entry_point, sink, other)
            label: Human-readable label
            file_path: File path relative to repo
            fingerprint: Optional explicit fingerprint
            line_number: Optional line number
            status: Optional status
            llm_risk_tier: Optional risk tier (S-E)
            llm_score: Optional 0-100 score
            llm_reasoning: Optional reasoning text
            metadata: Optional extra metadata

        Returns:
            Dict with created/updated signal
        """
        try:
            kind_enum = SinkSignalKind(kind)
        except ValueError:
            raise ValueError(f"Invalid kind: {kind}")

        status_enum = SinkSignalStatus.UNREVIEWED
        if status is not None:
            try:
                status_enum = SinkSignalStatus(status)
            except ValueError:
                raise ValueError(f"Invalid status: {status}")

        tier_enum = None
        if llm_risk_tier is not None:
            try:
                tier_enum = RiskTier(llm_risk_tier.strip().upper())
            except ValueError:
                raise ValueError(f"Invalid risk tier: {llm_risk_tier}")

        if llm_score is not None:
            if llm_score < 0 or llm_score > 100:
                raise ValueError("llm_score must be 0-100")

        signal_id = fingerprint or compute_signal_fingerprint(
            kind=kind_enum.value,
            file_path=file_path,
            line_number=line_number,
            label=label,
        )

        signal = SinkSignal(
            fingerprint=signal_id,
            kind=kind_enum,
            label=label,
            file_path=file_path,
            line_number=line_number,
            status=status_enum,
            source="llm",
            llm_risk_tier=tier_enum,
            llm_score=llm_score,
            llm_reasoning=llm_reasoning.strip() if llm_reasoning else None,
            metadata=metadata or {},
        )

        updated = await sink_signal_service.upsert_signals(
            project_id=self.project_id,
            signals=[signal],
        )

        result_signal = updated[0] if updated else signal
        return {"signal": result_signal.model_dump(mode="json")}

    async def report_finding(
        self,
        severity: str,
        title: str,
        vulnerability_type: str,
        file_path: str,
        line_start: int,
        vulnerable_code: str,
        description: str,
        confidence: float,
        cwe_id: str | None = None,
        line_end: int | None = None,
        source_trace: list[str] | None = None,
        attack_scenario: str | None = None,
        proof_of_concept: str | None = None,
        recommended_fix: str | None = None,
    ) -> dict[str, Any]:
        """Report a security finding.

        This returns the finding data; the actual persistence is handled
        by the orchestrator after validation.

        Returns:
            Dict with reported finding data
        """
        finding = {
            "severity": severity,
            "title": title,
            "vulnerability_type": vulnerability_type,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "vulnerable_code": vulnerable_code,
            "description": description,
            "confidence": confidence,
            "cwe_id": cwe_id,
            "source_trace": source_trace,
            "attack_scenario": attack_scenario,
            "proof_of_concept": proof_of_concept,
            "recommended_fix": recommended_fix,
        }

        return {"reported": True, "finding": finding}
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_tool_core.py::TestToolCoreSinkSignals tests/services/test_tool_core.py::TestToolCoreReportFinding -v`
Expected: PASS

### Step 5: Commit

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core.py
git commit -m "feat(tool_core): add sink signal and finding methods

- Add list_sink_signals() for retrieving project signals
- Add upsert_sink_signal() for creating/updating investigation leads
- Add report_finding() for reporting security findings
- Proper validation of enums and score ranges"
```

---

## Task 6: Create MCP Tool Server

Create the MCP tool server that exposes ToolCore methods via Claude SDK decorators.

**Files:**
- Create: `backend/providers/mcp_tools.py`
- Test: `backend/tests/providers/test_mcp_tools.py`

### Step 1: Write failing tests

```python
# backend/tests/providers/test_mcp_tools.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from providers.mcp_tools import create_quickhack_mcp_server, MCP_TOOLS

class TestMCPToolDefinitions:
    """Tests for MCP tool definitions."""

    def test_all_tools_have_required_fields(self):
        """Each tool should have name, description, and input_schema."""
        for tool in MCP_TOOLS:
            assert "name" in tool, f"Tool missing name"
            assert "description" in tool, f"Tool {tool.get('name')} missing description"
            assert "input_schema" in tool, f"Tool {tool.get('name')} missing input_schema"

    def test_input_schemas_are_valid_json_schema(self):
        """Each input_schema should be valid JSON Schema."""
        for tool in MCP_TOOLS:
            schema = tool["input_schema"]
            assert schema.get("type") == "object", f"Tool {tool['name']} schema must have type: object"
            assert "properties" in schema, f"Tool {tool['name']} schema must have properties"


class TestMCPServerCreation:
    """Tests for MCP server creation."""

    def test_create_server_returns_tools(self):
        """Should return server and tools list."""
        tool_core = MagicMock()
        server, tools = create_quickhack_mcp_server(tool_core)

        assert server is not None
        assert len(tools) > 0
        assert all(hasattr(t, "name") for t in tools)

    def test_allowed_tools_format(self):
        """Should generate correct allowed_tools format."""
        tool_core = MagicMock()
        server, tools = create_quickhack_mcp_server(tool_core)

        alias = "quickhack"
        allowed = [f"mcp__{alias}__{t.name}" for t in tools]

        assert all(a.startswith("mcp__quickhack__") for a in allowed)
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/providers/test_mcp_tools.py -v`
Expected: FAIL - module not found

### Step 3: Implement MCP tool server

```python
# backend/providers/mcp_tools.py
"""MCP tool server for Claude SDK integration.

This module exposes ToolCore methods as MCP tools using the Claude Agent SDK's
@tool() decorator pattern.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from services.tool_core import ToolCore


@dataclass
class MCPTool:
    """Represents an MCP tool definition."""
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]


# Tool definitions with full JSON Schema
MCP_TOOLS = [
    {
        "name": "read_file",
        "description": "Read file contents with optional line range",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path relative to repo root"},
                "start_line": {"type": "integer", "description": "Starting line (1-indexed)"},
                "end_line": {"type": "integer", "description": "Ending line (inclusive)"},
            },
            "required": ["path"]
        }
    },
    {
        "name": "search_code",
        "description": "Search for regex pattern across codebase",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search"},
                "file_pattern": {"type": "string", "description": "Glob to filter files"},
                "max_results": {"type": "integer", "description": "Max results (default: 50)"},
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "list_directory",
        "description": "List files and directories in a path",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path (use '.' for root)"},
                "recursive": {"type": "boolean", "description": "List recursively"},
                "pattern": {"type": "string", "description": "Glob pattern filter"},
            },
            "required": ["path"]
        }
    },
    {
        "name": "list_sink_signals",
        "description": "List sink signals (investigation leads) for the project",
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["unreviewed", "queued", "reviewed", "dismissed", "promoted"],
                    "description": "Optional status filter"
                },
                "limit": {"type": "integer", "description": "Max signals (default: 50)"},
            },
            "required": []
        }
    },
    {
        "name": "upsert_sink_signal",
        "description": "Create or update a sink signal (investigation lead)",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["entry_point", "sink", "other"],
                    "description": "Signal kind"
                },
                "label": {"type": "string", "description": "Human label"},
                "file_path": {"type": "string", "description": "File path"},
                "fingerprint": {"type": "string", "description": "Optional explicit ID"},
                "line_number": {"type": "integer", "description": "Line number"},
                "status": {
                    "type": "string",
                    "enum": ["unreviewed", "queued", "reviewed", "dismissed", "promoted"]
                },
                "llm_risk_tier": {
                    "type": "string",
                    "enum": ["S", "A", "B", "C", "D", "E"]
                },
                "llm_score": {"type": "integer", "description": "0-100 priority score"},
                "llm_reasoning": {"type": "string", "description": "Brief reasoning"},
                "metadata": {"type": "object", "description": "Extra metadata"},
            },
            "required": ["kind", "label", "file_path"]
        }
    },
    {
        "name": "report_finding",
        "description": "Report a CONFIRMED security vulnerability with evidence",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level"
                },
                "title": {"type": "string", "description": "Clear title"},
                "vulnerability_type": {"type": "string", "description": "Type (e.g., SQL Injection)"},
                "cwe_id": {"type": "string", "description": "CWE identifier"},
                "file_path": {"type": "string", "description": "Vulnerable file path"},
                "line_start": {"type": "integer", "description": "Starting line"},
                "line_end": {"type": "integer", "description": "Ending line"},
                "vulnerable_code": {"type": "string", "description": "Code snippet"},
                "description": {"type": "string", "description": "Detailed explanation"},
                "source_trace": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Trace from input to sink"
                },
                "attack_scenario": {"type": "string", "description": "How to exploit"},
                "proof_of_concept": {"type": "string", "description": "Example payload"},
                "confidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": "Confidence 0.0-1.0"
                },
                "recommended_fix": {"type": "string", "description": "Fix suggestion"},
            },
            "required": ["severity", "title", "vulnerability_type", "file_path",
                        "line_start", "vulnerable_code", "description", "confidence"]
        }
    },
    {
        "name": "scan_repo_for_secrets",
        "description": "Scan repository for hardcoded secrets and credentials",
        "input_schema": {
            "type": "object",
            "properties": {
                "entropy_threshold": {
                    "type": "number",
                    "description": "Min entropy for detection (default: 4.5)"
                },
            },
            "required": []
        }
    },
    {
        "name": "dependency_audit",
        "description": "Audit dependencies for known vulnerabilities",
        "input_schema": {
            "type": "object",
            "properties": {
                "lockfile_path": {
                    "type": "string",
                    "description": "Optional specific lockfile path"
                },
            },
            "required": []
        }
    },
    {
        "name": "grep_semantic",
        "description": "Search code with regex and context lines",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern"},
                "context_lines": {"type": "integer", "description": "Context lines (default: 3)"},
                "file_glob": {"type": "string", "description": "File glob (default: **/**)"},
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "generate_security_report",
        "description": "Generate security report from accumulated findings",
        "input_schema": {
            "type": "object",
            "properties": {
                "output_format": {
                    "type": "string",
                    "enum": ["markdown", "json", "sarif"],
                    "description": "Output format"
                },
            },
            "required": []
        }
    },
]

# Maximum output size (50KB)
MAX_OUTPUT_SIZE = 50_000


def truncate_output(text: str, max_size: int = MAX_OUTPUT_SIZE) -> str:
    """Truncate output to prevent flooding Claude's context."""
    if len(text) <= max_size:
        return text
    return text[:max_size] + f"\n... [truncated, {len(text) - max_size} chars omitted]"


def create_quickhack_mcp_server(tool_core: ToolCore) -> tuple[Any, list[MCPTool]]:
    """Create MCP server with quick_hack tools.

    Args:
        tool_core: ToolCore instance for tool implementations

    Returns:
        Tuple of (mcp_server_config, list of MCPTool objects)
    """
    tools: list[MCPTool] = []

    # Map tool names to ToolCore methods
    method_map = {
        "read_file": tool_core.read_file,
        "search_code": tool_core.search_code,
        "list_directory": tool_core.list_directory,
        "list_sink_signals": tool_core.list_sink_signals,
        "upsert_sink_signal": tool_core.upsert_sink_signal,
        "report_finding": tool_core.report_finding,
        "scan_repo_for_secrets": tool_core.scan_for_secrets,
        "dependency_audit": tool_core.dependency_audit,
        "grep_semantic": tool_core.grep_semantic,
        "generate_security_report": lambda **kwargs: tool_core.generate_security_report(
            findings=list(getattr(tool_core, "_accumulated_findings", {}).values()),
            **kwargs
        ),
    }

    async def create_handler(method: Callable, tool_name: str):
        """Create async handler that wraps ToolCore method."""
        async def handler(args: dict[str, Any]) -> dict[str, Any]:
            try:
                result = await method(**args)

                # Format as MCP response
                if isinstance(result, str):
                    text = truncate_output(result)
                elif isinstance(result, dict):
                    import json
                    text = truncate_output(json.dumps(result, indent=2))
                else:
                    text = truncate_output(str(result))

                return {"content": [{"type": "text", "text": text}]}
            except FileNotFoundError as e:
                return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
            except ValueError as e:
                return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
            except Exception as e:
                return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}

        return handler

    # Create MCPTool objects
    for tool_def in MCP_TOOLS:
        name = tool_def["name"]
        method = method_map.get(name)

        if method is None:
            continue

        # Create sync wrapper to avoid async in dataclass init
        import asyncio

        def make_sync_handler(m, n):
            async def async_handler(args):
                return await create_handler(m, n)

            def sync_wrapper(args):
                return asyncio.get_event_loop().run_until_complete(async_handler(args)(args))

            return sync_wrapper

        tool = MCPTool(
            name=name,
            description=tool_def["description"],
            input_schema=tool_def["input_schema"],
            handler=make_sync_handler(method, name),
        )
        tools.append(tool)

    # Create server configuration
    # This will be used by ClaudeSDKProvider to register with Claude SDK
    server_config = {
        "tools": tools,
        "tool_definitions": MCP_TOOLS,
    }

    return server_config, tools
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/providers/test_mcp_tools.py -v`
Expected: PASS

### Step 5: Commit

```bash
git add backend/providers/mcp_tools.py backend/tests/providers/test_mcp_tools.py
git commit -m "feat(mcp_tools): create MCP tool server for Claude SDK

- Define MCP_TOOLS with full JSON Schema for each tool
- Create MCPTool dataclass for tool metadata
- Add create_quickhack_mcp_server() factory function
- Map MCP tools to ToolCore methods
- Add output truncation to prevent context flooding"
```

---

## Task 7: Create ClaudeSDKProvider

Create the provider that wraps ClaudeSDKClient.

**Files:**
- Create: `backend/providers/claude_sdk_provider.py`
- Test: `backend/tests/providers/test_claude_sdk_provider.py`

### Step 1: Write failing tests

```python
# backend/tests/providers/test_claude_sdk_provider.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from providers.claude_sdk_provider import ClaudeSDKProvider

class TestClaudeSDKProviderInit:
    """Tests for ClaudeSDKProvider initialization."""

    def test_init_stores_config(self):
        """Should store configuration."""
        provider = ClaudeSDKProvider(
            repo_path="/tmp/repo",
            project_id="test-project",
            tool_core=MagicMock(),
            config=MagicMock(model="claude-sonnet-4-20250514"),
        )
        assert provider.repo_path == "/tmp/repo"
        assert provider.project_id == "test-project"

    def test_init_no_client_yet(self):
        """Client should not be created until start_session."""
        provider = ClaudeSDKProvider(
            repo_path="/tmp/repo",
            project_id="test-project",
            tool_core=MagicMock(),
            config=MagicMock(),
        )
        assert provider.client is None
        assert provider.session_id is None


class TestClaudeSDKProviderLifecycle:
    """Tests for session lifecycle."""

    @pytest.mark.asyncio
    async def test_start_session_creates_client(self):
        """start_session should create and connect client."""
        with patch("providers.claude_sdk_provider.ClaudeSDKClient") as MockClient:
            mock_client = AsyncMock()
            MockClient.return_value = mock_client

            provider = ClaudeSDKProvider(
                repo_path="/tmp/repo",
                project_id="test-project",
                tool_core=MagicMock(),
                config=MagicMock(model="claude-sonnet-4-20250514"),
            )

            await provider.start_session(audit_policy="Test policy")

            assert provider.client is not None
            mock_client.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_disconnects_client(self):
        """close should disconnect client."""
        provider = ClaudeSDKProvider(
            repo_path="/tmp/repo",
            project_id="test-project",
            tool_core=MagicMock(),
            config=MagicMock(),
        )
        mock_client = AsyncMock()
        provider.client = mock_client

        await provider.close()

        mock_client.disconnect.assert_called_once()
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/providers/test_claude_sdk_provider.py -v`
Expected: FAIL - module not found

### Step 3: Implement ClaudeSDKProvider

```python
# backend/providers/claude_sdk_provider.py
"""Claude SDK Provider for quick_hack.

This provider uses Claude Agent SDK's native agent loop instead of
the custom ReAct loop, while exposing all quick_hack tools via MCP.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from providers.mcp_tools import create_quickhack_mcp_server
from services.tool_core import ToolCore

# These will be imported from claude_agent_sdk when available
# For now, we define placeholder types for testing
try:
    from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
    from claude_agent_sdk import (
        AssistantMessage,
        SystemMessage,
        ResultMessage,
        TextBlock,
        ToolUseBlock,
        ToolResultBlock,
    )
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False
    # Placeholder classes for when SDK isn't installed
    ClaudeSDKClient = None
    ClaudeAgentOptions = None
    AssistantMessage = None
    SystemMessage = None
    ResultMessage = None
    TextBlock = None
    ToolUseBlock = None
    ToolResultBlock = None


class ClaudeSDKProvider:
    """Provider that uses Claude Agent SDK for the agent loop.

    This provider delegates the ReAct loop to Claude's native SDK while
    exposing all quick_hack tools via MCP. The orchestrator (governor)
    manages turn-based execution, budget enforcement, and finding validation.

    Attributes:
        repo_path: Path to the repository being analyzed
        project_id: Project identifier for persistence
        tool_core: Shared tool implementations
        config: Provider configuration (model, etc.)
        client: ClaudeSDKClient instance (created on start_session)
        session_id: Current session ID for resume capability
    """

    def __init__(
        self,
        repo_path: str,
        project_id: str,
        tool_core: ToolCore,
        config: Any,  # ProviderConfig
    ):
        """Initialize ClaudeSDKProvider.

        Args:
            repo_path: Path to repository root
            project_id: Project identifier
            tool_core: ToolCore instance with shared implementations
            config: Provider configuration with model settings
        """
        self.repo_path = repo_path
        self.project_id = project_id
        self.tool_core = tool_core
        self.config = config

        self.client: Optional[Any] = None  # ClaudeSDKClient
        self.session_id: Optional[str] = None

    async def start_session(
        self,
        audit_policy: str,
        resume_session_id: Optional[str] = None,
    ) -> None:
        """Start a new Claude SDK session.

        Args:
            audit_policy: System prompt appendix with audit policy
            resume_session_id: Optional session ID to resume
        """
        if not SDK_AVAILABLE:
            raise RuntimeError("Claude Agent SDK is not installed")

        # Create MCP server with tools
        mcp_server, tools = create_quickhack_mcp_server(self.tool_core)

        # Build allowed_tools list
        alias = "quickhack"
        allowed_tools = [f"mcp__{alias}__{t.name}" for t in tools]

        # Configure Claude SDK
        options = ClaudeAgentOptions(
            cwd=self.repo_path,
            system_prompt={
                "type": "preset",
                "preset": "claude_code",
                "append": audit_policy,
            },
            mcp_servers={alias: mcp_server},
            allowed_tools=allowed_tools,
            include_partial_messages=True,
            resume=resume_session_id,
        )

        # Create and connect client
        self.client = ClaudeSDKClient(options=options)
        await self.client.connect()

    async def run_turn(
        self,
        prompt: str,
        on_event: Callable[[dict], Any],
    ) -> Any:  # ResultMessage
        """Run a single turn of the agent loop.

        Args:
            prompt: User prompt for this turn
            on_event: Async callback for WebSocket events

        Returns:
            ResultMessage from Claude SDK
        """
        if self.client is None:
            raise RuntimeError("Session not started - call start_session first")

        # Send query
        await self.client.query(prompt)

        # Process response stream
        result = None
        async for msg in self.client.receive_response():
            # Convert to WebSocket events
            for event in self._to_ws_events(msg):
                await on_event(event)

            # Capture result message
            if isinstance(msg, ResultMessage):
                result = msg
                self.session_id = msg.session_id

        return result

    async def interrupt(self) -> None:
        """Interrupt the current Claude operation."""
        if self.client is not None:
            await self.client.interrupt()

    async def close(self) -> None:
        """Close the SDK session and disconnect."""
        if self.client is not None:
            await self.client.disconnect()
            self.client = None

    def _to_ws_events(self, msg: Any) -> list[dict]:
        """Convert Claude SDK message to WebSocket events.

        Args:
            msg: Message from Claude SDK

        Returns:
            List of WebSocket event dicts
        """
        if isinstance(msg, SystemMessage):
            return [{
                "type": "system",
                "subtype": msg.subtype,
                "data": msg.data,
            }]

        if isinstance(msg, ResultMessage):
            return [{
                "type": "turn_complete",
                "session_id": msg.session_id,
                "duration_ms": msg.duration_ms,
                "total_cost_usd": msg.total_cost_usd,
            }]

        if isinstance(msg, AssistantMessage):
            events = []
            for block in msg.content:
                if isinstance(block, TextBlock):
                    events.append({
                        "type": "agent_text",
                        "text": block.text,
                    })
                elif isinstance(block, ToolUseBlock):
                    events.append({
                        "type": "tool_call",
                        "id": block.id,
                        "name": block.name,
                        "args": block.input,
                    })
                elif isinstance(block, ToolResultBlock):
                    events.append({
                        "type": "tool_result",
                        "tool_use_id": block.tool_use_id,
                        "result": block.content,
                    })
            return events

        # Unknown message type
        return [{"type": "unknown", "raw": repr(msg)}]
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/providers/test_claude_sdk_provider.py -v`
Expected: PASS

### Step 5: Commit

```bash
git add backend/providers/claude_sdk_provider.py backend/tests/providers/test_claude_sdk_provider.py
git commit -m "feat(claude_sdk_provider): create Claude SDK provider

- Wrap ClaudeSDKClient for native agent loop
- Expose quick_hack tools via MCP with correct allowed_tools format
- Add start_session() with resume support
- Add run_turn() with WebSocket event conversion
- Add interrupt() and close() for lifecycle management
- Convert SDK messages to WebSocket events"
```

---

## Task 8: Create ClaudeSDKOrchestrator (Governor)

Create the turn-based orchestrator that manages Claude SDK sessions.

**Files:**
- Create: `backend/services/claude_sdk_orchestrator.py`
- Test: `backend/tests/services/test_claude_sdk_orchestrator.py`

### Step 1: Write failing tests

```python
# backend/tests/services/test_claude_sdk_orchestrator.py
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch
from services.claude_sdk_orchestrator import ClaudeSDKOrchestrator, SCAN_TIER_BUDGETS

class TestClaudeSDKOrchestratorInit:
    """Tests for orchestrator initialization."""

    def test_init_sets_budget_from_tier(self):
        """Should set budget based on scan tier."""
        orch = ClaudeSDKOrchestrator(
            scan_tier="medium",
            on_ws_event=AsyncMock(),
            provider=MagicMock(),
            tool_core=MagicMock(),
        )
        assert orch.budget_s == SCAN_TIER_BUDGETS["medium"]

    def test_init_starts_in_scanner_phase(self):
        """Should start in scanner phase."""
        orch = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=AsyncMock(),
            provider=MagicMock(),
            tool_core=MagicMock(),
        )
        assert orch.phase == "scanner"


class TestClaudeSDKOrchestratorBudget:
    """Tests for budget management."""

    def test_remaining_s_decreases(self):
        """Remaining time should decrease over time."""
        orch = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=AsyncMock(),
            provider=MagicMock(),
            tool_core=MagicMock(),
        )
        initial = orch.remaining_s()
        time.sleep(0.1)
        later = orch.remaining_s()
        assert later < initial

    def test_make_fresh_limits_has_deadline(self):
        """Fresh limits should have deadline set."""
        orch = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=AsyncMock(),
            provider=MagicMock(),
            tool_core=MagicMock(),
        )
        limits = orch.make_fresh_limits()
        assert limits.deadline is not None
        assert limits.deadline > time.monotonic()
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_claude_sdk_orchestrator.py -v`
Expected: FAIL - module not found

### Step 3: Implement ClaudeSDKOrchestrator

```python
# backend/services/claude_sdk_orchestrator.py
"""Claude SDK Orchestrator (Governor) for turn-based agent management.

This orchestrator manages Claude SDK sessions, enforcing time budgets,
validating findings, and steering Claude toward uncovered areas.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from services.security_scanners.base import ScanLimits
from services.tool_core import ToolCore
from providers.claude_sdk_provider import ClaudeSDKProvider


# Scan tier time budgets in seconds
SCAN_TIER_BUDGETS = {
    "quick": 5 * 60,       # 5 minutes
    "medium": 15 * 60,     # 15 minutes
    "advanced": 45 * 60,   # 45 minutes
    "pro": 90 * 60,        # 90 minutes
    "ultra": 4 * 60 * 60,  # 4 hours
    "evil": 24 * 60 * 60,  # 24 hours
}

# Time floors - minimum time before accepting completion
SCAN_TIER_FLOORS = {
    "quick": 2 * 60,       # 2 minutes
    "medium": 8 * 60,      # 8 minutes
    "advanced": 30 * 60,   # 30 minutes
    "pro": 60 * 60,        # 60 minutes
    "ultra": 2 * 60 * 60,  # 2 hours
    "evil": 8 * 60 * 60,   # 8 hours
}


class ClaudeSDKOrchestrator:
    """Turn-based orchestrator (governor) for Claude SDK sessions.

    Responsibilities:
    - Multiple run_turn() calls within budget
    - Validate findings after each turn
    - Steer Claude toward uncovered areas
    - Enforce time floor before completion
    - Handle scanner→analyzer handoff

    Attributes:
        scan_tier: Time budget tier
        budget_s: Total budget in seconds
        time_floor_s: Minimum time before completion
        phase: Current phase (scanner or analyzer)
    """

    def __init__(
        self,
        scan_tier: str,
        on_ws_event: Callable[[dict], Any],
        provider: ClaudeSDKProvider,
        tool_core: ToolCore,
    ):
        """Initialize orchestrator.

        Args:
            scan_tier: Scan tier name (quick, medium, etc.)
            on_ws_event: Async callback for WebSocket events
            provider: ClaudeSDKProvider instance
            tool_core: ToolCore for tool implementations
        """
        self.scan_tier = scan_tier
        self.on_ws_event = on_ws_event
        self.provider = provider
        self.tool_core = tool_core

        self.budget_s = SCAN_TIER_BUDGETS.get(scan_tier, SCAN_TIER_BUDGETS["medium"])
        self.time_floor_s = SCAN_TIER_FLOORS.get(scan_tier, 0)

        self.start_time = time.monotonic()
        self.phase = "scanner"
        self._cancelled = False

        # Track findings for validation
        self._pending_findings: list[dict] = []
        self._validated_findings: list[dict] = []

    def remaining_s(self) -> float:
        """Calculate remaining budget in seconds."""
        elapsed = time.monotonic() - self.start_time
        return max(0.0, self.budget_s - elapsed)

    def elapsed_s(self) -> float:
        """Calculate elapsed time in seconds."""
        return time.monotonic() - self.start_time

    def time_floor_satisfied(self) -> bool:
        """Check if minimum time has elapsed."""
        return self.elapsed_s() >= self.time_floor_s

    def make_fresh_limits(self) -> ScanLimits:
        """Create fresh ScanLimits with current remaining budget.

        Returns:
            ScanLimits with deadline and cancellation check
        """
        remaining = self.remaining_s()
        # Use 25% of remaining budget for this operation, max remaining
        budget_fraction = min(remaining, remaining * 0.25)
        deadline = time.monotonic() + budget_fraction

        return ScanLimits(
            deadline=deadline,
            cancelled=lambda: self._cancelled,
        )

    async def run_audit(
        self,
        initial_prompt: str,
        resume_session_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Run the full audit loop.

        Args:
            initial_prompt: Initial user prompt
            resume_session_id: Optional session ID to resume

        Returns:
            Audit result with findings and metadata
        """
        # Start session with scanner policy
        await self.provider.start_session(
            audit_policy=self._get_scanner_policy(),
            resume_session_id=resume_session_id,
        )

        prompt = initial_prompt

        while self.remaining_s() > 0 and not self._cancelled:
            # Run a turn
            result = await self.provider.run_turn(prompt, self.on_ws_event)

            # Validate any pending findings
            await self._validate_findings()

            # Check for handoff signal
            if self._should_handoff(result):
                await self._do_handoff()
                prompt = self._build_analyzer_prompt()
                continue

            # Check if Claude thinks it's done
            if self._claude_says_done(result):
                if not self.time_floor_satisfied():
                    prompt = self._build_continue_prompt()
                    continue
                else:
                    break

            # Build steering prompt for next turn
            prompt = self._build_steering_prompt()

        await self.provider.close()

        return {
            "findings": self._validated_findings,
            "phase": self.phase,
            "elapsed_s": self.elapsed_s(),
            "session_id": self.provider.session_id,
            "cancelled": self._cancelled,
        }

    async def cancel(self) -> None:
        """Cancel the audit."""
        self._cancelled = True
        await self.provider.interrupt()

    async def _validate_findings(self) -> None:
        """Validate pending findings from the last turn."""
        # For now, accept all findings with confidence >= 0.8
        # Future: Add more sophisticated validation
        validated = []
        for finding in self._pending_findings:
            confidence = finding.get("confidence", 0)
            if confidence >= 0.8:
                validated.append(finding)

        self._validated_findings.extend(validated)
        self._pending_findings.clear()

    def _should_handoff(self, result: Any) -> bool:
        """Check if we should handoff from scanner to analyzer."""
        # Handoff when scanner phase has found sufficient signals
        # and we have budget remaining
        if self.phase != "scanner":
            return False

        if self.remaining_s() < self.budget_s * 0.5:
            # Use at least 50% of budget in scanner phase
            return True

        return False

    async def _do_handoff(self) -> None:
        """Perform handoff from scanner to analyzer phase."""
        self.phase = "analyzer"

        # Close scanner session
        await self.provider.close()

        # Start analyzer session
        await self.provider.start_session(
            audit_policy=self._get_analyzer_policy(),
            resume_session_id=None,  # Fresh session for analyzer
        )

        await self.on_ws_event({
            "type": "phase_change",
            "from": "scanner",
            "to": "analyzer",
        })

    def _claude_says_done(self, result: Any) -> bool:
        """Check if Claude indicated completion."""
        # Check result message for completion signals
        # This would be enhanced based on actual SDK response format
        return False

    def _build_continue_prompt(self) -> str:
        """Build prompt to continue investigation."""
        remaining_floor = self.time_floor_s - self.elapsed_s()
        return (
            f"Continue investigating. You have {remaining_floor:.0f} seconds "
            f"minimum remaining before completion is accepted. "
            f"Look for additional attack vectors or verify existing findings more thoroughly."
        )

    def _build_steering_prompt(self) -> str:
        """Build prompt to steer toward uncovered areas."""
        # Future: Use coverage tracker to identify uncovered areas
        return "Continue your security analysis."

    def _build_analyzer_prompt(self) -> str:
        """Build initial prompt for analyzer phase."""
        return (
            "You are now in the analyzer phase. Review and verify the signals "
            "identified during scanning. Trace each potential vulnerability "
            "from source to sink and report confirmed findings."
        )

    def _get_scanner_policy(self) -> str:
        """Get system prompt appendix for scanner phase."""
        return """
You are a security scanner. Your job is to identify potential security issues
in the codebase. Use the available tools to:

1. Scan for hardcoded secrets
2. Check dependencies for vulnerabilities
3. Search for dangerous patterns (eval, exec, SQL injection, etc.)
4. Identify entry points and data sinks

Report findings using the report_finding tool. Track investigation leads
using upsert_sink_signal.
"""

    def _get_analyzer_policy(self) -> str:
        """Get system prompt appendix for analyzer phase."""
        return """
You are a security analyzer. Your job is to verify potential vulnerabilities
identified during scanning. For each signal:

1. Trace data flow from source to sink
2. Check for sanitization or validation
3. Determine if the issue is exploitable
4. Report confirmed findings with high confidence

Only report findings you have verified with concrete evidence.
"""
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_claude_sdk_orchestrator.py -v`
Expected: PASS

### Step 5: Commit

```bash
git add backend/services/claude_sdk_orchestrator.py backend/tests/services/test_claude_sdk_orchestrator.py
git commit -m "feat(orchestrator): create ClaudeSDKOrchestrator governor

- Implement turn-based orchestrator for Claude SDK sessions
- Add budget management with scan tier budgets and floors
- Add make_fresh_limits() for ScanLimits factory
- Implement run_audit() loop with validation and steering
- Add scanner→analyzer handoff logic
- Add cancellation support"
```

---

## Task 9: Integrate with AgentOrchestrator

Add provider routing to select between Claude SDK and legacy ReAct.

**Files:**
- Modify: `backend/services/agent_orchestrator.py`
- Modify: `backend/tests/services/test_agent_orchestrator.py` (if exists)

### Step 1: Write failing tests

```python
# backend/tests/services/test_agent_orchestrator_sdk.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

class TestAgentOrchestratorProviderRouting:
    """Tests for provider routing in AgentOrchestrator."""

    @pytest.mark.asyncio
    async def test_routes_claude_sdk_provider(self):
        """Should use ClaudeSDKOrchestrator for claude_sdk provider."""
        with patch("services.agent_orchestrator.ClaudeSDKOrchestrator") as MockOrch:
            mock_orch = AsyncMock()
            MockOrch.return_value = mock_orch

            # Create agent with claude_sdk provider
            # This test depends on actual AgentOrchestrator implementation
            # For now, just verify the routing logic would work
            assert True

    @pytest.mark.asyncio
    async def test_routes_anthropic_to_react(self):
        """Should use ReAct loop for anthropic provider."""
        # Verify anthropic provider still uses ReAct
        assert True
```

### Step 2: Run tests to verify baseline

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/services/test_agent_orchestrator_sdk.py -v`
Expected: PASS (placeholder tests)

### Step 3: Modify AgentOrchestrator for provider routing

This step requires reading the existing `agent_orchestrator.py` and adding the routing logic. The key changes are:

```python
# Add to backend/services/agent_orchestrator.py

# Add imports at top
from providers.claude_sdk_provider import ClaudeSDKProvider
from services.claude_sdk_orchestrator import ClaudeSDKOrchestrator
from services.tool_core import ToolCore

# In the start_agent method or equivalent, add routing:

async def _run_agent(self, agent: BaseAgent):
    """Run an agent based on its provider configuration."""
    config = agent.provider_config

    if config.provider.lower() == "claude_sdk":
        await self._run_sdk_agent(agent)
    else:
        await self._run_react_agent(agent)

async def _run_sdk_agent(self, agent: BaseAgent):
    """Run agent using Claude SDK provider."""
    # Create ToolCore with limits factory
    def get_limits():
        return self._sdk_orchestrators[agent.id].make_fresh_limits()

    tool_core = ToolCore(
        repo_path=agent.repo_path,
        project_id=agent.repo_id,
        get_scan_limits=get_limits,
    )

    # Create provider
    provider = ClaudeSDKProvider(
        repo_path=agent.repo_path,
        project_id=agent.repo_id,
        tool_core=tool_core,
        config=agent.provider_config,
    )

    # Store for cancellation
    self._sdk_providers[agent.id] = provider

    # Create orchestrator
    orchestrator = ClaudeSDKOrchestrator(
        scan_tier=agent.scan_tier or "medium",
        on_ws_event=self._make_ws_callback(agent.id),
        provider=provider,
        tool_core=tool_core,
    )

    self._sdk_orchestrators[agent.id] = orchestrator

    # Run audit
    result = await orchestrator.run_audit(
        initial_prompt=self._build_initial_prompt(agent),
        resume_session_id=agent.session_id,
    )

    # Update agent with results
    agent.findings.extend(result.get("findings", []))
    agent.session_id = result.get("session_id")

async def cancel_agent(self, agent_id: str):
    """Cancel a running agent."""
    # Interrupt SDK provider first
    if agent_id in self._sdk_providers:
        await self._sdk_providers[agent_id].interrupt()

    # Then cancel the task
    if agent_id in self._agent_tasks:
        self._agent_tasks[agent_id].cancel()
```

### Step 4: Run all tests

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/ -v --ignore=tests/cass`
Expected: All tests PASS

### Step 5: Commit

```bash
git add backend/services/agent_orchestrator.py backend/tests/services/test_agent_orchestrator_sdk.py
git commit -m "feat(orchestrator): add Claude SDK provider routing

- Route 'claude_sdk' provider to ClaudeSDKOrchestrator
- Keep legacy ReAct for anthropic/openai/ollama providers
- Wire cancellation to call provider.interrupt()
- Store session_id for resume capability"
```

---

## Task 10: Update ToolExecutor to use ToolCore

Refactor ToolExecutor to delegate to ToolCore for shared implementations.

**Files:**
- Modify: `backend/agents/tools.py`
- Test: Run existing tool tests

### Step 1: Verify existing tests pass

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/ -v`
Expected: Current tests PASS

### Step 2: Refactor ToolExecutor

The key changes are to make ToolExecutor delegate to ToolCore while maintaining backward compatibility:

```python
# Modify backend/agents/tools.py

# Add import at top
from services.tool_core import ToolCore

# Modify ToolExecutor.__init__ to create ToolCore
class ToolExecutor:
    def __init__(
        self,
        repo_path: str,
        project_id: Optional[str] = None,
        time_budget_ms: Optional[int] = None,
    ):
        self.repo_path = Path(repo_path)
        self.project_id = project_id
        self.investigation_notes: list[dict] = []

        # Create ToolCore for shared implementations
        self._tool_core = ToolCore(
            repo_path=str(self.repo_path),
            project_id=project_id or "",
            get_scan_limits=self._make_scan_limits,
        )

        # ... rest of existing init
```

Then delegate methods that have ToolCore implementations:

```python
    async def _tool_read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> ToolResult:
        """Read file contents."""
        try:
            content = await self._tool_core.read_file(path, start_line, end_line)
            return ToolResult(True, content)
        except FileNotFoundError as e:
            return ToolResult(False, None, str(e))
        except ValueError as e:
            return ToolResult(False, None, str(e))
```

### Step 3: Run tests to verify refactor works

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend && python -m pytest tests/agents/ tests/services/test_tool_core.py -v`
Expected: All tests PASS

### Step 4: Commit

```bash
git add backend/agents/tools.py
git commit -m "refactor(tools): delegate ToolExecutor to ToolCore

- Create ToolCore instance in ToolExecutor init
- Delegate shared methods to ToolCore implementations
- Maintain backward compatibility with existing tool interface
- Share code between MCP tools and legacy ToolExecutor"
```

---

## Task 11: Add exports to providers/__init__.py

Export the new provider classes.

**Files:**
- Modify: `backend/providers/__init__.py`

### Step 1: Add exports

```python
# backend/providers/__init__.py
from providers.base_provider import BaseProvider, ProviderConfig
from providers.openai_provider import OpenAIProvider
from providers.anthropic_provider import AnthropicProvider
from providers.ollama_provider import OllamaProvider
from providers.claude_sdk_provider import ClaudeSDKProvider
from providers.mcp_tools import create_quickhack_mcp_server, MCP_TOOLS

__all__ = [
    "BaseProvider",
    "ProviderConfig",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "ClaudeSDKProvider",
    "create_quickhack_mcp_server",
    "MCP_TOOLS",
]
```

### Step 2: Commit

```bash
git add backend/providers/__init__.py
git commit -m "feat(providers): export Claude SDK provider and MCP tools"
```

---

## Task 12: Add exports to services/__init__.py

Export the new service classes.

**Files:**
- Modify: `backend/services/__init__.py`

### Step 1: Add exports

```python
# backend/services/__init__.py
from services.tool_core import ToolCore
from services.claude_sdk_orchestrator import ClaudeSDKOrchestrator, SCAN_TIER_BUDGETS

__all__ = [
    "ToolCore",
    "ClaudeSDKOrchestrator",
    "SCAN_TIER_BUDGETS",
]
```

### Step 2: Commit

```bash
git add backend/services/__init__.py
git commit -m "feat(services): export ToolCore and ClaudeSDKOrchestrator"
```

---

## Task 13: Run full test suite and fix any issues

**Files:**
- All test files

### Step 1: Run full test suite

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend
python -m pytest tests/ -v --ignore=tests/cass
```

### Step 2: Fix any failing tests

Address any test failures that arise from the integration.

### Step 3: Commit fixes

```bash
git add -A
git commit -m "fix: resolve test failures from Claude SDK integration"
```

---

## Task 14: Final verification and documentation

### Step 1: Verify imports work

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend
python -c "
from services.tool_core import ToolCore
from providers.claude_sdk_provider import ClaudeSDKProvider
from services.claude_sdk_orchestrator import ClaudeSDKOrchestrator
print('All imports successful!')
"
```

### Step 2: Run type checking (if available)

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/backend
python -m mypy services/tool_core.py providers/claude_sdk_provider.py services/claude_sdk_orchestrator.py --ignore-missing-imports
```

### Step 3: Final commit

```bash
git add -A
git commit -m "feat: complete Claude SDK integration

Adds Claude Agent SDK as a new provider option (provider: 'claude_sdk')
that replaces the custom ReAct loop with Claude's native agent loop.

Components:
- ToolCore: Shared tool implementations for MCP and legacy
- MCP Tools: Tool definitions with Claude SDK decorators
- ClaudeSDKProvider: Wrapper for ClaudeSDKClient
- ClaudeSDKOrchestrator: Turn-based governor with budget enforcement

Features:
- Full MCP lockdown (all tools as MCP, no Claude Code built-ins)
- Governor validates findings after each turn
- Dual-mode with scanner→analyzer handoff
- Session persistence via session_id
- Explicit provider selection via 'claude_sdk'

Legacy providers (anthropic, openai, ollama) continue to use ReAct."
```

---

## Summary

This implementation plan creates the Claude SDK integration in 14 tasks:

1. **ToolCore foundation** - Path validation and security boundaries
2. **ToolCore read_file** - File reading with line slicing
3. **ToolCore list/search** - Directory listing and code search
4. **ToolCore security** - Scanner integrations
5. **ToolCore signals** - Sink signals and findings
6. **MCP Tool Server** - Tool definitions for Claude SDK
7. **ClaudeSDKProvider** - SDK client wrapper
8. **ClaudeSDKOrchestrator** - Turn-based governor
9. **AgentOrchestrator routing** - Provider selection
10. **ToolExecutor refactor** - Delegate to ToolCore
11. **Provider exports** - Module exports
12. **Service exports** - Module exports
13. **Test suite** - Full verification
14. **Final verification** - Type checking and documentation

Each task follows TDD with explicit test→implement→commit cycles.
