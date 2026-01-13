# Phase 3: Tool Execution Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Integrate artifact creation into tool execution layer so tools automatically create and track artifacts for file reads, search results, and other tool outputs.

**Architecture:** Extend ToolCore with artifact tracking middleware that creates artifacts after tool execution, tracks provenance via SpanService, and updates FlowService events with artifact IDs. Maintain backward compatibility with existing tool interface.

**Tech Stack:** Python 3.12, pytest, existing ToolCore/ArtifactService/SpanService

---

## Phase 3: Tool Execution Integration

### Task 10: Add Artifact Creation Helper to ToolCore

**Files:**
- Modify: `backend/services/tool_core.py`
- Test: `backend/tests/services/test_tool_core_artifacts.py`

**Step 1: Write failing test for artifact creation**

```python
# backend/tests/services/test_tool_core_artifacts.py
"""Tests for ToolCore artifact creation integration"""
import pytest
from services.tool_core import ToolCore
from services.artifact_service import artifact_service
from models.investigation_trace import ArtifactType, generate_artifact_id

@pytest.fixture
def tool_core(tmp_path):
    """Create ToolCore instance with temp repo"""
    (tmp_path / "test.txt").write_text("test content")
    return ToolCore(
        repo_path=str(tmp_path),
        project_id="test_project",
        agent_id="agent_123"
    )

def test_create_file_artifact(tool_core):
    """ToolCore should create FILE_SNIPPET artifacts"""
    artifact_service.clear_artifacts()

    content = "def test():\n    pass"
    file_path = "app/auth.py"

    artifact = tool_core._create_file_artifact(
        content=content,
        file_path=file_path,
        line_start=10,
        line_end=11
    )

    # Verify artifact created
    assert artifact is not None
    assert artifact.artifact_type == ArtifactType.FILE_SNIPPET
    assert artifact.content == content
    assert artifact.file_path == file_path
    assert artifact.line_start == 10
    assert artifact.line_end == 11

    # Verify summary generated
    assert "app/auth.py:10-11" in artifact.summary

    # Verify artifact stored in service
    retrieved = artifact_service.get_artifact(artifact.artifact_id)
    assert retrieved is not None
    assert retrieved.artifact_id == artifact.artifact_id

def test_create_tool_output_artifact(tool_core):
    """ToolCore should create TOOL_OUTPUT artifacts"""
    artifact_service.clear_artifacts()

    content = "search results here"
    tool_name = "ripgrep"

    artifact = tool_core._create_tool_output_artifact(
        content=content,
        tool_name=tool_name,
        query="pattern"
    )

    assert artifact is not None
    assert artifact.artifact_type == ArtifactType.TOOL_OUTPUT
    assert artifact.content == content
    assert tool_name in artifact.summary
    assert "pattern" in artifact.summary

def test_artifact_deduplication(tool_core):
    """Creating same artifact twice should return same artifact"""
    artifact_service.clear_artifacts()

    content = "same content"

    art1 = tool_core._create_tool_output_artifact(content, "test")
    art2 = tool_core._create_tool_output_artifact(content, "test")

    # Should be same artifact (content-hash deduplication)
    assert art1.artifact_id == art2.artifact_id
```

**Step 2: Run test to verify it fails**

```bash
pytest backend/tests/services/test_tool_core_artifacts.py::test_create_file_artifact -v
```

Expected: `AttributeError: 'ToolCore' object has no attribute '_create_file_artifact'`

**Step 3: Add artifact creation helpers to ToolCore**

```python
# Add to backend/services/tool_core.py (in ToolCore class)

from services.artifact_service import artifact_service
from models.investigation_trace import Artifact, ArtifactType, generate_artifact_id

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
```

**Step 4: Add imports at top of tool_core.py**

```python
# Add to imports section at top of backend/services/tool_core.py
from services.artifact_service import artifact_service
from models.investigation_trace import Artifact, ArtifactType, generate_artifact_id
```

**Step 5: Run test to verify it passes**

```bash
pytest backend/tests/services/test_tool_core_artifacts.py -v
```

Expected: PASS (3 tests)

**Step 6: Commit**

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core_artifacts.py
git commit -m "feat(tool-core): add artifact creation helpers

- Add _create_file_artifact() for FILE_SNIPPET artifacts
- Add _create_tool_output_artifact() for TOOL_OUTPUT artifacts
- Integrate with ArtifactService for content-hash deduplication
- Generate human-readable summaries (max 200 chars)
- Calculate artifact size in bytes
- All artifact creation is idempotent

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 11: Integrate Artifact Creation in read_file

**Files:**
- Modify: `backend/services/tool_core.py`
- Modify: `backend/tests/services/test_tool_core_artifacts.py`

**Step 1: Write failing test for read_file artifact integration**

```python
# Add to backend/tests/services/test_tool_core_artifacts.py

@pytest.mark.asyncio
async def test_read_file_creates_artifact(tool_core, tmp_path):
    """read_file should create artifact and return artifact_id"""
    artifact_service.clear_artifacts()

    # Create test file
    test_file = tmp_path / "test.py"
    test_file.write_text("line 1\nline 2\nline 3")

    # Read file
    result = await tool_core.read_file("test.py")

    # Should return dict with content and artifact_id
    assert isinstance(result, dict)
    assert "content" in result
    assert "artifact_id" in result
    assert result["content"] == "line 1\nline 2\nline 3"

    # Verify artifact created
    artifact = artifact_service.get_artifact(result["artifact_id"])
    assert artifact is not None
    assert artifact.artifact_type == ArtifactType.FILE_SNIPPET
    assert artifact.file_path == "test.py"

@pytest.mark.asyncio
async def test_read_file_with_line_range_creates_artifact(tool_core, tmp_path):
    """read_file with line range should create artifact with line refs"""
    artifact_service.clear_artifacts()

    # Create test file
    test_file = tmp_path / "test.py"
    test_file.write_text("line 1\nline 2\nline 3\nline 4\nline 5")

    # Read specific lines
    result = await tool_core.read_file("test.py", start_line=2, end_line=4)

    # Verify artifact has line references
    artifact = artifact_service.get_artifact(result["artifact_id"])
    assert artifact.line_start == 2
    assert artifact.line_end == 4
    assert "test.py:2-4" in artifact.summary
```

**Step 2: Run test to verify it fails**

```bash
pytest backend/tests/services/test_tool_core_artifacts.py::test_read_file_creates_artifact -v
```

Expected: `AssertionError: assert False` (result is str, not dict)

**Step 3: Update read_file to create artifacts**

```python
# Modify read_file method in backend/services/tool_core.py
# Replace the existing read_file implementation with:

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

        # Create artifact
        artifact = self._create_file_artifact(
            content=result_content,
            file_path=path,
            line_start=actual_start,
            line_end=actual_end
        )

        # Store in cache if enabled (store content string)
        if self.cache is not None and cache_key is not None:
            self.cache.set(cache_key, result_content)

        return {
            "content": result_content,
            "artifact_id": artifact.artifact_id
        }
```

**Step 4: Run test to verify it passes**

```bash
pytest backend/tests/services/test_tool_core_artifacts.py -k read_file -v
```

Expected: PASS (2 new tests)

**Step 5: Commit**

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core_artifacts.py
git commit -m "feat(tool-core): integrate artifact creation in read_file

- read_file now returns dict with content and artifact_id
- Creates FILE_SNIPPET artifact for each read operation
- Artifacts include file_path and line_start/line_end when specified
- Maintains cache compatibility (creates artifact for cached results)
- Backward compatible: returns dict instead of string

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 12: Add Span Context Tracking to ToolCore

**Files:**
- Modify: `backend/services/tool_core.py`
- Modify: `backend/tests/services/test_tool_core_artifacts.py`

**Step 1: Write failing test for span context tracking**

```python
# Add to backend/tests/services/test_tool_core_artifacts.py
from services.span_service import span_service
from models.investigation_trace import SpanType, SpanState

def test_set_current_span_context(tool_core):
    """ToolCore should track current span context"""
    # Set span context
    tool_core.set_span_context(
        span_id="span_123",
        hypothesis_id="hyp_1"
    )

    assert tool_core._current_span_id == "span_123"
    assert tool_core._current_hypothesis_id == "hyp_1"

def test_clear_span_context(tool_core):
    """ToolCore should clear span context"""
    tool_core.set_span_context("span_123", "hyp_1")
    tool_core.clear_span_context()

    assert tool_core._current_span_id is None
    assert tool_core._current_hypothesis_id is None

@pytest.mark.asyncio
async def test_read_file_tracks_provenance(tool_core, tmp_path):
    """read_file should track artifact provenance in span"""
    artifact_service.clear_artifacts()
    span_service.clear_agent_spans("agent_123")

    # Create span
    span = span_service.create_span(
        agent_id="agent_123",
        span_id="span_123",
        span_type=SpanType.HYPOTHESIS,
        hypothesis_id="hyp_1",
        label="Test hypothesis",
        state=SpanState.OPEN
    )

    # Set span context
    tool_core.set_span_context("span_123", "hyp_1")

    # Create test file
    test_file = tmp_path / "test.py"
    test_file.write_text("test content")

    # Read file
    result = await tool_core.read_file("test.py")

    # Verify artifact provenance tracked
    artifact_id = result["artifact_id"]
    artifact = artifact_service.get_artifact(artifact_id)
    assert "span_123" in artifact.producer_spans

    # Verify span has artifact
    updated_span = span_service.get_span("agent_123", "span_123")
    assert artifact_id in updated_span.artifact_ids
```

**Step 2: Run test to verify it fails**

```bash
pytest backend/tests/services/test_tool_core_artifacts.py::test_set_current_span_context -v
```

Expected: `AttributeError: 'ToolCore' object has no attribute 'set_span_context'`

**Step 3: Add span context tracking to ToolCore**

```python
# Add to ToolCore.__init__ in backend/services/tool_core.py
# After self.workspace_policy initialization:

        # Span context tracking
        self._current_span_id: str | None = None
        self._current_hypothesis_id: str | None = None

# Add methods to ToolCore class:

    def set_span_context(
        self,
        span_id: str,
        hypothesis_id: str | None = None
    ) -> None:
        """
        Set current span context for artifact provenance tracking.

        Args:
            span_id: Current span being executed
            hypothesis_id: Optional hypothesis ID
        """
        self._current_span_id = span_id
        self._current_hypothesis_id = hypothesis_id

    def clear_span_context(self) -> None:
        """Clear current span context."""
        self._current_span_id = None
        self._current_hypothesis_id = None

    def _track_artifact_provenance(self, artifact_id: str) -> None:
        """
        Track artifact provenance in current span.

        Args:
            artifact_id: Artifact ID to track
        """
        if not self._current_span_id or not self.agent_id:
            return

        # Import here to avoid circular dependency
        from services.span_service import span_service

        # Add artifact to span
        span_service.attach_artifact(
            agent_id=self.agent_id,
            span_id=self._current_span_id,
            artifact_id=artifact_id
        )

        # Track producer provenance
        artifact_service.add_producer(
            span_id=self._current_span_id,
            artifact_id=artifact_id
        )
```

**Step 4: Update read_file to track provenance**

```python
# In read_file method, after creating artifact, add:

        # Track provenance in current span
        self._track_artifact_provenance(artifact.artifact_id)

        return {
            "content": result_content,
            "artifact_id": artifact.artifact_id
        }
```

**Step 5: Run test to verify it passes**

```bash
pytest backend/tests/services/test_tool_core_artifacts.py -v
```

Expected: PASS (all 8 tests)

**Step 6: Commit**

```bash
git add backend/services/tool_core.py backend/tests/services/test_tool_core_artifacts.py
git commit -m "feat(tool-core): add span context tracking for artifact provenance

- Add set_span_context() to set current span
- Add clear_span_context() to clear context
- Add _track_artifact_provenance() to link artifacts to spans
- read_file automatically tracks provenance when span context set
- Integrates with SpanService and ArtifactService
- Updates producer_spans and span.artifact_ids bidirectionally

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Execution Options

Plan complete and saved to `docs/plans/2026-01-13-phase3-tool-execution-integration.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
