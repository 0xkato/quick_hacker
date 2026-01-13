# Phase 2: Artifact Tracking Service Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement ArtifactService for content-hash deduplicated artifact management with provenance tracking.

**Architecture:** Create ArtifactService similar to SpanService but focused on artifact lifecycle: creation with content-hash deduplication, retrieval, provenance tracking (producer/consumer spans), and cleanup. Store artifacts in-memory per agent with global deduplication by content hash.

**Tech Stack:** Python 3.12, pytest, dataclasses from Phase 1

---

## Phase 2: Artifact Service Management

### Task 7: Create ArtifactService Base

**Files:**
- Create: `backend/services/artifact_service.py`
- Test: `backend/tests/services/test_artifact_service.py`

**Step 1: Write failing test for ArtifactService**

```python
# backend/tests/services/test_artifact_service.py
"""Tests for ArtifactService"""
import pytest
from services.artifact_service import ArtifactService
from models.investigation_trace import Artifact, ArtifactType, generate_artifact_id

def test_artifact_service_create_artifact():
    """ArtifactService should create and store artifacts"""
    service = ArtifactService()

    content = "def vulnerable_function():\n    pass"
    artifact_id = generate_artifact_id(content)

    artifact = service.create_artifact(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.FILE_SNIPPET,
        content=content,
        summary="File snippet from auth.py:45-50",
        file_path="app/auth.py",
        line_start=45,
        line_end=50
    )

    assert artifact.artifact_id == artifact_id
    assert artifact.content == content

    # Should be retrievable
    retrieved = service.get_artifact(artifact_id)
    assert retrieved is not None
    assert retrieved.artifact_id == artifact_id

def test_artifact_service_deduplication():
    """ArtifactService should deduplicate by content hash"""
    service = ArtifactService()

    content = "same content"
    artifact_id = generate_artifact_id(content)

    # Create first artifact
    artifact1 = service.create_artifact(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.TOOL_OUTPUT,
        content=content,
        summary="First occurrence"
    )

    # Create second artifact with same content (same ID)
    artifact2 = service.create_artifact(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.TOOL_OUTPUT,
        content=content,
        summary="Second occurrence"
    )

    # Should return same artifact (deduplication)
    assert artifact1.artifact_id == artifact2.artifact_id

    # Verify only one artifact stored
    all_artifacts = service.get_all_artifacts()
    assert len(all_artifacts) == 1

def test_artifact_service_get_artifacts_by_type():
    """ArtifactService should filter artifacts by type"""
    service = ArtifactService()

    # Create artifacts of different types
    service.create_artifact(
        artifact_id=generate_artifact_id("snippet1"),
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="snippet1",
        summary="Snippet"
    )

    service.create_artifact(
        artifact_id=generate_artifact_id("search1"),
        artifact_type=ArtifactType.SEARCH_RESULT,
        content="search1",
        summary="Search"
    )

    snippets = service.get_artifacts_by_type(ArtifactType.FILE_SNIPPET)
    assert len(snippets) == 1
    assert snippets[0].artifact_type == ArtifactType.FILE_SNIPPET
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_artifact_service.py::test_artifact_service_create_artifact -v
```

Expected: `ModuleNotFoundError: No module named 'services.artifact_service'`

**Step 3: Create ArtifactService**

```python
# backend/services/artifact_service.py
"""
Artifact Service - Manages investigation artifacts.

Provides content-hash deduplicated artifact storage and provenance tracking.
"""

from typing import Optional
from models.investigation_trace import Artifact, ArtifactType


class ArtifactService:
    """
    Manages investigation artifacts with content-hash deduplication.

    Artifacts are stored globally by artifact_id (content hash).
    """

    def __init__(self):
        # artifact_id -> Artifact (global deduplication)
        self._artifacts: dict[str, Artifact] = {}

    def create_artifact(
        self,
        artifact_id: str,
        artifact_type: ArtifactType,
        content: str | dict,
        summary: str,
        file_path: Optional[str] = None,
        line_start: Optional[int] = None,
        line_end: Optional[int] = None
    ) -> Artifact:
        """
        Create or retrieve artifact (content-hash deduplication).

        If artifact_id already exists, returns existing artifact.
        This enables deduplication: same content → same artifact.

        Args:
            artifact_id: Content-hash ID (from generate_artifact_id)
            artifact_type: Type of artifact
            content: Artifact content
            summary: Human-readable summary (max 200 chars)
            file_path: Optional file reference
            line_start: Optional line start
            line_end: Optional line end

        Returns:
            Artifact (existing or newly created)
        """
        # Deduplication: return existing if present
        if artifact_id in self._artifacts:
            return self._artifacts[artifact_id]

        # Create new artifact
        artifact = Artifact(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            content=content,
            summary=summary,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end
        )

        self._artifacts[artifact_id] = artifact
        return artifact

    def get_artifact(self, artifact_id: str) -> Optional[Artifact]:
        """Get artifact by ID"""
        return self._artifacts.get(artifact_id)

    def get_all_artifacts(self) -> list[Artifact]:
        """Get all artifacts"""
        return list(self._artifacts.values())

    def get_artifacts_by_type(self, artifact_type: ArtifactType) -> list[Artifact]:
        """Get all artifacts of a specific type"""
        return [
            artifact for artifact in self._artifacts.values()
            if artifact.artifact_type == artifact_type
        ]

    def clear_artifacts(self) -> None:
        """Clear all artifacts"""
        self._artifacts.clear()


# Global instance
artifact_service = ArtifactService()
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_artifact_service.py -v
```

Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add backend/services/artifact_service.py backend/tests/services/test_artifact_service.py
git commit -m "feat(services): add ArtifactService with content-hash deduplication

- Add create_artifact() with automatic deduplication
- Add get_artifact() for retrieval by ID
- Add get_all_artifacts() for full artifact list
- Add get_artifacts_by_type() for filtering
- Store artifacts globally by content-hash ID
- Export global artifact_service instance"
```

---

### Task 8: Add Provenance Tracking to ArtifactService

**Files:**
- Modify: `backend/services/artifact_service.py`
- Modify: `backend/tests/services/test_artifact_service.py`

**Step 1: Write failing test for provenance tracking**

```python
# Add to backend/tests/services/test_artifact_service.py

def test_artifact_service_add_producer():
    """ArtifactService should track producer spans"""
    service = ArtifactService()

    artifact_id = generate_artifact_id("content")
    service.create_artifact(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.FILE_SNIPPET,
        content="content",
        summary="Test"
    )

    # Add producer span
    success = service.add_producer("span_123", artifact_id)
    assert success is True

    artifact = service.get_artifact(artifact_id)
    assert "span_123" in artifact.producer_spans

    # Adding same producer again should be idempotent
    success = service.add_producer("span_123", artifact_id)
    assert success is True
    assert len(artifact.producer_spans) == 1

def test_artifact_service_add_consumer():
    """ArtifactService should track consumer spans"""
    service = ArtifactService()

    artifact_id = generate_artifact_id("content")
    service.create_artifact(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.SEARCH_RESULT,
        content="content",
        summary="Test"
    )

    # Add consumer span
    success = service.add_consumer("span_456", artifact_id)
    assert success is True

    artifact = service.get_artifact(artifact_id)
    assert "span_456" in artifact.consumer_spans

def test_artifact_service_provenance_nonexistent():
    """Provenance methods should handle nonexistent artifacts"""
    service = ArtifactService()

    success = service.add_producer("span_123", "nonexistent_id")
    assert success is False

    success = service.add_consumer("span_456", "nonexistent_id")
    assert success is False

def test_artifact_service_get_artifacts_by_producer():
    """ArtifactService should find artifacts by producer span"""
    service = ArtifactService()

    art1_id = generate_artifact_id("content1")
    art2_id = generate_artifact_id("content2")

    service.create_artifact(art1_id, ArtifactType.FILE_SNIPPET, "content1", "Art 1")
    service.create_artifact(art2_id, ArtifactType.FILE_SNIPPET, "content2", "Art 2")

    service.add_producer("span_A", art1_id)
    service.add_producer("span_A", art2_id)
    service.add_producer("span_B", art2_id)

    # Find artifacts produced by span_A
    artifacts = service.get_artifacts_by_producer("span_A")
    assert len(artifacts) == 2

    # Find artifacts produced by span_B
    artifacts = service.get_artifacts_by_producer("span_B")
    assert len(artifacts) == 1
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_artifact_service.py::test_artifact_service_add_producer -v
```

Expected: `AttributeError: 'ArtifactService' object has no attribute 'add_producer'`

**Step 3: Add provenance methods to ArtifactService**

```python
# Add to backend/services/artifact_service.py

    def add_producer(self, span_id: str, artifact_id: str) -> bool:
        """
        Add a producer span for an artifact.

        Args:
            span_id: Span that produced this artifact
            artifact_id: Artifact ID

        Returns:
            True if successful, False if artifact not found
        """
        artifact = self.get_artifact(artifact_id)
        if not artifact:
            return False

        artifact.producer_spans.add(span_id)
        return True

    def add_consumer(self, span_id: str, artifact_id: str) -> bool:
        """
        Add a consumer span for an artifact.

        Args:
            span_id: Span that consumed this artifact
            artifact_id: Artifact ID

        Returns:
            True if successful, False if artifact not found
        """
        artifact = self.get_artifact(artifact_id)
        if not artifact:
            return False

        artifact.consumer_spans.add(span_id)
        return True

    def get_artifacts_by_producer(self, span_id: str) -> list[Artifact]:
        """Get all artifacts produced by a specific span"""
        return [
            artifact for artifact in self._artifacts.values()
            if span_id in artifact.producer_spans
        ]

    def get_artifacts_by_consumer(self, span_id: str) -> list[Artifact]:
        """Get all artifacts consumed by a specific span"""
        return [
            artifact for artifact in self._artifacts.values()
            if span_id in artifact.consumer_spans
        ]
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_artifact_service.py -v
```

Expected: PASS (8 tests total)

**Step 5: Commit**

```bash
git add backend/services/artifact_service.py backend/tests/services/test_artifact_service.py
git commit -m "feat(artifact-service): add provenance tracking for producer/consumer spans

- Add add_producer() to track spans that produced artifacts
- Add add_consumer() to track spans that consumed artifacts
- Add get_artifacts_by_producer() for provenance queries
- Add get_artifacts_by_consumer() for reverse provenance
- Use sets for automatic deduplication of span IDs
- Return False for nonexistent artifacts"
```

---

### Task 9: Add Artifact Statistics and Cleanup

**Files:**
- Modify: `backend/services/artifact_service.py`
- Modify: `backend/tests/services/test_artifact_service.py`

**Step 1: Write failing test for statistics**

```python
# Add to backend/tests/services/test_artifact_service.py

def test_artifact_service_get_stats():
    """ArtifactService should provide statistics"""
    service = ArtifactService()

    # Create artifacts of different types
    service.create_artifact(
        generate_artifact_id("snippet1"),
        ArtifactType.FILE_SNIPPET,
        "snippet1",
        "Snippet 1"
    )
    service.create_artifact(
        generate_artifact_id("snippet2"),
        ArtifactType.FILE_SNIPPET,
        "snippet2",
        "Snippet 2"
    )
    service.create_artifact(
        generate_artifact_id("search1"),
        ArtifactType.SEARCH_RESULT,
        "search1",
        "Search 1"
    )

    stats = service.get_stats()

    assert stats["total_artifacts"] == 3
    assert stats["by_type"]["file_snippet"] == 2
    assert stats["by_type"]["search_result"] == 1
    assert stats["total_size_bytes"] == 0  # size_bytes defaults to 0

def test_artifact_service_remove_artifact():
    """ArtifactService should support artifact removal"""
    service = ArtifactService()

    artifact_id = generate_artifact_id("content")
    service.create_artifact(
        artifact_id=artifact_id,
        artifact_type=ArtifactType.TOOL_OUTPUT,
        content="content",
        summary="Test"
    )

    # Verify artifact exists
    assert service.get_artifact(artifact_id) is not None

    # Remove artifact
    removed = service.remove_artifact(artifact_id)
    assert removed is True

    # Verify artifact removed
    assert service.get_artifact(artifact_id) is None

    # Removing nonexistent artifact should return False
    removed = service.remove_artifact(artifact_id)
    assert removed is False
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/services/test_artifact_service.py::test_artifact_service_get_stats -v
```

Expected: `AttributeError: 'ArtifactService' object has no attribute 'get_stats'`

**Step 3: Add statistics and cleanup methods**

```python
# Add to backend/services/artifact_service.py
from collections import defaultdict

    def get_stats(self) -> dict:
        """
        Get artifact statistics.

        Returns:
            Dict with total counts and breakdowns by type
        """
        type_counts = defaultdict(int)
        total_size = 0

        for artifact in self._artifacts.values():
            type_counts[artifact.artifact_type.value] += 1
            total_size += artifact.size_bytes

        return {
            "total_artifacts": len(self._artifacts),
            "by_type": dict(type_counts),
            "total_size_bytes": total_size
        }

    def remove_artifact(self, artifact_id: str) -> bool:
        """
        Remove an artifact.

        Args:
            artifact_id: Artifact ID to remove

        Returns:
            True if removed, False if not found
        """
        if artifact_id in self._artifacts:
            del self._artifacts[artifact_id]
            return True
        return False
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/services/test_artifact_service.py -v
```

Expected: PASS (10 tests total)

**Step 5: Commit**

```bash
git add backend/services/artifact_service.py backend/tests/services/test_artifact_service.py
git commit -m "feat(artifact-service): add statistics and cleanup methods

- Add get_stats() for artifact metrics by type
- Add remove_artifact() for cleanup
- Calculate total size across all artifacts
- Return False when removing nonexistent artifacts"
```

---

## Execution Options

Plan complete and saved to `docs/plans/2026-01-13-phase2-artifact-service-implementation.md`.

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
