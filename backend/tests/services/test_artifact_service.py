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
