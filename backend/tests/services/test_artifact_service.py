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
