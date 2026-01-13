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
