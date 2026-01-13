"""Tests for ToolCore artifact creation integration"""
import pytest
from services.tool_core import ToolCore
from services.artifact_service import artifact_service
from models.investigation_trace import ArtifactType, generate_artifact_id
from services.span_service import span_service
from models.investigation_trace import SpanType, SpanState

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
