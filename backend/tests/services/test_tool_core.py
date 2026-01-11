# backend/tests/services/test_tool_core.py
import pytest
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

    def test_validate_dir_rejects_symlink(self, tool_core, temp_repo):
        """Symlink directories should be rejected."""
        (temp_repo / "real_dir").mkdir()
        (temp_repo / "link_dir").symlink_to(temp_repo / "real_dir")
        with pytest.raises(ValueError, match="Symlink"):
            tool_core._validate_dir("link_dir")

    def test_validate_dir_rejects_path_traversal(self, tool_core):
        """Directory path traversal should be rejected."""
        with pytest.raises(ValueError, match="escapes"):
            tool_core._validate_dir("../../../tmp")


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
