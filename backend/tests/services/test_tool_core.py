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
