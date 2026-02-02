"""Tests for ProjectFilesystem virtual filesystem."""

import pytest
from pathlib import Path
from agents.deep_audit.filesystem import ProjectFilesystem, DATA_BASE_PATH


def test_filesystem_resolves_repo_path_as_readonly(tmp_path):
    """Test that /repo/ paths resolve to repo_root as read-only."""
    project_id = "test_proj"
    project_root = tmp_path / "projects" / project_id
    repo_root = project_root / "repo"
    repo_root.mkdir(parents=True)

    # Create a test file
    test_file = repo_root / "src" / "main.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text("print('hello')")

    # Monkeypatch data directory
    import agents.deep_audit.filesystem as fs_module
    original_base = getattr(fs_module, 'DATA_BASE_PATH', Path("data/projects"))
    fs_module.DATA_BASE_PATH = tmp_path / "projects"

    try:
        fs = ProjectFilesystem(project_id, repo_path=str(repo_root))
        physical_path, is_writable = fs.resolve_path("/repo/src/main.py")

        assert physical_path == test_file
        assert is_writable is False
    finally:
        fs_module.DATA_BASE_PATH = original_base


def test_filesystem_resolves_memories_path_as_writable(tmp_path):
    """Test that /memories/ paths resolve to memory_root as writable."""
    project_id = "test_proj"
    project_root = tmp_path / "projects" / project_id
    memories_root = project_root / "memories"
    memories_root.mkdir(parents=True)

    # Monkeypatch data directory
    import agents.deep_audit.filesystem as fs_module
    original_base = getattr(fs_module, 'DATA_BASE_PATH', Path("data/projects"))
    fs_module.DATA_BASE_PATH = tmp_path / "projects"

    try:
        fs = ProjectFilesystem(project_id)
        physical_path, is_writable = fs.resolve_path("/memories/findings.json")

        expected = tmp_path / "projects" / project_id / "memories" / "findings.json"
        assert physical_path == expected
        assert is_writable is True
    finally:
        fs_module.DATA_BASE_PATH = original_base


def test_filesystem_rejects_invalid_paths(tmp_path):
    """Test that paths not starting with /repo/ or /memories/ are rejected."""
    fs = ProjectFilesystem("test_proj", repo_path=str(tmp_path))

    with pytest.raises(ValueError, match="Path must start with /repo/ or /memories/"):
        fs.resolve_path("/invalid/path.txt")

    with pytest.raises(ValueError, match="Path must start with /repo/ or /memories/"):
        fs.resolve_path("relative/path.txt")

    with pytest.raises(ValueError, match="Path must start with /repo/ or /memories/"):
        fs.resolve_path("/etc/passwd")


def test_filesystem_prevents_path_traversal(tmp_path):
    """Test that path traversal attempts are rejected."""
    fs = ProjectFilesystem("test_proj", repo_path=str(tmp_path))

    with pytest.raises(ValueError, match="Path traversal detected"):
        fs.resolve_path("/repo/../../../etc/passwd")

    with pytest.raises(ValueError, match="Path traversal detected"):
        fs.resolve_path("/memories/../../secrets.txt")

    with pytest.raises(ValueError, match="Path traversal detected"):
        fs.resolve_path("/repo/subdir/../../../../../../etc/passwd")
