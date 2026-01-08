"""Tests for file exploration tools."""

import pytest
import tempfile
import os
from pathlib import Path
from cass.tools.file_tools import FileTools


@pytest.fixture
def temp_project():
    """Create a temporary project structure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create structure
        src = Path(tmpdir) / "src"
        src.mkdir()

        (src / "main.py").write_text("def main():\n    print('hello')\n")
        (src / "auth.py").write_text("def login(user, password):\n    return True\n")

        routes = src / "routes"
        routes.mkdir()
        (routes / "api.py").write_text("@app.route('/users')\ndef get_users():\n    pass\n")

        yield tmpdir


def test_read_file(temp_project):
    """Can read file contents."""
    tools = FileTools(temp_project)
    content = tools.read_file("src/main.py")
    assert "def main():" in content


def test_list_directory(temp_project):
    """Can list directory contents."""
    tools = FileTools(temp_project)
    entries = tools.list_directory("src")
    names = [e["name"] for e in entries]
    assert "main.py" in names
    assert "auth.py" in names
    assert "routes" in names


def test_search_code(temp_project):
    """Can search for patterns."""
    tools = FileTools(temp_project)
    results = tools.search_code("@app.route")
    assert len(results) == 1
    assert "api.py" in results[0]["file"]


def test_get_file_info(temp_project):
    """Can get file metadata."""
    tools = FileTools(temp_project)
    info = tools.get_file_info("src/main.py")
    assert info["language"] == "python"
    assert info["line_count"] == 2


def test_find_files(temp_project):
    """Can find files matching glob pattern."""
    tools = FileTools(temp_project)
    results = tools.find_files("**/*.py", "src")
    assert len(results) >= 2  # main.py, auth.py
    assert all(r.endswith(".py") for r in results)


def test_read_file_line_range(temp_project):
    """Can read specific line range."""
    tools = FileTools(temp_project)
    content = tools.read_file("src/main.py", start_line=1, end_line=1)
    assert "def main():" in content


def test_read_file_not_found(temp_project):
    """Raises FileNotFoundError for missing file."""
    tools = FileTools(temp_project)
    with pytest.raises(FileNotFoundError):
        tools.read_file("nonexistent.py")


def test_path_traversal_blocked(temp_project):
    """Path traversal attempts should be blocked."""
    tools = FileTools(temp_project)
    with pytest.raises(ValueError, match="Path traversal"):
        tools.read_file("../../../etc/passwd")
