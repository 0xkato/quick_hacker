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
