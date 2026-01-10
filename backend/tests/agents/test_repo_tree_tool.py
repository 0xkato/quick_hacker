import pytest

from agents.tools import ToolExecutor


@pytest.mark.asyncio
async def test_get_repo_tree_builds_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('ok')\n")
    (tmp_path / "README.md").write_text("# hi\n")

    executor = ToolExecutor(str(tmp_path))
    result = await executor.execute("get_repo_tree", {"path": ".", "max_depth": 2, "max_nodes": 50})
    assert result.success is True
    assert isinstance(result.data, dict)
    tree = result.data.get("tree")
    assert tree and tree.get("is_dir") is True

    children = tree.get("children") or []
    paths = {c.get("path") for c in children}
    assert "src" in paths
    assert "README.md" in paths


@pytest.mark.asyncio
async def test_get_repo_tree_rejects_traversal(tmp_path):
    executor = ToolExecutor(str(tmp_path))
    result = await executor.execute("get_repo_tree", {"path": "../"})
    assert result.success is False
    assert "escapes repository" in (result.error or "").lower()

