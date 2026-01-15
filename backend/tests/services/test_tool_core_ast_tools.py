from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_analyze_ast_python_extracts_functions(tmp_path: Path):
    from services.tool_core import ToolCore

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "example.py").write_text(
        "import os\n\n"
        "def foo(x):\n"
        "    return x\n\n"
        "class Bar:\n"
        "    def baz(self):\n"
        "        return 1\n"
    )

    tool_core = ToolCore(repo_path=str(repo), project_id="proj")
    result = await tool_core.analyze_ast(file_path="example.py")

    assert result["language"] == "python"
    assert any(f.get("name") == "foo" for f in result.get("functions", []))


@pytest.mark.asyncio
async def test_trace_dataflow_returns_enclosing_function(tmp_path: Path):
    from services.tool_core import ToolCore

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "example.py").write_text(
        "def handler(request, cursor):\n"
        "    user = request.args.get('user')\n"
        "    query = f\"select * from t where u='{user}'\"\n"
        "    cursor.execute(query)\n"
    )

    tool_core = ToolCore(repo_path=str(repo), project_id="proj")
    result = await tool_core.trace_dataflow(file_path="example.py", line_number=4)

    assert result["file_path"] == "example.py"
    assert result["line_number"] == 4
    assert result["enclosing_function"]["name"] == "handler"
