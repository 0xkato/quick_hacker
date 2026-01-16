from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_mcp_tools_list_includes_read_file(tmp_path: Path):
    from mcp.quickhack_mcp_server import QuickHackMCPServer
    from services.tool_core import ToolCore

    tool_core = ToolCore(repo_path=str(tmp_path), project_id="proj")
    server = QuickHackMCPServer(tool_core)

    resp = await server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    tools = resp["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "read_file" in names
    # Flow tracking tools referenced by prompting/agents/*_system_prompt.md
    assert "track_file_analysis" in names
    assert "track_function_discovered" in names
    assert "track_call_chain" in names
    assert "track_sink_identified" in names
    assert "track_entry_point" in names


@pytest.mark.asyncio
async def test_mcp_read_file_rejects_symlink_escape(tmp_path: Path):
    from mcp.quickhack_mcp_server import QuickHackMCPServer
    from services.tool_core import ToolCore

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    (repo / "link.txt").symlink_to(outside)

    tool_core = ToolCore(repo_path=str(repo), project_id="proj")
    server = QuickHackMCPServer(tool_core)

    resp = await server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "link.txt"}},
        }
    )
    assert resp["result"]["isError"] is True


@pytest.mark.asyncio
async def test_mcp_read_file_rejects_excluded_directory(tmp_path: Path):
    from mcp.quickhack_mcp_server import QuickHackMCPServer
    from services.tool_core import ToolCore

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "x.js").write_text("console.log('nope')")

    tool_core = ToolCore(repo_path=str(repo), project_id="proj")
    server = QuickHackMCPServer(tool_core)

    resp = await server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "node_modules/x.js"}},
        }
    )
    assert resp["result"]["isError"] is True


@pytest.mark.asyncio
async def test_mcp_read_file_rejects_path_traversal(tmp_path: Path):
    from mcp.quickhack_mcp_server import QuickHackMCPServer
    from services.tool_core import ToolCore

    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "outside.txt").write_text("outside")

    tool_core = ToolCore(repo_path=str(repo), project_id="proj")
    server = QuickHackMCPServer(tool_core)

    resp = await server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "../outside.txt"}},
        }
    )
    assert resp["result"]["isError"] is True


def test_mcp_server_starts_as_script_and_lists_tools(tmp_path: Path):
    backend_dir = Path(__file__).resolve().parents[2]
    script_path = backend_dir / "mcp" / "quickhack_mcp_server.py"

    limits_path = tmp_path / "limits.json"
    limits_path.write_text(json.dumps({"max_runtime_s": 1.0}), encoding="utf-8")
    cancel_path = tmp_path / "cancel.flag"

    env = os.environ.copy()
    env["QUICKHACK_REPO_PATH"] = str(tmp_path)
    env["QUICKHACK_PROJECT_ID"] = "proj"
    env["QUICKHACK_AGENT_ID"] = "agent"
    env["QUICKHACK_LIMITS_PATH"] = str(limits_path)
    env["QUICKHACK_CANCEL_PATH"] = str(cancel_path)

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}},
    }
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    proc = subprocess.Popen(
        [sys.executable, "-u", str(script_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    out, err = proc.communicate(input=f"{json.dumps(init_req)}\n{json.dumps(list_req)}\n", timeout=5)

    assert proc.returncode == 0, err
    responses = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        payload = json.loads(line)
        responses[payload.get("id")] = payload

    assert responses[1]["result"]["serverInfo"]["name"] == "quickhack"
    tool_names = {t["name"] for t in responses[2]["result"]["tools"]}
    assert "read_file" in tool_names
