from __future__ import annotations

import os
import sys
from textwrap import dedent
from pathlib import Path

import pytest


def test_codex_event_parsing_maps_agent_text(tmp_path: Path) -> None:
    from providers.codex_cli_provider import CodexCLIProvider

    provider = CodexCLIProvider(
        repo_path=str(tmp_path),
        project_id="proj",
        agent_id="agent",
        model="gpt-5.2-codex",
        codex_path="codex",
    )

    events = provider._convert_codex_event(
        {"type": "item.completed", "item": {"id": "item_0", "type": "agent_message", "text": "hi"}}
    )
    assert events == [{"type": "agent_text", "text": "hi"}]


def test_codex_event_parsing_tracks_session_id_and_turn_complete(tmp_path: Path) -> None:
    from providers.codex_cli_provider import CodexCLIProvider

    provider = CodexCLIProvider(
        repo_path=str(tmp_path),
        project_id="proj",
        agent_id="agent",
        model="gpt-5.2-codex",
        codex_path="codex",
    )

    provider._convert_codex_event({"type": "thread.started", "thread_id": "thread-123"})
    assert provider.session_id == "thread-123"

    events = provider._convert_codex_event({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 2}})
    assert events and events[-1]["type"] == "turn_complete"
    assert events[-1]["session_id"] == "thread-123"


def test_codex_event_parsing_maps_mcp_tool_call_and_result(tmp_path: Path) -> None:
    from providers.codex_cli_provider import CodexCLIProvider

    provider = CodexCLIProvider(
        repo_path=str(tmp_path),
        project_id="proj",
        agent_id="agent",
        model="gpt-5.2-codex",
        codex_path="codex",
    )

    tool_call = provider._convert_codex_event(
        {
            "type": "item.started",
            "item": {
                "id": "item_1",
                "type": "mcp_tool_call",
                "server": "quickhack",
                "tool": "read_file",
                "arguments": {"path": "README.md"},
                "status": "in_progress",
            },
        }
    )
    assert tool_call == [
        {
            "type": "tool_call",
            "id": "item_1",
            "name": "mcp__quickhack__read_file",
            "args": {"path": "README.md"},
        }
    ]

    tool_result = provider._convert_codex_event(
        {
            "type": "item.completed",
            "item": {
                "id": "item_1",
                "type": "mcp_tool_call",
                "server": "quickhack",
                "tool": "read_file",
                "arguments": {"path": "README.md"},
                "status": "completed",
                "result": {"content": [{"type": "text", "text": "ok"}], "structured_content": None},
                "error": None,
            },
        }
    )
    assert tool_result and tool_result[0]["type"] == "tool_result"
    assert tool_result[0]["tool_use_id"] == "item_1"
    assert tool_result[0]["tool_name"] == "mcp__quickhack__read_file"
    assert tool_result[0]["is_error"] is False


def test_resume_command_construction_uses_session_id(tmp_path: Path, monkeypatch) -> None:
    from providers.codex_cli_provider import CodexCLIProvider

    provider = CodexCLIProvider(
        repo_path=str(tmp_path),
        project_id="proj",
        agent_id="agent",
        model="gpt-5.2-codex",
        codex_path="codex",
    )

    provider.session_id = "thread-123"
    cmd = provider._build_codex_command(prompt="continue")
    assert cmd[:3] == ["codex", "exec", "resume"]
    # Session id is the first positional argument after `resume`.
    assert cmd[3] == "thread-123"


def test_initial_command_construction_uses_exec(tmp_path: Path) -> None:
    from providers.codex_cli_provider import CodexCLIProvider

    provider = CodexCLIProvider(
        repo_path=str(tmp_path),
        project_id="proj",
        agent_id="agent",
        model="gpt-5.2-codex",
        codex_path="codex",
    )

    provider.session_id = None
    cmd = provider._build_codex_command(prompt="start")
    assert cmd[:2] == ["codex", "exec"]
    assert "resume" not in cmd


def test_provider_creates_isolated_codex_home(tmp_path: Path, monkeypatch) -> None:
    from providers.codex_cli_provider import CodexCLIProvider

    data_dir = tmp_path / "data"
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    provider = CodexCLIProvider(
        repo_path=str(tmp_path / "repo"),
        project_id="proj",
        agent_id="agent",
        model="gpt-5.2-codex",
        codex_path="codex",
    )

    codex_home = Path(provider.codex_home)
    assert str(codex_home).endswith(str(Path("projects/proj/.codex_runtime/agent")))

    provider._ensure_codex_home()
    assert (codex_home / ".codex" / "config.toml").exists()


@pytest.mark.asyncio
async def test_run_turn_handles_large_jsonl_lines(tmp_path: Path, monkeypatch) -> None:
    from providers.codex_cli_provider import CodexCLIProvider

    data_dir = tmp_path / "data"
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    repo = tmp_path / "repo"
    repo.mkdir()

    fake_codex = tmp_path / "fake_codex"
    fake_codex.write_text(
        "#!" + sys.executable + "\n"
        + dedent(
            """\
            import json
            import sys

            payload = {
                "type": "item.completed",
                "item": {
                    "id": "item_0",
                    "type": "agent_message",
                    "text": "a" * 70000,
                },
            }
            sys.stdout.write(json.dumps(payload))
            sys.stdout.write("\\n")
            sys.stdout.flush()
            """
        ),
        encoding="utf-8",
    )
    os.chmod(fake_codex, 0o755)

    provider = CodexCLIProvider(
        repo_path=str(repo),
        project_id="proj",
        agent_id="agent",
        model="gpt-5.2-codex",
        codex_path=str(fake_codex),
    )

    events = await provider.run_turn(prompt="hello")
    assert any(ev.get("type") == "agent_text" for ev in events)
    assert any(len(ev.get("text", "")) >= 70000 for ev in events if ev.get("type") == "agent_text")
