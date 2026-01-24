"""Regression tests for protocol config import side-effects.

The Codex CLI MCP server speaks JSON over stdout. Any accidental stdout writes
from imports can corrupt the stream and cause tool calls to fail.
"""

from __future__ import annotations

import importlib


def test_protocol_config_does_not_write_to_stdout_on_import(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ENABLE_QUESTS_BY_DEFAULT", "true")

    import protocol_config.protocol_config as protocol_config

    importlib.reload(protocol_config)
    captured = capsys.readouterr()

    assert captured.out == ""

