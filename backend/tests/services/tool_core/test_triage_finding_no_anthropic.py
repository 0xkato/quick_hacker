"""ToolCore triage_finding must be resilient without optional deps."""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest


def _block_anthropic_import(monkeypatch) -> None:
    real_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "anthropic" or str(name).startswith("anthropic."):
            raise ModuleNotFoundError("No module named 'anthropic'")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)


def _clear_module_prefix(prefix: str) -> None:
    for key in list(sys.modules):
        if key == prefix or key.startswith(prefix + "."):
            sys.modules.pop(key, None)


def test_finding_filters_imports_without_anthropic(monkeypatch):
    _block_anthropic_import(monkeypatch)
    _clear_module_prefix("services.finding_filters")

    import services.finding_filters  # noqa: F401


@pytest.mark.asyncio
async def test_triage_finding_no_api_key_does_not_require_anthropic(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ENABLE_QUESTS_BY_DEFAULT", "true")
    _block_anthropic_import(monkeypatch)
    _clear_module_prefix("services.finding_filters")

    import protocol_config.protocol_config as protocol_config

    importlib.reload(protocol_config)

    from services.tool_core import ToolCore

    repo = tmp_path / "repo"
    repo.mkdir()

    tool_core = ToolCore(repo_path=str(repo), project_id="proj")
    result = await tool_core.triage_finding(
        title="Test",
        file_path="app.py",
        vulnerability_type="command_injection",
        severity="critical",
        description="Test description",
    )

    assert result["decision"] == "keep"
    assert isinstance(result.get("reason"), str) and result.get("reason")
    assert "is_production_code" in result

