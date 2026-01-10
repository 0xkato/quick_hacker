import pytest

from agents.tools import ToolExecutor


@pytest.mark.asyncio
async def test_sink_signal_tools_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "app.py").write_text("print('hi')\n")

    executor = ToolExecutor(str(repo_root), project_id="proj-1")

    upsert = await executor.execute(
        "upsert_sink_signal",
        {
            "kind": "sink",
            "label": "User input reaches subprocess",
            "file_path": "app.py",
            "line_number": 1,
            "status": "unreviewed",
            "llm_risk_tier": "A",
            "llm_score": 80,
            "llm_reasoning": "Potential command injection sink",
        },
    )
    assert upsert.success is True
    assert isinstance(upsert.data, dict)
    signal = upsert.data.get("signal") or {}
    assert signal.get("file_path") == "app.py"
    assert signal.get("llm_score") == 80

    listed = await executor.execute("list_sink_signals", {"limit": 10})
    assert listed.success is True
    signals = (listed.data or {}).get("signals") or []
    assert len(signals) == 1
    assert signals[0]["label"] == "User input reaches subprocess"

