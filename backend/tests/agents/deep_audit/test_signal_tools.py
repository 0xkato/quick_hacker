# backend/tests/agents/deep_audit/test_signal_tools.py
import pytest
import json
from pathlib import Path
from agents.deep_audit.tools import upsert_sink_signals, promote_finding


def test_upsert_sink_signals_creates_new_signal(tmp_path, monkeypatch):
    """Test upsert_sink_signals creates a new signal."""
    project_id = "test_proj"
    project_root = tmp_path / "projects" / project_id
    project_root.mkdir(parents=True)

    # Monkeypatch project service
    from services.project_service import project_service

    def mock_get_project_path(pid):
        return str(project_root) if pid == project_id else None

    monkeypatch.setattr(project_service, 'get_project_path', mock_get_project_path)

    signal_data = {
        "signal_id": "sql_inj_001",
        "signal_type": "sql_injection_candidate",
        "file_path": "/repo/auth/db.py",
        "line_range": [45, 52],
        "sink_snippet": "execute(query)",
        "confidence": 0.8,
        "scope_id": "auth",
    }

    result = upsert_sink_signals(project_id=project_id, signals=[signal_data])

    assert result["success"] is True
    assert result["upserted_count"] == 1

    # Verify file was created
    signals_file = project_root / "sink_signals.json"
    assert signals_file.exists()

    # Verify content
    with open(signals_file) as f:
        data = json.load(f)
    assert len(data["signals"]) == 1
    assert data["signals"][0]["signal_id"] == "sql_inj_001"


def test_upsert_sink_signals_deduplicates_by_fingerprint(tmp_path, monkeypatch):
    """Test upsert_sink_signals deduplicates signals."""
    project_id = "test_proj"
    project_root = tmp_path / "projects" / project_id
    project_root.mkdir(parents=True)

    from services.project_service import project_service

    def mock_get_project_path(pid):
        return str(project_root) if pid == project_id else None

    monkeypatch.setattr(project_service, 'get_project_path', mock_get_project_path)

    signal_data = {
        "signal_id": "sql_inj_001",
        "signal_type": "sql_injection_candidate",
        "file_path": "/repo/auth/db.py",
        "line_range": [45, 52],
        "sink_snippet": "execute(query)",
        "confidence": 0.8,
        "scope_id": "auth",
    }

    # Insert first time
    result1 = upsert_sink_signals(project_id=project_id, signals=[signal_data])
    assert result1["upserted_count"] == 1

    # Insert duplicate (same signal_id)
    result2 = upsert_sink_signals(project_id=project_id, signals=[signal_data])
    assert result2["upserted_count"] == 0  # Already exists

    # Verify only one signal exists
    signals_file = project_root / "sink_signals.json"
    with open(signals_file) as f:
        data = json.load(f)
    assert len(data["signals"]) == 1


def test_promote_finding_creates_finding(tmp_path):
    """Test promote_finding creates a Finding object."""
    project_id = "test_proj"
    agent_id = "agent_123"

    finding_data = {
        "title": "SQL Injection in auth",
        "description": "User input flows to SQL query",
        "severity": "high",
        "file_path": "/repo/auth/db.py",
        "line_start": 45,
        "line_end": 52,
        "vulnerable_code": "execute(query)",
        "vulnerability_type": "sql_injection",
        "confidence": 0.9,
    }

    result = promote_finding(
        project_id=project_id,
        agent_id=agent_id,
        finding=finding_data
    )

    assert result["success"] is True
    assert "finding" in result
    assert result["finding"]["title"] == "SQL Injection in auth"
    assert result["finding"]["severity"] == "high"
