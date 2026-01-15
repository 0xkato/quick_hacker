from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from database import get_db
from middleware.auth import AuthContext, require_auth
from models.schemas import AgentStatus
from services.tool_core import ToolCore


async def mock_require_auth() -> AuthContext:
    return AuthContext(is_authenticated=True, is_legacy_token=True)


async def mock_get_db():
    yield Mock()


class FakeCodexCLIProvider:
    prompts: list[str] = []

    def __init__(
        self,
        *,
        repo_path: str,
        project_id: str,
        agent_id: str,
        model: str,
        codex_path: str = "codex",
        mcp_server_name: str = "quickhack",
    ) -> None:
        self.repo_path = repo_path
        self.project_id = project_id
        self.agent_id = agent_id
        self.model = model
        self.codex_path = codex_path
        self.mcp_server_name = mcp_server_name
        self.session_id: str | None = None

    async def start_session(self, *, resume_session_id: str | None = None) -> str:
        if resume_session_id:
            self.session_id = resume_session_id
        return self.session_id or ""

    def write_turn_limits(self, *, max_runtime_s: float) -> None:
        return None

    def set_cancelled(self, cancelled: bool) -> None:
        return None

    async def interrupt(self) -> None:
        return None

    async def run_turn(self, *, prompt: str, on_event=None):
        self.__class__.prompts.append(prompt)
        # Establish a session.
        if not self.session_id:
            self.session_id = "thread-test-123"
            if on_event:
                on_event({"type": "session_started", "session_id": self.session_id})

        tool_core = ToolCore(repo_path=self.repo_path, project_id=self.project_id, agent_id=self.agent_id)

        # Persist a sink signal via ToolCore (simulating MCP server execution).
        signal_call_id = "tool_call_signal_1"
        signal_args = {
            "kind": "sink",
            "label": "os.system usage",
            "file_path": "app.py",
            "line_number": 10,
            "llm_risk_tier": "A",
            "llm_score": 90,
            "llm_reasoning": "Direct shell execution sink.",
            "metadata": {"sink_type": "exec"},
        }
        if on_event:
            on_event(
                {
                    "type": "tool_call",
                    "id": signal_call_id,
                    "name": "mcp__quickhack__upsert_sink_signal",
                    "args": signal_args,
                }
            )
        signal_result = await tool_core.upsert_sink_signal(**signal_args)
        if on_event:
            on_event(
                {
                    "type": "tool_result",
                    "tool_use_id": signal_call_id,
                    "tool_name": "mcp__quickhack__upsert_sink_signal",
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(signal_result)}],
                        "isError": False,
                    },
                    "is_error": False,
                }
            )

        # Emit a report_finding tool call result.
        finding_call_id = "tool_call_finding_1"
        finding_args = {
            "severity": "high",
            "title": "Command injection via os.system",
            "vulnerability_type": "command_injection",
            "file_path": "app.py",
            "line_start": 10,
            "vulnerable_code": "os.system(user_input)",
            "description": "Untrusted input reaches os.system.",
            "confidence": 0.8,
            "cwe_id": "CWE-78",
            "recommended_fix": "Avoid shell execution or validate/escape input.",
        }
        if on_event:
            on_event(
                {
                    "type": "tool_call",
                    "id": finding_call_id,
                    "name": "mcp__quickhack__report_finding",
                    "args": finding_args,
                }
            )
        finding_result = await tool_core.report_finding(**finding_args)
        if on_event:
            on_event(
                {
                    "type": "tool_result",
                    "tool_use_id": finding_call_id,
                    "tool_name": "mcp__quickhack__report_finding",
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(finding_result)}],
                        "isError": False,
                    },
                    "is_error": False,
                }
            )

        if on_event:
            on_event({"type": "agent_text", "text": "Analysis complete. No more findings."})
            on_event({"type": "turn_complete", "session_id": self.session_id, "usage": None})

        return []


@pytest.mark.integration
def test_codex_cli_agent_via_api_creates_sink_signal_and_finding(tmp_path: Path, monkeypatch):
    from main import app

    data_dir = tmp_path / "data"
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    repo_path = tmp_path / "repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    (repo_path / "app.py").write_text("import os\nos.system('echo hi')\n", encoding="utf-8")

    # Ensure the API uses mocked auth + db, and doesn't try to initialize a real DB.
    app.dependency_overrides[require_auth] = mock_require_auth
    app.dependency_overrides[get_db] = mock_get_db

    from services.agent_orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator()

    with (
        patch("routers.agents.orchestrator", orchestrator),
        patch("services.agent_orchestrator.project_service") as mock_project_service,
        patch("services.agent_orchestrator.get_user_api_key_for_provider", new=AsyncMock(return_value=None)),
        patch("services.agent_orchestrator.CodexCLIProvider", FakeCodexCLIProvider),
        patch("main.init_db", new=AsyncMock()),
        patch("main.initialize_triage_availability", new=AsyncMock()),
        patch("main.settings_service.initialize", new=AsyncMock()),
        patch("main.project_service.initialize", new=AsyncMock()),
    ):
        mock_project_service.get_project_repo_path.return_value = str(repo_path)

        with TestClient(app) as client:
            create_payload = {
                "repo_id": "proj_codex_api",
                "agent_type": "deep_audit",
                "provider_config": {"provider": "codex_cli", "model": "gpt-5.2-codex"},
                # Custom timing override so tests don't wait on tier floors.
                "time_budget_seconds": 60,
            }

            created = client.post("/api/agents", json=create_payload)
            assert created.status_code == 200, created.text
            agent_id = created.json()["id"]

            started = client.post(f"/api/agents/{agent_id}/start")
            assert started.status_code == 200, started.text

            # Poll for completion (FakeCodexCLIProvider finishes quickly).
            deadline = time.time() + 2.0
            status = None
            while time.time() < deadline:
                resp = client.get(f"/api/agents/{agent_id}")
                assert resp.status_code == 200
                status = resp.json()["status"]
                if status in (AgentStatus.COMPLETED.value, AgentStatus.FAILED.value, AgentStatus.CANCELLED.value):
                    break
                time.sleep(0.05)

            assert status == AgentStatus.COMPLETED.value

            # Finding should be available via the agent findings endpoint.
            findings = client.get(f"/api/agents/{agent_id}/findings")
            assert findings.status_code == 200
            findings_data = findings.json()
            assert len(findings_data) == 1
            assert findings_data[0]["title"] == "Command injection via os.system"
            # Codex CLI path runs the strict triage pipeline (disposition populated).
            assert findings_data[0].get("disposition") is not None
            assert any("DEEP AUDIT MODE" in p for p in FakeCodexCLIProvider.prompts)

    # Sink signals are persisted per project.
    sink_path = data_dir / "projects" / "proj_codex_api" / "sink_signals.json"
    assert sink_path.exists()
    raw = json.loads(sink_path.read_text(encoding="utf-8"))
    assert "signals" in raw
    assert any(sig.get("label") == "os.system usage" for sig in raw["signals"])
