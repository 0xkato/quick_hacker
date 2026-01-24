from __future__ import annotations

from pathlib import Path

from agents.base_agent import BaseAgent
from agents.react import ReActSecurityAgent
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig, ProviderType
from services.flow_service import flow_service


class DummyAgent(BaseAgent):
    agent_type = AgentType.CUSTOM

    async def analyze(self):
        return None


def test_base_agent_snapshot_coerces_types_and_persists_codex_session_id(tmp_path: Path) -> None:
    request = AgentCreateRequest(
        repo_id="proj_snapshot",
        agent_type=AgentType.CUSTOM,
        provider_config=ProviderConfig(provider=ProviderType.CODEX_CLI, model="gpt-5.2-codex"),
        time_budget_seconds=60,
    )
    agent = DummyAgent(request=request, repo_path=str(tmp_path))

    # Simulate DeepAuditSupervisor overriding types.
    agent.repo_path = Path(tmp_path)
    agent.files_analyzed = ["a.py", "b.py"]

    # Codex session id is required for pause/resume.
    agent._codex_session_id = "thread-123"

    snapshot = agent.get_state_snapshot()
    assert snapshot.repo_path == str(tmp_path)
    assert snapshot.files_analyzed == 2
    assert snapshot.provider_config["provider"] == "codex_cli"
    assert snapshot.provider_config["model"] == "gpt-5.2-codex"
    assert snapshot.provider_config["session_id"] == "thread-123"


def test_base_agent_snapshot_persists_flow_state(tmp_path: Path) -> None:
    request = AgentCreateRequest(
        repo_id="proj_snapshot_flow",
        agent_type=AgentType.CUSTOM,
        provider_config=ProviderConfig(provider=ProviderType.CODEX_CLI, model="gpt-5.2-codex"),
        time_budget_seconds=60,
    )
    agent = DummyAgent(request=request, repo_path=str(tmp_path))

    try:
        flow_service.initialize_flow(agent.id)
        start = flow_service.add_node(agent.id, "user_input", "Start", {})
        flow_service.add_node(agent.id, "analysis", "Done", {}, parent_id=start.id)

        snapshot = agent.get_state_snapshot()
        assert len(snapshot.flow_nodes) >= 2
        assert len(snapshot.flow_edges) >= 1
    finally:
        flow_service.clear_flow(agent.id)


def test_react_agent_snapshot_persists_codex_session_id(tmp_path: Path) -> None:
    request = AgentCreateRequest(
        repo_id="proj_react_snapshot",
        agent_type=AgentType.CUSTOM,
        provider_config=ProviderConfig(provider=ProviderType.CODEX_CLI, model="gpt-5.2-codex"),
        time_budget_seconds=60,
    )
    agent = ReActSecurityAgent(request=request, repo_path=str(tmp_path))
    agent._codex_session_id = "thread-react-456"

    snapshot = agent.get_state_snapshot()
    assert snapshot.provider_config["provider"] == "codex_cli"
    assert snapshot.provider_config["session_id"] == "thread-react-456"
