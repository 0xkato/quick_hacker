"""Integration tests for Deep Audit supervisor."""

import pytest
import uuid
from pathlib import Path
from models.schemas import AgentCreateRequest, AgentType, AgentStatus
from services.agent_orchestrator import orchestrator


@pytest.mark.asyncio
async def test_create_deep_audit_agent(tmp_path):
    """Test creating a deep audit agent via orchestrator."""
    # Create a minimal test repo
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()
    (repo_path / "main.py").write_text("print('hello')")

    # Mock project service
    from services.project_service import ProjectService
    from unittest.mock import patch

    with patch.object(ProjectService, 'get_project_repo_path', return_value=str(repo_path)):
        # Create agent request
        request = AgentCreateRequest(
            repo_id="test_proj",
            agent_type=AgentType.DEEP_AUDIT,
            scan_tier="quick",
        )

        # Mock auth context
        from middleware.auth import AuthContext
        test_user_id = uuid.uuid4()
        auth_context = AuthContext(user_id=test_user_id, is_authenticated=True)

        # Create agent
        agent = await orchestrator.create_agent(request, auth_context, db=None)

        assert agent is not None
        assert agent.agent_type == AgentType.DEEP_AUDIT
        assert agent.status == AgentStatus.PENDING


@pytest.mark.asyncio
async def test_deep_audit_supervisor_graph_executes(tmp_path):
    """Test that supervisor graph can execute (basic smoke test)."""
    from agents.deep_audit import DeepAuditSupervisor
    from models.schemas import AgentCreateRequest, AgentType

    # Create test repo
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()

    # Create minimal project structure
    project_root = tmp_path / "projects" / "test_proj"
    (project_root / "repo").mkdir(parents=True)

    # Mock DATA_BASE_PATH
    import agents.deep_audit.filesystem as fs_module
    original_base = fs_module.DATA_BASE_PATH
    fs_module.DATA_BASE_PATH = tmp_path / "projects"

    try:
        request = AgentCreateRequest(
            repo_id="test_proj",
            agent_type=AgentType.DEEP_AUDIT,
            scan_tier="quick",
        )

        supervisor = DeepAuditSupervisor(
            request=request,
            repo_path=str(repo_path),
            on_message=lambda msg: None,
        )

        # Run graph (should complete without errors)
        findings = await supervisor.run()

        assert supervisor.status == AgentStatus.COMPLETED
        assert isinstance(findings, list)

    finally:
        fs_module.DATA_BASE_PATH = original_base
