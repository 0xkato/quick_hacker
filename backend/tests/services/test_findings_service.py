"""Tests for findings persistence service wiring."""

from datetime import datetime, timezone
import importlib

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


def test_findings_service_importable():
    """`services.findings_service` imports (regression for missing get_session)."""
    module = importlib.import_module("services.findings_service")
    assert hasattr(module, "findings_service")


def test_findings_service_metadata_mapping_uses_metadata_attr():
    """Service maps SQLAlchemy `metadata_` → Pydantic `metadata`."""
    findings_module = importlib.import_module("services.findings_service")
    models = importlib.import_module("database.models")

    service = findings_module.findings_service
    DBFinding = models.Finding

    db_finding = DBFinding(
        id="finding_1",
        agent_id="agent_1",
        repo_id="repo_1",
        severity="high",
        title="Test finding",
        description="Test description",
        file_path="app.py",
        line_start=1,
        vulnerability_type="TestType",
        confidence=0.5,
        created_at=datetime.now(timezone.utc),
        metadata_={"persisted": True},
        source_trace=["a", "b"],
    )

    pydantic_finding = service._to_pydantic(db_finding)
    assert pydantic_finding.metadata == {"persisted": True}


@pytest.mark.asyncio
async def test_create_finding_raises_on_db_failure():
    """_create_finding must propagate DB errors, not swallow them."""
    from agents.react_agent import ReActSecurityAgent

    # Build a minimal mock agent with the _create_finding method
    agent = MagicMock(spec=ReActSecurityAgent)
    agent.id = "test-agent"
    agent.repo_id = "test-repo"
    agent.agent_type = MagicMock()
    agent.agent_type.value = "react"
    agent.findings = []
    agent._log = MagicMock()
    agent._broadcast = MagicMock()

    # Bind the real method to our mock
    agent._create_finding = ReActSecurityAgent._create_finding.__get__(agent, type(agent))

    finding_data = {
        "title": "Test XSS",
        "severity": "high",
        "description": "XSS in input",
        "file_path": "app.py",
        "line_start": 10,
        "vulnerability_type": "XSS",
    }

    with patch("agents.react_agent.findings_service") as mock_svc:
        mock_svc.save_finding = AsyncMock(side_effect=Exception("DB connection refused"))

        with pytest.raises(Exception, match="DB connection refused"):
            await agent._create_finding(finding_data)

    # Finding should NOT be in memory if DB save failed
    assert len(agent.findings) == 0
