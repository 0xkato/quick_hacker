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


def test_findings_service_has_count_method():
    """FindingsService exposes get_findings_count_by_agent for efficient counting."""
    from services.findings_service import findings_service
    assert hasattr(findings_service, "get_findings_count_by_agent")
    assert callable(findings_service.get_findings_count_by_agent)


import inspect


def test_report_service_generate_report_accepts_findings_param():
    """generate_report() must accept an optional `findings` parameter."""
    from services.report_service import ReportService
    sig = inspect.signature(ReportService.generate_report)
    params = list(sig.parameters.keys())
    assert "findings" in params, f"generate_report params: {params}"


def test_report_service_uses_findings_param_over_agent_findings():
    """When `findings` is passed, generate_report uses it instead of agent.findings."""
    from services.report_service import ReportService
    from models.schemas import Finding, Severity
    from datetime import datetime

    service = ReportService()

    injected_finding = Finding(
        id="db-f1",
        agent_id="a1",
        repo_id="r1",
        severity=Severity.CRITICAL,
        title="DB Finding",
        description="From DB",
        file_path="vuln.py",
        line_start=1,
        vulnerability_type="SQLi",
        confidence=0.9,
        created_at=datetime.utcnow(),
    )

    agent = MagicMock()
    agent.id = "a1"
    agent.repo_id = "r1"
    agent.repo_path = "/tmp/repo"
    agent.name = "test"
    agent.agent_type = MagicMock()
    agent.agent_type.value = "react"
    agent.started_at = datetime.utcnow()
    agent.completed_at = datetime.utcnow()
    agent.findings = []  # Agent memory is EMPTY

    with patch("services.observability_service.observability_service") as mock_obs, \
         patch("services.flow_service.flow_service"), \
         patch.object(service, "_save_report_files"), \
         patch.object(service, "_broadcast"):
        mock_obs.get_stats.return_value = {}
        usage = MagicMock()
        usage.prompt_tokens = 0
        usage.completion_tokens = 0
        mock_obs.get_token_usage.return_value = usage

        report = service.generate_report(agent, findings=[injected_finding])

    # Report must contain the DB finding, not the empty agent.findings
    assert len(report.findings_summary) == 1
    assert report.findings_summary[0].id == "db-f1"
    assert report.findings_summary[0].title == "DB Finding"


def test_progress_broadcast_uses_db_count():
    """Progress broadcast should report findings_count from DB, not len(self.findings)."""
    with open("agents/react_agent.py") as f:
        source = f.read()

    # Find the iteration PROGRESS broadcast (contains "iteration" and "findings_count")
    # This is the broadcast with "max_iterations" — the one we need to fix
    marker = '"max_iterations"'
    idx = source.index(marker)
    # Get surrounding context (the full broadcast dict)
    progress_section = source[max(0, idx - 200):idx + 300]
    assert "len(self.findings)" not in progress_section, \
        "Progress broadcast still uses len(self.findings) — should use self._db_findings_count"
