"""Tests for findings persistence service wiring."""

from datetime import datetime, timezone
import importlib


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
