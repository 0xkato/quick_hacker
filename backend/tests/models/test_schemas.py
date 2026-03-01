import pytest
from datetime import datetime


def test_validation_result_creation():
    """Test ValidationResult model with all fields."""
    from models.schemas import ValidationResult

    result = ValidationResult(
        is_valid=True,
        reasoning=["Finding has clear security impact", "Exploit path is proven"],
        categories=["security_issue"],
        investigation_steps=["Read file at line 42", "Checked function signature"],
        confidence=95,
        timestamp=datetime(2024, 1, 1, 12, 0, 0)
    )

    assert result.is_valid is True
    assert len(result.reasoning) == 2
    assert result.reasoning[0] == "Finding has clear security impact"
    assert result.categories == ["security_issue"]
    assert len(result.investigation_steps) == 2
    assert result.confidence == 95
    assert result.timestamp == datetime(2024, 1, 1, 12, 0, 0)


def test_validation_result_minimal():
    """Test ValidationResult with only required fields."""
    from models.schemas import ValidationResult

    result = ValidationResult(
        is_valid=False,
        reasoning=["Not a real security issue"],
        categories=["hardening", "by_design"]
    )

    assert result.is_valid is False
    assert result.reasoning == ["Not a real security issue"]
    assert result.categories == ["hardening", "by_design"]
    assert result.investigation_steps is None
    assert result.confidence is None
    assert isinstance(result.timestamp, datetime)


def test_finding_with_validation_result():
    """Test Finding model with validation_result field."""
    from models.schemas import Finding, ValidationResult, Severity

    validation = ValidationResult(
        is_valid=True,
        reasoning=["Clear exploit path", "Impact is high"],
        categories=["security_issue"],
        confidence=90
    )

    finding = Finding(
        id="test-123",
        agent_id="agent-1",
        repo_id="repo-1",
        severity=Severity.HIGH,
        title="SQL Injection",
        description="User input flows to SQL query",
        file_path="/app/routes.py",
        line_start=42,
        vulnerability_type="sql_injection",
        confidence=0.9,
        created_at=datetime(2024, 1, 1, 12, 0, 0),
        validation_result=validation
    )

    assert finding.validation_result is not None
    assert finding.validation_result.is_valid is True
    assert finding.validation_result.confidence == 90
    assert len(finding.validation_result.reasoning) == 2


def test_finding_without_validation_result():
    """Test Finding model without validation_result (None)."""
    from models.schemas import Finding, Severity

    finding = Finding(
        id="test-456",
        agent_id="agent-1",
        repo_id="repo-1",
        severity=Severity.MEDIUM,
        title="Hardcoded secret",
        description="API key in code",
        file_path="/app/config.py",
        line_start=10,
        vulnerability_type="hardcoded_secret",
        confidence=0.8,
        created_at=datetime(2024, 1, 1, 12, 0, 0)
    )

    assert finding.validation_result is None


def test_protocol_policy_with_validation_settings():
    """Test ProtocolPolicy with default LLM validation settings."""
    from models.schemas import ProtocolPolicy

    policy = ProtocolPolicy(
        id="osvrp_strict",
        display_name="Open Source VRP Strict"
    )

    # Verify defaults
    assert policy.enable_llm_validation is True
    assert policy.validation_criticism_level == "high"
    assert policy.validation_model is None
    assert policy.validation_timeout_seconds == 120
    assert policy.validation_fallback_on_error == "invalid"


def test_protocol_policy_validation_disabled():
    """Test ProtocolPolicy with LLM validation disabled."""
    from models.schemas import ProtocolPolicy

    policy = ProtocolPolicy(
        id="no_validation_policy",
        display_name="No Validation Policy",
        enable_llm_validation=False
    )

    assert policy.enable_llm_validation is False
    assert policy.validation_criticism_level == "high"  # Still has default
    assert policy.validation_model is None
    assert policy.validation_timeout_seconds == 120
    assert policy.validation_fallback_on_error == "invalid"


def test_protocol_policy_with_custom_llm_validation():
    """Test ProtocolPolicy with custom LLM validation settings."""
    from models.schemas import ProtocolPolicy

    policy = ProtocolPolicy(
        id="internal_audit",
        display_name="Internal Audit",
        enable_llm_validation=False,
        validation_criticism_level="medium",
        validation_model="claude-opus-4-6",
        validation_timeout_seconds=60,
        validation_fallback_on_error="skip"
    )

    assert policy.enable_llm_validation is False
    assert policy.validation_criticism_level == "medium"
    assert policy.validation_model == "claude-opus-4-6"
    assert policy.validation_timeout_seconds == 60
    assert policy.validation_fallback_on_error == "skip"


def test_protocol_policy_validation_criticism_level_literal():
    """Test ProtocolPolicy validation_criticism_level accepts only valid literals."""
    from models.schemas import ProtocolPolicy
    from pydantic import ValidationError

    # Valid values should work
    for level in ["high", "medium", "low"]:
        policy = ProtocolPolicy(
            id="test",
            display_name="Test",
            validation_criticism_level=level
        )
        assert policy.validation_criticism_level == level

    # Invalid value should raise ValidationError
    with pytest.raises(ValidationError) as exc_info:
        ProtocolPolicy(
            id="test",
            display_name="Test",
            validation_criticism_level="invalid"
        )
    assert "validation_criticism_level" in str(exc_info.value)


def test_protocol_policy_validation_fallback_literal():
    """Test ProtocolPolicy validation_fallback_on_error accepts only valid literals."""
    from models.schemas import ProtocolPolicy
    from pydantic import ValidationError

    # Valid values should work
    for fallback in ["invalid", "valid", "skip"]:
        policy = ProtocolPolicy(
            id="test",
            display_name="Test",
            validation_fallback_on_error=fallback
        )
        assert policy.validation_fallback_on_error == fallback

    # Invalid value should raise ValidationError
    with pytest.raises(ValidationError) as exc_info:
        ProtocolPolicy(
            id="test",
            display_name="Test",
            validation_fallback_on_error="unknown"
        )
    assert "validation_fallback_on_error" in str(exc_info.value)


def test_proof_checklist_exec_reasoning_fields():
    """Verify ProofChecklist accepts optional exec reasoning fields."""
    from models.schemas import ProofChecklist, ChecklistItem, ChecklistStatus

    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        sink_present=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        dataflow_evidenced=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        reachable=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        boundary_crossed=ChecklistItem(
            value=False, status=ChecklistStatus.DISPROVEN, reason="Test"
        ),
        not_only_misconfig=ChecklistItem(
            value=True, status=ChecklistStatus.PROVEN, reason="Test"
        ),
        exec_sink_reason="exec() at line 42",
        feature_intent_reason="Feature intent PROVEN: path=/pipelines/",
        auth_bypass_reason="Auth bypass not PROVEN"
    )

    assert checklist.exec_sink_reason == "exec() at line 42"
    assert checklist.feature_intent_reason == "Feature intent PROVEN: path=/pipelines/"
    assert checklist.auth_bypass_reason == "Auth bypass not PROVEN"
