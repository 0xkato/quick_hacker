"""Tests for FindingClassification enum and classification gate fields."""

import pytest
from pydantic import ValidationError

from models.schemas import (
    Finding,
    FindingCreate,
    FindingClassification,
    Severity,
)


class TestFindingClassificationEnum:
    """Tests for the FindingClassification enum."""

    def test_enum_has_security_issue(self):
        """Enum should have SECURITY_ISSUE value."""
        assert FindingClassification.SECURITY_ISSUE == "security_issue"

    def test_enum_has_bug(self):
        """Enum should have BUG value."""
        assert FindingClassification.BUG == "bug"

    def test_enum_has_misconfiguration(self):
        """Enum should have MISCONFIGURATION value."""
        assert FindingClassification.MISCONFIGURATION == "misconfiguration"

    def test_enum_has_hardening(self):
        """Enum should have HARDENING value."""
        assert FindingClassification.HARDENING == "hardening"

    def test_enum_has_exactly_four_values(self):
        """Enum should have exactly 4 values."""
        values = list(FindingClassification)
        assert len(values) == 4


class TestFindingCreateClassificationFields:
    """Tests for classification fields on FindingCreate."""

    def test_accepts_classification_field(self):
        """FindingCreate should accept classification field."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            classification=FindingClassification.BUG,
        )
        assert finding.classification == FindingClassification.BUG

    def test_classification_defaults_to_security_issue(self):
        """Classification should default to SECURITY_ISSUE."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
        )
        assert finding.classification == FindingClassification.SECURITY_ISSUE

    def test_accepts_config_dependent_field(self):
        """FindingCreate should accept config_dependent field."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            config_dependent=True,
        )
        assert finding.config_dependent is True

    def test_config_dependent_defaults_to_false(self):
        """config_dependent should default to False."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
        )
        assert finding.config_dependent is False

    def test_accepts_config_flag_field(self):
        """FindingCreate should accept config_flag field."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            config_flag="ENABLE_DEBUG",
        )
        assert finding.config_flag == "ENABLE_DEBUG"

    def test_config_flag_defaults_to_none(self):
        """config_flag should default to None."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
        )
        assert finding.config_flag is None

    def test_accepts_default_secure_field(self):
        """FindingCreate should accept default_secure field."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            default_secure=True,
        )
        assert finding.default_secure is True

    def test_default_secure_defaults_to_none(self):
        """default_secure should default to None."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
        )
        assert finding.default_secure is None

    def test_accepts_contradiction_present_field(self):
        """FindingCreate should accept contradiction_present field."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            contradiction_present=True,
        )
        assert finding.contradiction_present is True

    def test_contradiction_present_defaults_to_false(self):
        """contradiction_present should default to False."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
        )
        assert finding.contradiction_present is False

    def test_accepts_classification_reasoning_field(self):
        """FindingCreate should accept classification_reasoning field."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            classification_reasoning="This is a real SQL injection",
        )
        assert finding.classification_reasoning == "This is a real SQL injection"

    def test_classification_reasoning_defaults_to_empty_string(self):
        """classification_reasoning should default to empty string."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
        )
        assert finding.classification_reasoning == ""


class TestFixTypeLiteral:
    """Tests for fix_type literal field."""

    def test_accepts_code_fix_type(self):
        """FindingCreate should accept fix_type='code'."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            fix_type="code",
        )
        assert finding.fix_type == "code"

    def test_accepts_config_fix_type(self):
        """FindingCreate should accept fix_type='config'."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            fix_type="config",
        )
        assert finding.fix_type == "config"

    def test_accepts_docs_fix_type(self):
        """FindingCreate should accept fix_type='docs'."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            fix_type="docs",
        )
        assert finding.fix_type == "docs"

    def test_accepts_warning_fix_type(self):
        """FindingCreate should accept fix_type='warning'."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            fix_type="warning",
        )
        assert finding.fix_type == "warning"

    def test_fix_type_defaults_to_code(self):
        """fix_type should default to 'code'."""
        finding = FindingCreate(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
        )
        assert finding.fix_type == "code"

    def test_rejects_invalid_fix_type(self):
        """FindingCreate should reject invalid fix_type values."""
        with pytest.raises(ValidationError):
            FindingCreate(
                severity=Severity.HIGH,
                title="Test",
                description="Test description",
                file_path="/test.py",
                line_start=1,
                vulnerability_type="sql_injection",
                confidence=0.9,
                fix_type="invalid",
            )


class TestFindingModelClassificationFields:
    """Tests for classification fields on Finding model."""

    def test_finding_has_classification_field(self):
        """Finding model should include classification field."""
        from datetime import datetime

        finding = Finding(
            id="test-id",
            agent_id="agent-id",
            repo_id="repo-id",
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            created_at=datetime.utcnow(),
            classification=FindingClassification.MISCONFIGURATION,
        )
        assert finding.classification == FindingClassification.MISCONFIGURATION

    def test_finding_has_config_dependent_field(self):
        """Finding model should include config_dependent field."""
        from datetime import datetime

        finding = Finding(
            id="test-id",
            agent_id="agent-id",
            repo_id="repo-id",
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            created_at=datetime.utcnow(),
            config_dependent=True,
        )
        assert finding.config_dependent is True

    def test_finding_has_fix_type_field(self):
        """Finding model should include fix_type field."""
        from datetime import datetime

        finding = Finding(
            id="test-id",
            agent_id="agent-id",
            repo_id="repo-id",
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            created_at=datetime.utcnow(),
            fix_type="config",
        )
        assert finding.fix_type == "config"

    def test_finding_has_all_classification_fields(self):
        """Finding model should include all classification gate fields."""
        from datetime import datetime

        finding = Finding(
            id="test-id",
            agent_id="agent-id",
            repo_id="repo-id",
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
            file_path="/test.py",
            line_start=1,
            vulnerability_type="sql_injection",
            confidence=0.9,
            created_at=datetime.utcnow(),
            classification=FindingClassification.HARDENING,
            config_dependent=True,
            config_flag="DEBUG_MODE",
            default_secure=False,
            contradiction_present=True,
            fix_type="warning",
            classification_reasoning="This is just a hardening suggestion",
        )
        assert finding.classification == FindingClassification.HARDENING
        assert finding.config_dependent is True
        assert finding.config_flag == "DEBUG_MODE"
        assert finding.default_secure is False
        assert finding.contradiction_present is True
        assert finding.fix_type == "warning"
        assert finding.classification_reasoning == "This is just a hardening suggestion"
