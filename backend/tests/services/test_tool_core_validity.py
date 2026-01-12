import pytest
from pathlib import Path
from services.tool_core import ToolCore


@pytest.fixture
def tool_core(tmp_path):
    """Create a ToolCore instance for testing."""
    return ToolCore(
        repo_path=str(tmp_path),
        project_id="test-project"
    )


def test_get_validity_checklist_sql_injection(tool_core):
    """Test getting SQL injection validity checklist."""
    result = tool_core.get_validity_checklist("sql_injection")

    assert result["success"] is True
    assert result["class"] == "sql_injection"
    assert "# SQL Injection Validity Checklist" in result["content"]
    assert "Required Conditions" in result["content"]
    assert "Evidence Requirements" in result["content"]


def test_get_validity_checklist_disprove(tool_core):
    """Test getting disprove checklist."""
    result = tool_core.get_validity_checklist("disprove")

    assert result["success"] is True
    assert result["class"] == "disprove"
    assert "# Disprove-First Self-Critique Checklist" in result["content"]
    assert "6 Disprove Questions" in result["content"]


def test_get_validity_checklist_invalid_class(tool_core):
    """Test getting checklist for invalid class returns error."""
    result = tool_core.get_validity_checklist("nonexistent_class")

    assert result["success"] is False
    assert "error" in result
    assert "unknown" in result["error"].lower() or "not found" in result["error"].lower()


def test_get_validity_checklist_all_valid_classes(tool_core):
    """Test all 8 vulnerability classes + disprove checklist exist."""
    valid_classes = [
        "sql_injection",
        "command_execution",
        "path_traversal",
        "ssrf",
        "xss",
        "deserialization",
        "auth_bypass",
        "sensitive_data_exposure",
        "disprove"
    ]

    for vuln_class in valid_classes:
        result = tool_core.get_validity_checklist(vuln_class)
        assert result["success"] is True, f"Failed for {vuln_class}"
        assert result["class"] == vuln_class
        assert len(result["content"]) > 100  # Non-empty content
