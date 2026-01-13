import pytest
from services.prompt_router import PromptRouter
from agents.deep_audit.case_builder import (
    CaseBuilder,
    _map_signal_type_to_category,
    assemble_auditor_prompt_for_signal,
)
from agents.deep_audit.subagents import get_auditor_prompt

def test_case_builder_loads_validity_checklist_for_sql_injection():
    """Test that case builder loads SQL injection validity checklist."""
    # Test the _assemble_prompt_for_category method on CaseBuilder instance
    case_builder = CaseBuilder()
    prompt = case_builder._assemble_prompt_for_category(
        category="SQL_INJECTION",
        stage="validate_exploitability",
        task="Analyze potential SQL injection"
    )

    # Verify prompt includes validity checklist
    assert "SQL Injection Proof Checklist" in prompt
    assert "sink_present" in prompt

def test_case_builder_loads_validity_checklist_for_xss():
    """Test that case builder loads XSS validity checklist."""
    # Test the _assemble_prompt_for_category method on CaseBuilder instance
    case_builder = CaseBuilder()
    prompt = case_builder._assemble_prompt_for_category(
        category="XSS",
        stage="validate_exploitability",
        task="Analyze potential XSS"
    )

    # Verify prompt includes XSS validity checklist
    assert "XSS" in prompt
    assert "security_control_bypassed" in prompt

def test_map_signal_type_to_category():
    """Test signal_type to category mapping."""
    # Test SQL injection mapping
    assert _map_signal_type_to_category("sql_injection_candidate") == "SQL_INJECTION"
    assert _map_signal_type_to_category("SQL_INJECTION") == "SQL_INJECTION"

    # Test XSS mapping
    assert _map_signal_type_to_category("xss_candidate") == "XSS"
    assert _map_signal_type_to_category("cross_site_scripting_candidate") == "XSS"

    # Test SSRF mapping
    assert _map_signal_type_to_category("ssrf_candidate") == "SSRF"

    # Test unknown type
    assert _map_signal_type_to_category("unknown_type") is None

def test_map_signal_type_to_category_handles_none():
    """Test that None signal_type returns None without crashing."""
    assert _map_signal_type_to_category(None) is None

def test_assemble_auditor_prompt_for_sql_injection_signal():
    """Test assembling auditor prompt with SQL injection validity checklist."""
    signal = {
        "signal_id": "test_signal_1",
        "signal_type": "sql_injection_candidate",
        "file_path": "app/routes.py",
        "line_range": [45, 52],
    }
    case_file_path = "/memories/cases/test_case_1.md"

    prompt = assemble_auditor_prompt_for_signal(signal, case_file_path)

    # Verify prompt includes the case file path
    assert case_file_path in prompt

    # Verify prompt includes SQL injection validity checklist
    assert "SQL Injection Proof Checklist" in prompt
    assert "sink_present" in prompt
    assert "source_controlled_input" in prompt
    assert "dataflow_evidenced" in prompt

def test_assemble_auditor_prompt_for_xss_signal():
    """Test assembling auditor prompt with XSS validity checklist."""
    signal = {
        "signal_id": "test_signal_2",
        "signal_type": "xss_candidate",
        "file_path": "app/templates.py",
        "line_range": [30, 35],
    }
    case_file_path = "/memories/cases/test_case_2.md"

    prompt = assemble_auditor_prompt_for_signal(signal, case_file_path)

    # Verify prompt includes the case file path
    assert case_file_path in prompt

    # Verify prompt includes XSS validity checklist with security_control_bypassed
    assert "XSS" in prompt
    assert "sink_present" in prompt
    assert "security_control_bypassed" in prompt

def test_assemble_auditor_prompt_for_unknown_signal_type():
    """Test assembling auditor prompt for unknown signal type (fallback)."""
    signal = {
        "signal_id": "test_signal_3",
        "signal_type": "unknown_vulnerability_type",
        "file_path": "app/unknown.py",
        "line_range": [10, 20],
    }
    case_file_path = "/memories/cases/test_case_3.md"

    prompt = assemble_auditor_prompt_for_signal(signal, case_file_path)

    # Verify prompt includes the case file path
    assert case_file_path in prompt

    # Verify prompt does NOT include validity checklist (fallback mode)
    assert "SQL Injection Proof Checklist" not in prompt
    assert "XSS" not in prompt

    # But should still have basic auditor instructions
    assert "Auditor subagent" in prompt

def test_assemble_auditor_prompt_for_none_signal_type():
    """Test assembling auditor prompt when signal_type is None (fallback)."""
    signal = {
        "signal_id": "test_signal_none",
        "signal_type": None,
        "file_path": "app/unknown.py",
        "line_range": [10, 20],
    }
    case_file_path = "/memories/cases/test_case_none.md"

    prompt = assemble_auditor_prompt_for_signal(signal, case_file_path)

    # Verify prompt includes the case file path
    assert case_file_path in prompt

    # Verify prompt does NOT include validity checklist (fallback mode)
    assert "SQL Injection Proof Checklist" not in prompt
    assert "XSS" not in prompt

    # But should still have basic auditor instructions
    assert "Auditor subagent" in prompt

def test_get_auditor_prompt_with_signal():
    """Test get_auditor_prompt wrapper with signal parameter."""
    signal = {
        "signal_id": "test_signal",
        "signal_type": "sql_injection_candidate",
    }
    case_file_path = "/memories/cases/test.md"

    prompt = get_auditor_prompt(case_file_path, signal=signal)

    # Should use PromptRouter integration
    assert "SQL Injection Proof Checklist" in prompt
    assert "sink_present" in prompt
    assert case_file_path in prompt

def test_get_auditor_prompt_without_signal():
    """Test get_auditor_prompt wrapper without signal (backward compatibility)."""
    case_file_path = "/memories/cases/test.md"

    prompt = get_auditor_prompt(case_file_path)

    # Should use legacy template
    assert case_file_path in prompt
    assert "Auditor subagent" in prompt

    # Should NOT include PromptRouter checklist
    assert "SQL Injection Proof Checklist" not in prompt
