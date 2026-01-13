"""
Unit tests for blocking_gaps.py - Category-aware blocking gaps service.

Tests ensure:
1. Default blocking gaps for standard vulnerability types
2. Rule 3b: exec/eval exception with security_control_bypassed
3. Special case handling for SECRETS category
4. Only UNKNOWN required fields are returned as blocking gaps
"""

import pytest
from models.schemas import ProofChecklist, ChecklistItem, ChecklistStatus, VulnerabilityCategory
from services.blocking_gaps import get_blocking_gaps_for_category


def test_default_blocking_gaps():
    """Test default blocking gaps for SQL injection."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint is reachable"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    gaps = get_blocking_gaps_for_category("SQL_INJECTION", checklist)

    # Default: Only UNKNOWN required fields should be in gaps
    # sink_present, reachable, not_only_misconfig are already PROVEN, so not blocking
    assert "source_controlled_input" in gaps
    assert "dataflow_evidenced" in gaps
    assert "boundary_crossed" in gaps
    assert "sink_present" not in gaps  # Already proven
    assert "reachable" not in gaps  # Already proven
    assert "not_only_misconfig" not in gaps  # Already proven


def test_exec_eval_exception_with_auth_bypass():
    """Test Rule 3b: exec/eval with security_control_bypassed can replace boundary_crossed."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input controlled"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="exec() found"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Dataflow confirmed"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Route is reachable"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Auth bypass confirmed")
    )

    gaps = get_blocking_gaps_for_category("CODE_INJECTION", checklist)

    # Should require security_control_bypassed instead of boundary_crossed
    # Since security_control_bypassed is PROVEN, no gaps should exist
    assert len(gaps) == 0
    assert "boundary_crossed" not in gaps
    assert "security_control_bypassed" not in gaps


def test_exec_eval_without_auth_bypass():
    """Test CODE_INJECTION without security_control_bypassed - needs boundary_crossed."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input controlled"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="exec() found"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Dataflow confirmed"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Route is reachable"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified")
    )

    gaps = get_blocking_gaps_for_category("CODE_INJECTION", checklist)

    # Should require standard proof chain with boundary_crossed
    assert "boundary_crossed" in gaps
    assert "security_control_bypassed" not in gaps  # Not required when boundary_crossed is needed


def test_secrets_category_special_case():
    """Test that hardcoded secrets don't need dataflow/source/reachable/boundary."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Secret is present"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        reachable=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Hardcoded secret"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    gaps = get_blocking_gaps_for_category("SECRETS", checklist)

    # Only sink_present and not_only_misconfig required, both are PROVEN
    assert len(gaps) == 0
    assert "source_controlled_input" not in gaps
    assert "dataflow_evidenced" not in gaps
    assert "reachable" not in gaps
    assert "boundary_crossed" not in gaps


def test_secrets_with_gaps():
    """Test SECRETS category when required fields are not proven."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        sink_present=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        reachable=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable"),
        not_only_misconfig=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    gaps = get_blocking_gaps_for_category("SECRETS", checklist)

    # Only sink_present and not_only_misconfig should be blocking
    assert gaps == ["sink_present", "not_only_misconfig"]


def test_xss_requires_escaping_proof():
    """Test that XSS requires security_control_bypassed to prove no escaping."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="HTML output"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Dataflow confirmed"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Route reachable"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Server boundary"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code issue"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Escaping not verified")
    )

    gaps = get_blocking_gaps_for_category("XSS", checklist)

    # XSS requires proof that output is NOT escaped
    assert gaps == ["security_control_bypassed"]


def test_all_proven_no_gaps():
    """Test that no gaps are returned when all required fields are proven."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Verified"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Verified"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Verified"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Verified"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Verified"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Verified"),
        security_control_bypassed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Verified")
    )

    gaps = get_blocking_gaps_for_category("SQL_INJECTION", checklist)

    # All required fields are proven, no gaps
    assert len(gaps) == 0
