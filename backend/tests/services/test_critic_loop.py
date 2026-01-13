"""
Unit tests for critic_loop.py - Critic/Refuter feedback loop service.

Tests ensure:
1. Fast-track for VALID_SECURITY_ISSUE/BUG dispositions
2. CONTINUE when blocking gaps remain (Pass 1)
3. STOP_SPECULATIVE after Pass 2+ with blocking gaps
4. STOP_FILTERED for misconfiguration-only findings
5. Pass 3 "one more push" exception (1 gap + 3+ tool calls remaining)
6. Recommended tool calls for each gap type
"""

import pytest
from models.schemas import (
    Finding, ProofChecklist, ChecklistItem, ChecklistStatus,
    Disposition, Severity, VulnerabilityCategory
)
from services.evidence_gatherer import EvidenceResult
from services.critic_loop import CriticLoop, CriticDecision, CriticInput
from datetime import datetime


def test_critic_fast_track_valid_disposition():
    """Test that critic fast-tracks when preliminary_disposition is already VALID."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Dataflow confirmed"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint reachable"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Boundary crossed"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_1",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.HIGH,
        title="SQL Injection Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="SQL Injection",
        confidence=0.95,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.SQL_INJECTION
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.VALID_SECURITY_ISSUE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "READY_TO_REPORT"
    assert len(decision.blocking_gaps) == 0


def test_critic_fast_track_bug_disposition():
    """Test that critic fast-tracks when preliminary_disposition is BUG."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Bug sink found"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Dataflow confirmed"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Reachable"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Boundary crossed"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code bug"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_2",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.MEDIUM,
        title="Bug Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="Bug",
        confidence=0.85,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.GENERIC
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.BUG,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "READY_TO_REPORT"
    assert len(decision.blocking_gaps) == 0


def test_critic_continue_with_blocking_gaps():
    """Test that critic returns CONTINUE when blocking gaps remain."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # Blocking gap
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint reachable"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # Blocking gap
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_3",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.HIGH,
        title="SQL Injection Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="SQL Injection",
        confidence=0.75,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.SQL_INJECTION
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "CONTINUE"
    assert "dataflow_evidenced" in decision.blocking_gaps
    assert "boundary_crossed" in decision.blocking_gaps
    assert len(decision.recommended_tool_calls) > 0


def test_critic_stop_speculative_after_pass_2():
    """Test that critic returns STOP_SPECULATIVE after pass 2 with blocking gaps."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Still not verified"),  # Still blocking
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint reachable"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Boundary crossed"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_4",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.HIGH,
        title="SQL Injection Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="SQL Injection",
        confidence=0.75,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.SQL_INJECTION
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=2,  # Pass 2
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "STOP_SPECULATIVE"


def test_critic_stop_filtered_misconfiguration():
    """Test that critic returns STOP_FILTERED for misconfiguration-only findings."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Dataflow confirmed"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint reachable"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Boundary crossed"),
        not_only_misconfig=ChecklistItem(value=False, status=ChecklistStatus.DISPROVEN, reason="Only a misconfiguration"),  # Only a misconfiguration
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_5",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.MEDIUM,
        title="Misconfiguration Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="Misconfiguration",
        confidence=0.85,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.GENERIC
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "STOP_FILTERED"
    assert decision.disposition_hint == "MISCONFIGURATION"


def test_critic_one_more_push_exception():
    """Test Pass 3 'one more push' exception: 1 gap + 3+ tool calls remaining."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # 1 gap
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint reachable"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Boundary crossed"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_6",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.HIGH,
        title="SQL Injection Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="SQL Injection",
        confidence=0.75,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.SQL_INJECTION
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=3,  # Pass 3
            remaining_tool_calls=5,  # 3+ remaining
            hypothesis_span_id="span_123"
        )
    )

    # Should continue with "one more push" exception
    assert decision.decision == "CONTINUE"
    assert len(decision.blocking_gaps) == 1
    assert "dataflow_evidenced" in decision.blocking_gaps


def test_critic_pass_3_multiple_gaps_still_stops():
    """Test Pass 3 with multiple gaps still returns STOP_SPECULATIVE."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # Gap 1
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint reachable"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # Gap 2
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_7",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.HIGH,
        title="SQL Injection Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="SQL Injection",
        confidence=0.75,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.SQL_INJECTION
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=3,  # Pass 3
            remaining_tool_calls=5,  # 3+ remaining but 2 gaps
            hypothesis_span_id="span_123"
        )
    )

    # Should stop because there are 2 gaps, not eligible for "one more push"
    assert decision.decision == "STOP_SPECULATIVE"


def test_critic_pass_3_insufficient_tool_calls():
    """Test Pass 3 with 1 gap but insufficient tool calls still stops."""
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="User input confirmed"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL query found"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # 1 gap
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Endpoint reachable"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Boundary crossed"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code vulnerability"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not applicable")
    )

    finding = Finding(
        id="test_8",
        agent_id="agent_1",
        repo_id="repo_1",
        severity=Severity.HIGH,
        title="SQL Injection Test",
        description="Test finding",
        file_path="test.py",
        line_start=10,
        vulnerability_type="SQL Injection",
        confidence=0.75,
        created_at=datetime.utcnow(),
        category=VulnerabilityCategory.SQL_INJECTION
    )

    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(snippet="test", symbol_info=None, framework=None, matches=[]),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=3,  # Pass 3
            remaining_tool_calls=2,  # Only 2 remaining, not 3+
            hypothesis_span_id="span_123"
        )
    )

    # Should stop because insufficient tool calls for "one more push"
    assert decision.decision == "STOP_SPECULATIVE"
