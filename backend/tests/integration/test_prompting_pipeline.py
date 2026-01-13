# backend/tests/integration/test_prompting_pipeline.py
import pytest
from datetime import datetime
from services.prompt_router import PromptRouter
from services.critic_loop import CriticLoop, CriticInput
from services.blocking_gaps import get_blocking_gaps_for_category
from models.schemas import (
    Finding, ProofChecklist, Disposition, ChecklistItem, ChecklistStatus,
    VulnerabilityCategory, Severity
)
from services.evidence_gatherer import EvidenceResult


@pytest.mark.integration
def test_full_prompting_pipeline():
    """Test full pipeline: routing → critic → blocking gaps."""
    # Step 1: Route to appropriate modules
    router = PromptRouter()
    modules = router.route(
        category="SQL_INJECTION",
        stage="trace_dataflow",
        framework="django",
        framework_confidence=0.9
    )

    assert modules.base_prompt == "base/base_prompt.md"
    assert modules.validity_checklist == "validity_checklists/sql_injection.md"
    assert modules.stage_module == "stages/trace_dataflow.md"
    assert modules.context_module == "contexts/django.md"

    # Step 2: Assemble prompt
    final_prompt = router.assemble_from_paths(modules, task="Find SQL injection in /api/users")
    # Verify sections are present (flexible assertions since exact headers may vary)
    assert len(final_prompt) > 5000  # Should be substantial with all modules
    assert "evidence" in final_prompt.lower() or "proof" in final_prompt.lower()
    assert "sql" in final_prompt.lower()
    assert "Find SQL injection in /api/users" in final_prompt

    # Step 3: Simulate finding with incomplete checklist
    finding = Finding(
        id="test_finding_1",
        agent_id="test_agent",
        repo_id="test_repo",
        vulnerability_type="SQL Injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        title="Potential SQL injection in /api/users",
        description="Potential SQL injection in /api/users",
        severity=Severity.HIGH,
        file_path="/api/users.py",
        line_start=42,
        confidence=0.8,
        created_at=datetime.utcnow()
    )
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Request param"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL execute"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not traced"),  # Gap
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="HTTP route"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # Gap
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code issue"),
        security_control_bypassed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not checked")
    )

    # Step 4: Critic evaluates
    critic = CriticLoop()
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(
                snippet="test snippet",
                symbol_info=None,
                framework=None,
                matches=[]
            ),
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

    # Step 5: Verify blocking gaps align with category
    blocking = get_blocking_gaps_for_category("SQL_INJECTION", checklist)
    assert set(blocking) == set(decision.blocking_gaps)


@pytest.mark.integration
def test_pipeline_with_complete_checklist():
    """Test pipeline with complete checklist results in READY_TO_REPORT."""
    router = PromptRouter()
    critic = CriticLoop()

    # Complete checklist with all items PROVEN
    finding = Finding(
        id="test_finding_2",
        agent_id="test_agent",
        repo_id="test_repo",
        vulnerability_type="SQL Injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        title="SQL injection confirmed",
        description="SQL injection confirmed",
        severity=Severity.HIGH,
        file_path="/api/users.py",
        line_start=42,
        confidence=0.9,
        created_at=datetime.utcnow()
    )
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Request param"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL execute"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Traced"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="HTTP route"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Network boundary"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code issue")
    )

    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(
                snippet="test snippet",
                symbol_info=None,
                framework=None,
                matches=[]
            ),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "READY_TO_REPORT"
    assert len(decision.blocking_gaps) == 0


@pytest.mark.integration
def test_pipeline_fast_track_valid_disposition():
    """Test that VALID_SECURITY_ISSUE disposition fast-tracks through critic."""
    critic = CriticLoop()

    # Incomplete checklist but VALID disposition
    finding = Finding(
        id="test_finding_3",
        agent_id="test_agent",
        repo_id="test_repo",
        vulnerability_type="SQL Injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        title="SQL injection",
        description="SQL injection",
        severity=Severity.HIGH,
        file_path="/api/users.py",
        line_start=42,
        confidence=0.9,
        created_at=datetime.utcnow()
    )
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Request param"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL execute"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not traced"),  # Gap
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="HTTP route"),
        boundary_crossed=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not verified"),  # Gap
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code issue")
    )

    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(
                snippet="test snippet",
                symbol_info=None,
                framework=None,
                matches=[]
            ),
            checklist=checklist,
            preliminary_disposition=Disposition.VALID_SECURITY_ISSUE,  # Fast-track
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "READY_TO_REPORT"
    assert "Fast-tracked" in decision.reasoning


@pytest.mark.integration
def test_pipeline_filters_misconfiguration():
    """Test that misconfiguration-only findings are filtered out."""
    critic = CriticLoop()

    finding = Finding(
        id="test_finding_4",
        agent_id="test_agent",
        repo_id="test_repo",
        vulnerability_type="SQL Injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        title="SQL injection",
        description="SQL injection",
        severity=Severity.HIGH,
        file_path="/api/users.py",
        line_start=42,
        confidence=0.8,
        created_at=datetime.utcnow()
    )
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Request param"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL execute"),
        dataflow_evidenced=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Traced"),
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="HTTP route"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Network boundary"),
        not_only_misconfig=ChecklistItem(value=False, status=ChecklistStatus.DISPROVEN, reason="Only config")  # Filtered
    )

    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(
                snippet="test snippet",
                symbol_info=None,
                framework=None,
                matches=[]
            ),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "STOP_FILTERED"
    assert decision.disposition_hint == "MISCONFIGURATION"


@pytest.mark.integration
def test_pipeline_multiple_passes():
    """Test pass number logic: Pass 1 continues, Pass 2 stops speculative."""
    critic = CriticLoop()

    finding = Finding(
        id="test_finding_5",
        agent_id="test_agent",
        repo_id="test_repo",
        vulnerability_type="SQL Injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        title="SQL injection",
        description="SQL injection",
        severity=Severity.HIGH,
        file_path="/api/users.py",
        line_start=42,
        confidence=0.8,
        created_at=datetime.utcnow()
    )
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Request param"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL execute"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not traced"),  # Gap
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="HTTP route"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Network boundary"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code issue")
    )

    # Pass 1: Should continue
    decision_pass1 = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(
                snippet="test snippet",
                symbol_info=None,
                framework=None,
                matches=[]
            ),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision_pass1.decision == "CONTINUE"
    assert "Pass 1" in decision_pass1.reasoning

    # Pass 2: Should stop speculative
    decision_pass2 = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(
                snippet="test snippet",
                symbol_info=None,
                framework=None,
                matches=[]
            ),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=2,
            remaining_tool_calls=10,
            hypothesis_span_id="span_123"
        )
    )

    assert decision_pass2.decision == "STOP_SPECULATIVE"
    assert "Pass 2" in decision_pass2.reasoning


@pytest.mark.integration
def test_pipeline_one_more_push_exception():
    """Test that Pass 3 with 1 gap and 3+ tool calls triggers 'one more push'."""
    critic = CriticLoop()

    finding = Finding(
        id="test_finding_6",
        agent_id="test_agent",
        repo_id="test_repo",
        vulnerability_type="SQL Injection",
        category=VulnerabilityCategory.SQL_INJECTION,
        title="SQL injection",
        description="SQL injection",
        severity=Severity.HIGH,
        file_path="/api/users.py",
        line_start=42,
        confidence=0.8,
        created_at=datetime.utcnow()
    )
    checklist = ProofChecklist(
        source_controlled_input=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Request param"),
        sink_present=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="SQL execute"),
        dataflow_evidenced=ChecklistItem(value=False, status=ChecklistStatus.UNKNOWN, reason="Not traced"),  # Only 1 gap
        reachable=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="HTTP route"),
        boundary_crossed=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Network boundary"),
        not_only_misconfig=ChecklistItem(value=True, status=ChecklistStatus.PROVEN, reason="Code issue")
    )

    # Pass 3 with 1 gap and 5 tool calls remaining
    decision = critic.evaluate(
        CriticInput(
            finding=finding,
            evidence=EvidenceResult(
                snippet="test snippet",
                symbol_info=None,
                framework=None,
                matches=[]
            ),
            checklist=checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=3,
            remaining_tool_calls=5,
            hypothesis_span_id="span_123"
        )
    )

    assert decision.decision == "CONTINUE"
    assert "one more push" in decision.reasoning.lower()


@pytest.mark.integration
def test_pipeline_routing_for_different_categories():
    """Test routing works correctly for different vulnerability categories."""
    router = PromptRouter()

    # Test SSRF
    modules_ssrf = router.route(
        category="SSRF",
        stage="identify_entrypoints",
        framework="fastapi",
        framework_confidence=0.9
    )
    assert modules_ssrf.validity_checklist == "validity_checklists/ssrf.md"
    assert modules_ssrf.stage_module == "stages/identify_entrypoints.md"
    assert modules_ssrf.context_module == "contexts/fastapi.md"

    # Test CODE_INJECTION
    modules_code = router.route(
        category="CODE_INJECTION",
        stage="validate_exploitability",
        framework="flask",
        framework_confidence=0.9
    )
    assert modules_code.stage_module == "stages/validate_exploitability.md"
    assert modules_code.context_module == "contexts/flask.md"
