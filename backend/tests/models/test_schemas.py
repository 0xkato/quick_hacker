import pytest


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
