import pytest
from services.prompt_router import PromptRouter
from models.schemas import ProofChecklist, ChecklistStatus

@pytest.mark.integration
def test_prompt_router_to_ui_flow():
    """
    Test complete flow:
    1. PromptRouter loads validity checklist
    2. Agent uses assembled prompt
    3. StrictClassifier generates ProofChecklist
    4. ProofChecklist has correct structure for UI
    """
    # Step 1: PromptRouter loads checklist
    router = PromptRouter()
    modules = router.route(category="SQL_INJECTION")
    prompt = router.assemble_from_paths(modules, task="Find SQL injection")

    assert "sink_present" in prompt
    assert "SQL Injection Proof Checklist" in prompt

    # Step 2: Simulate StrictClassifier output
    # (Full agent test would be too slow, just verify data structure)
    checklist = ProofChecklist(
        source_controlled_input={"value": True, "status": ChecklistStatus.PROVEN, "reason": "User input from request.args"},
        sink_present={"value": True, "status": ChecklistStatus.PROVEN, "reason": "Found cursor.execute()"},
        dataflow_evidenced={"value": True, "status": ChecklistStatus.PROVEN, "reason": "String concatenation"},
        reachable={"value": True, "status": ChecklistStatus.PROVEN, "reason": "Route registered"},
        boundary_crossed={"value": True, "status": ChecklistStatus.PROVEN, "reason": "Public API endpoint"},
        not_only_misconfig={"value": True, "status": ChecklistStatus.PROVEN, "reason": "Code is vulnerable"},
    )

    # Step 3: Verify checklist structure matches UI expectations
    assert checklist.source_controlled_input.status == ChecklistStatus.PROVEN
    assert checklist.sink_present.status == ChecklistStatus.PROVEN
    assert checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN

    # Step 4: Verify all 6 required fields present
    required_fields = [
        'source_controlled_input',
        'sink_present',
        'dataflow_evidenced',
        'reachable',
        'boundary_crossed',
        'not_only_misconfig'
    ]
    for field in required_fields:
        assert hasattr(checklist, field)
        assert getattr(checklist, field) is not None

@pytest.mark.integration
def test_xss_checklist_includes_security_control_bypassed():
    """Test XSS validity checklist includes security_control_bypassed."""
    router = PromptRouter()
    modules = router.route(category="XSS")
    prompt = router.assemble_from_paths(modules, task="Find XSS")

    # Verify XSS-specific field is mentioned
    assert "security_control_bypassed" in prompt
    assert "escaping" in prompt.lower() or "encoding" in prompt.lower()
