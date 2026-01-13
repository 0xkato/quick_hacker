import pytest
from services.prompt_router import PromptRouter, PromptModules


def test_route_sql_injection():
    """Test routing for SQL injection category."""
    router = PromptRouter()

    modules = router.route(
        category="SQL_INJECTION",
        stage=None,
        framework=None,
        framework_confidence=0.0
    )

    assert modules.base_prompt == "base/base_prompt.md"
    assert modules.validity_checklist == "validity_checklists/sql_injection.md"
    assert modules.stage_module is None
    assert modules.context_module is None


def test_route_deep_audit_stage():
    """Test routing for DeepAudit stage."""
    router = PromptRouter()

    modules = router.route(
        category="SSRF",
        stage="trace_dataflow",
        framework=None,
        framework_confidence=0.0
    )

    assert modules.base_prompt == "base/base_prompt.md"
    assert modules.validity_checklist == "validity_checklists/ssrf.md"
    assert modules.stage_module == "stages/trace_dataflow.md"
    assert modules.context_module is None


def test_route_with_framework_context():
    """Test routing with high-confidence framework detection."""
    router = PromptRouter()

    modules = router.route(
        category="SQL_INJECTION",
        stage=None,
        framework="django",
        framework_confidence=0.85
    )

    assert modules.base_prompt == "base/base_prompt.md"
    assert modules.validity_checklist == "validity_checklists/sql_injection.md"
    assert modules.context_module == "contexts/django.md"


def test_route_framework_below_confidence_threshold():
    """Test that framework context is NOT loaded when confidence < 0.8."""
    router = PromptRouter()

    modules = router.route(
        category="SQL_INJECTION",
        stage=None,
        framework="django",
        framework_confidence=0.75  # Below 0.8 threshold
    )

    assert modules.context_module is None  # Should not load


def test_assemble_prompt():
    """Test assembling final prompt from modules."""
    router = PromptRouter()

    final_prompt = router.assemble_prompt(
        base_prompt="Base content\n",
        validity_checklist="Validity content\n",
        stage_module="Stage content\n",
        context_module="Context content\n",
        task="Task: Find SQL injection\n"
    )

    expected = "Base content\n\nValidity content\n\nStage content\n\nContext content\n\nTask: Find SQL injection\n"
    assert final_prompt == expected
