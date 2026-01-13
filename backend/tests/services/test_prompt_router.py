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


def test_all_vulnerability_categories():
    """Test routing for all supported vulnerability categories."""
    router = PromptRouter()

    categories = [
        "SQL_INJECTION",
        "SSRF",
        "CODE_INJECTION",
        "COMMAND_INJECTION",
        "AUTH_BYPASS",
        "IDOR",
        "MEMORY_SAFETY"
    ]

    for category in categories:
        modules = router.route(category=category)
        assert modules.base_prompt == "base/base_prompt.md"
        assert modules.validity_checklist is not None, f"No checklist found for {category}"


def test_all_deepaudit_stages():
    """Test routing for all DeepAudit stages."""
    router = PromptRouter()

    stages = [
        "identify_entrypoints",
        "trace_dataflow",
        "validate_exploitability",
        "triage"
    ]

    for stage in stages:
        modules = router.route(stage=stage)
        assert modules.base_prompt == "base/base_prompt.md"
        assert modules.stage_module is not None, f"No stage module found for {stage}"


def test_all_framework_contexts():
    """Test routing for all supported frameworks."""
    router = PromptRouter()

    frameworks = ["django", "fastapi", "flask", "express"]

    for framework in frameworks:
        modules = router.route(
            framework=framework,
            framework_confidence=0.9  # Above threshold
        )
        assert modules.base_prompt == "base/base_prompt.md"
        assert modules.context_module is not None, f"No context module found for {framework}"


def test_assemble_from_paths_integration():
    """Test loading and assembling real prompt modules."""
    router = PromptRouter()

    modules = router.route(
        category="SQL_INJECTION",
        stage="trace_dataflow",
        framework="django",
        framework_confidence=0.9
    )

    final_prompt = router.assemble_from_paths(modules, task="Find SQL injection")

    # Verify all sections are present
    assert "Base System Prompt" in final_prompt or "Evidence Integrity" in final_prompt
    assert "SQL" in final_prompt or "sql" in final_prompt
    assert "Find SQL injection" in final_prompt
    assert len(final_prompt) > 1000  # Should be substantial


def test_unknown_category_returns_none():
    """Test that unknown category returns None for validity_checklist."""
    router = PromptRouter()

    modules = router.route(category="UNKNOWN_CATEGORY")
    assert modules.base_prompt == "base/base_prompt.md"
    assert modules.validity_checklist is None


def test_unknown_stage_returns_none():
    """Test that unknown stage returns None for stage_module."""
    router = PromptRouter()

    modules = router.route(stage="unknown_stage")
    assert modules.base_prompt == "base/base_prompt.md"
    assert modules.stage_module is None


def test_unknown_framework_returns_none():
    """Test that unknown framework returns None for context_module."""
    router = PromptRouter()

    modules = router.route(
        framework="unknown_framework",
        framework_confidence=0.9
    )
    assert modules.base_prompt == "base/base_prompt.md"
    assert modules.context_module is None
