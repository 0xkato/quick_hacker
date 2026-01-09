from prompts.workflow_engine import get_developer_prompt

def test_prompt_documents_trace_path_verdict():
    """Prompt should document the trace_path_verdict tool."""
    prompt = get_developer_prompt()
    assert "trace_path_verdict" in prompt.lower()

def test_prompt_documents_coverage_workflow():
    """Prompt should explain the coverage tracking workflow."""
    prompt = get_developer_prompt()
    assert "coverage" in prompt.lower()
    # Should mention the workflow of discovering -> tracing -> verdicting
    assert "entry point" in prompt.lower() or "entry_point" in prompt.lower()
