import pytest


def test_get_system_prompt_includes_flow_context_pack_section():
    from routers.chat import get_system_prompt

    context = {
        "flow_context_pack": {
            "version": 1,
            "selected_node": {
                "id": "n1",
                "type": "finding",
                "label": "HIGH: SQLi",
                "llm_reasoning": "Reasoning here",
            },
            "path": [
                {"id": "root", "type": "structured_root", "label": "Structured Trace"},
                {"id": "global", "type": "global_recon", "label": "Global Recon"},
                {"id": "steps", "type": "steps", "label": "Steps", "file_path": "a.py"},
                {"id": "n1", "type": "finding", "label": "HIGH: SQLi"},
            ],
            "finding": {
                "id": "f1",
                "severity": "high",
                "title": "SQL injection",
                "description": "User input reaches query",
                "file_path": "a.py",
                "line_start": 10,
                "vulnerability_type": "sql_injection",
            },
        }
    }

    prompt = get_system_prompt(context)
    assert "Flow Context" in prompt
    assert "HIGH: SQLi" in prompt
    assert "SQL injection" in prompt
    assert "a.py" in prompt


def test_get_system_prompt_truncates_large_flow_context_fields():
    from routers.chat import get_system_prompt

    context = {
        "flow_context_pack": {
            "version": 1,
            "selected_node": {
                "id": "n1",
                "type": "analysis",
                "label": "Big node",
                "llm_reasoning": "x" * 20000,
                "tool_result_summary": "y" * 20000,
                "code_context": "z" * 20000,
            },
            "path": [{"id": "n1", "type": "analysis", "label": "Big node"}],
        }
    }

    prompt = get_system_prompt(context)
    assert "Flow Context" in prompt
    assert "[truncated]" in prompt

