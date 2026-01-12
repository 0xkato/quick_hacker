import pytest


def test_load_prompt_reads_template_file():
    from prompting_loader import load_prompt

    text = load_prompt("chat/general.md")
    assert "security researcher" in text.lower()


def test_render_prompt_formats_placeholders():
    from prompting_loader import render_prompt

    rendered = render_prompt("agents/react_system_prompt.md", repo_info="REPO_INFO_X")
    assert "REPO_INFO_X" in rendered


def test_render_prompt_supports_templates_with_json_braces():
    from prompting_loader import render_prompt

    rendered = render_prompt(
        "agents/attack_surface_triage_user_prompt.md",
        threat_model="A",
        candidates_json="[]",
    )
    assert "Threat model: A" in rendered
    assert "Candidates (JSON array):" in rendered
    assert "[]" in rendered


def test_load_prompt_blocks_path_traversal():
    from prompting_loader import load_prompt

    with pytest.raises(ValueError):
        load_prompt("../backend/main.py")
