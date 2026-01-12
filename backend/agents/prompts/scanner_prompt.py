"""Scanner phase system prompt for dual-model analysis."""

from prompting_loader import load_prompt, render_prompt


def format_scanner_prompt(repo_info: str, handoff_after: str, custom_focus: str = None) -> str:
    """Format the scanner prompt with repo info and optional focus."""
    prompt = render_prompt("agents/scanner_system_prompt.md", repo_info=repo_info)

    if handoff_after == "exploration":
        prompt += "\n\n" + load_prompt("agents/scanner_early_handoff_note.md")

    if custom_focus:
        prompt += "\n\n" + render_prompt("agents/user_focus_area.md", custom_focus=custom_focus)

    return prompt
