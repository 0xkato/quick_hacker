from prompts import get_hard_rules_prompt

def test_prompt_mentions_complete_audit_tool():
    """Prompt should document the complete_audit tool requirement."""
    prompt = get_hard_rules_prompt()
    assert "complete_audit" in prompt.lower()

def test_prompt_removes_old_final_outcome_format():
    """Prompt should not have the old FINAL OUTCOME text format."""
    prompt = get_hard_rules_prompt()
    # Should not instruct to output "FINAL OUTCOME" as text
    assert "your final user-facing report must be exactly one of:" not in prompt.lower()
