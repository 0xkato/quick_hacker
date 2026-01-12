"""Universal classification gate prompt template for agent prompts.

This module provides the classification gate that must be applied to all
findings before they are reported. It ensures findings are correctly
categorized and reduces false positives by enforcing strict classification rules.
"""

from prompting_loader import render_prompt


VALID_THREAT_MODELS = {"A", "AB", "ABC"}


def get_classification_gate_prompt(threat_model: str) -> str:
    """Format the classification gate template with the given threat model.

    Args:
        threat_model: The threat model to use (A, AB, or ABC)

    Returns:
        The formatted classification gate prompt string

    Raises:
        ValueError: If threat_model is not one of "A", "AB", or "ABC"
    """
    if threat_model not in VALID_THREAT_MODELS:
        raise ValueError(
            f"Invalid threat_model '{threat_model}'. "
            f"Must be one of: {', '.join(sorted(VALID_THREAT_MODELS))}"
        )
    return render_prompt("agents/classification_gate.md", threat_model=threat_model)
