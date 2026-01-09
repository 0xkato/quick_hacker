"""Tests for classification gate injection in base agent."""
import pytest
from prompts.classification_gate import get_classification_gate_prompt


def test_classification_prompt_injected_for_threat_model_a():
    """Classification gate prompt is generated for threat model A."""
    prompt = get_classification_gate_prompt("A")
    assert "Current threat model: A" in prompt or "Threat Model: **A**" in prompt
    assert "CLASSIFICATION" in prompt.upper() or "Classification" in prompt


def test_classification_prompt_injected_for_threat_model_ab():
    """Classification gate prompt is generated for threat model AB."""
    prompt = get_classification_gate_prompt("AB")
    assert "AB" in prompt


def test_classification_prompt_injected_for_threat_model_abc():
    """Classification gate prompt is generated for threat model ABC."""
    prompt = get_classification_gate_prompt("ABC")
    assert "ABC" in prompt
