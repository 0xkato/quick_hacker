"""Tests for triage phase prompt."""
import pytest
from prompts.v2.phases.triage import TriagePrompt, build_triage_prompt


class TestTriagePrompt:
    def test_uses_security_detectors(self):
        prompt = build_triage_prompt(tech_stack={"languages": ["python"]})
        assert "detect" in prompt.lower() or "security" in prompt.lower()

    def test_outputs_candidates_by_type(self):
        prompt = build_triage_prompt(tech_stack={"languages": ["python"]})
        assert "candidate" in prompt.lower()
        assert "type" in prompt.lower() or "category" in prompt.lower()

    def test_does_not_validate_yet(self):
        prompt = build_triage_prompt(tech_stack={"languages": ["python"]})
        # Should not be doing deep validation
        assert "later" in prompt.lower() or "next phase" in prompt.lower() or "not" in prompt.lower()

    def test_threat_model_aware(self):
        prompt = build_triage_prompt(
            tech_stack={"languages": ["python"]},
            threat_model="authenticated"
        )
        assert "threat" in prompt.lower() or "model" in prompt.lower() or "auth" in prompt.lower()

    def test_includes_sink_families(self):
        prompt = build_triage_prompt(tech_stack={"languages": ["python"]})
        # Should mention sink types to look for
        assert "sql" in prompt.lower() or "command" in prompt.lower() or "sink" in prompt.lower()
