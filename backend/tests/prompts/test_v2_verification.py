"""Tests for verification pipeline prompts."""
import pytest
from prompts.v2.phases.verification import (
    EvidenceVerificationPrompt,
    DevilsAdvocatePrompt,
    ProofOfConceptPrompt,
    FinalGatePrompt,
    build_verification_pipeline,
)


class TestVerificationPipeline:
    def test_evidence_verification_tries_to_disprove(self):
        prompt = EvidenceVerificationPrompt.get_prompt()
        assert "disprove" in prompt.lower() or "refute" in prompt.lower()

    def test_devils_advocate_argues_against(self):
        prompt = DevilsAdvocatePrompt.get_prompt()
        assert "against" in prompt.lower() or "counter" in prompt.lower()

    def test_poc_requires_concrete_payload(self):
        prompt = ProofOfConceptPrompt.get_prompt()
        assert "payload" in prompt.lower() or "concrete" in prompt.lower()

    def test_final_gate_is_high_bar(self):
        prompt = FinalGatePrompt.get_prompt()
        assert "reputation" in prompt.lower() or "certain" in prompt.lower()

    def test_pipeline_includes_all_gates(self):
        pipeline = build_verification_pipeline(finding={})
        assert "evidence" in pipeline.lower()
        assert "advocate" in pipeline.lower() or "against" in pipeline.lower()
        assert "proof" in pipeline.lower() or "poc" in pipeline.lower()
        assert "final" in pipeline.lower()
