"""Tests for V2 base infrastructure."""
import pytest
from prompts.v2.base import ProviderAdapter, ProviderType, CoreConstraints


class TestProviderAdapter:
    def test_detects_openai_models(self):
        adapter = ProviderAdapter()
        assert adapter.detect_provider("gpt-5.2") == ProviderType.OPENAI
        assert adapter.detect_provider("gpt-4o") == ProviderType.OPENAI

    def test_detects_anthropic_models(self):
        adapter = ProviderAdapter()
        assert adapter.detect_provider("claude-3-opus") == ProviderType.ANTHROPIC
        assert adapter.detect_provider("claude-3-5-sonnet") == ProviderType.ANTHROPIC

    def test_formats_with_verbosity_spec(self):
        adapter = ProviderAdapter()
        result = adapter.format_prompt("Test prompt", "gpt-5.2")
        assert "verbosity" in result.lower()
        assert "Test prompt" in result


class TestCoreConstraints:
    def test_includes_zero_fp_contract(self):
        constraints = CoreConstraints.get_all()
        assert "false positive" in constraints.lower()

    def test_includes_evidence_discipline(self):
        constraints = CoreConstraints.get_all()
        assert "evidence" in constraints.lower()
        assert "hallucinate" in constraints.lower() or "fabricate" in constraints.lower()

    def test_includes_prompt_injection_immunity(self):
        constraints = CoreConstraints.get_all()
        assert "untrusted" in constraints.lower()

    def test_can_get_individual_constraints(self):
        assert CoreConstraints.zero_fp() is not None
        assert CoreConstraints.evidence_discipline() is not None
        assert CoreConstraints.prompt_injection_immunity() is not None
