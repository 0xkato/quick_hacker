"""Tests for base analysis prompt."""
import pytest
from prompts.v2.analysis.base_analysis import BaseAnalysisPrompt


class TestBaseAnalysisPrompt:
    def test_requires_source_to_sink_trace(self):
        prompt = BaseAnalysisPrompt.get_validation_requirements()
        assert "source" in prompt.lower()
        assert "sink" in prompt.lower()
        assert "trace" in prompt.lower()

    def test_includes_evidence_requirements(self):
        prompt = BaseAnalysisPrompt.get_validation_requirements()
        assert "evidence" in prompt.lower()
        assert "file" in prompt.lower() or "line" in prompt.lower()

    def test_includes_rejection_criteria(self):
        prompt = BaseAnalysisPrompt.get_validation_requirements()
        assert "reject" in prompt.lower() or "not" in prompt.lower()

    def test_defines_output_format(self):
        prompt = BaseAnalysisPrompt.get_output_format()
        assert "validated" in prompt.lower() or "finding" in prompt.lower()
        assert "rejected" in prompt.lower() or "reason" in prompt.lower()

    def test_includes_verdict_reporting_instruction(self):
        prompt = BaseAnalysisPrompt.get_verdict_reporting_instruction()
        assert "trace_path_verdict" in prompt
        assert "safe" in prompt.lower()
        assert "vulnerable" in prompt.lower()
        assert "reasoning" in prompt.lower()
