"""Tests for prompt assembly orchestrator."""
import pytest
from prompts.v2.assembly import PromptAssembler


class TestPromptAssembler:
    def test_assembles_exploration_with_constraints(self):
        assembler = PromptAssembler("gpt-4o")
        prompt = assembler.assemble_exploration("test-repo")
        assert "verbosity" in prompt.lower()
        assert "false positive" in prompt.lower()
        assert "test-repo" in prompt

    def test_assembles_triage_with_constraints(self):
        assembler = PromptAssembler("claude-3-5-sonnet")
        prompt = assembler.assemble_triage({"languages": ["python"]})
        assert "verbosity" in prompt.lower()
        assert "untrusted" in prompt.lower()

    def test_assembles_analysis_for_sqli(self):
        assembler = PromptAssembler("gpt-5.2")
        prompt = assembler.assemble_analysis("sql_injection", candidates=[])
        assert "sql" in prompt.lower()
        assert "execute" in prompt.lower()

    def test_assembles_analysis_for_all_vuln_types(self):
        assembler = PromptAssembler("gpt-4o")
        for vuln_type in assembler.get_supported_vuln_types():
            prompt = assembler.assemble_analysis(vuln_type, candidates=[])
            assert len(prompt) > 0

    def test_raises_for_unknown_vuln_type(self):
        assembler = PromptAssembler("gpt-4o")
        with pytest.raises(ValueError) as exc:
            assembler.assemble_analysis("unknown_vuln", candidates=[])
        assert "unknown_vuln" in str(exc.value).lower()

    def test_assembles_verification_pipeline(self):
        assembler = PromptAssembler("gpt-4o")
        prompt = assembler.assemble_verification({"title": "Test Finding"})
        assert "evidence" in prompt.lower()
        assert "advocate" in prompt.lower()
        assert "proof" in prompt.lower()
        assert "final" in prompt.lower()

    def test_supported_vuln_types(self):
        assembler = PromptAssembler("gpt-4o")
        types = assembler.get_supported_vuln_types()
        assert "sql_injection" in types
        assert "xss" in types
        assert "ssrf" in types
