"""Tests for command injection analysis prompt."""
import pytest
from prompts.v2.analysis.command_injection import CommandInjectionAnalyzer, build_cmdi_prompt


class TestCommandInjectionAnalyzer:
    def test_includes_command_specific_sinks(self):
        """Should include command injection dangerous sinks."""
        prompt = build_cmdi_prompt(candidates=[])
        # Should have subprocess, system, exec sinks
        assert "subprocess" in prompt.lower()
        assert "system" in prompt.lower()
        assert "exec" in prompt.lower() or "eval" in prompt.lower()

    def test_includes_safe_patterns(self):
        """Should include safe patterns for rejecting FPs."""
        prompt = build_cmdi_prompt(candidates=[])
        # Should know shell=False and shlex.quote are safe
        assert "shell=false" in prompt.lower()
        assert "shlex" in prompt.lower() or "quote" in prompt.lower()

    def test_includes_poc_patterns(self):
        """Should include command injection PoC patterns."""
        prompt = build_cmdi_prompt(candidates=[])
        # Should have ; | $() patterns
        assert ";" in prompt
        assert "|" in prompt
        assert "$(" in prompt or "`" in prompt

    def test_framework_guidance_python(self):
        """Should provide Python-specific guidance."""
        prompt = build_cmdi_prompt(candidates=[], framework="python")
        assert "python" in prompt.lower()

    def test_framework_guidance_node(self):
        """Should provide Node-specific guidance."""
        prompt = build_cmdi_prompt(candidates=[], framework="node")
        assert "node" in prompt.lower() or "child_process" in prompt.lower()

    def test_framework_guidance_ruby(self):
        """Should provide Ruby-specific guidance."""
        prompt = build_cmdi_prompt(candidates=[], framework="ruby")
        assert "ruby" in prompt.lower()

    def test_includes_candidates_in_prompt(self):
        """Should include candidate details in prompt."""
        candidates = [
            {
                "id": "CMDI-001",
                "file": "utils/runner.py",
                "line": 42,
                "sink": "os.system",
                "code_snippet": "os.system(f'ping {host}')"
            }
        ]
        prompt = build_cmdi_prompt(candidates=candidates)
        assert "CMDI-001" in prompt
        assert "utils/runner.py" in prompt
        assert "os.system" in prompt

    def test_analyzer_dangerous_sinks_structure(self):
        """Dangerous sinks should be well-structured."""
        sinks = CommandInjectionAnalyzer.dangerous_sinks
        assert "os.system" in sinks
        assert "subprocess" in sinks
        assert "popen" in sinks.lower()

    def test_analyzer_get_full_prompt(self):
        """get_full_prompt should combine all sections."""
        prompt = CommandInjectionAnalyzer.get_full_prompt()
        assert "dangerous" in prompt.lower()
        assert "safe" in prompt.lower()
        assert "poc" in prompt.lower() or "proof" in prompt.lower()
