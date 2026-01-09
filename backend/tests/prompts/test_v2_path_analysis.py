"""Tests for path traversal analysis prompt."""
import pytest
from prompts.v2.analysis.path_traversal import PathTraversalAnalyzer, build_path_traversal_prompt


class TestPathTraversalAnalyzer:
    def test_includes_path_specific_sinks(self):
        """Should include path traversal dangerous sinks like open, send_file."""
        prompt = build_path_traversal_prompt(candidates=[])
        prompt_lower = prompt.lower()
        # Check for file operation sinks
        assert "open(" in prompt_lower or "open()" in prompt_lower
        assert "send_file" in prompt_lower

    def test_includes_safe_patterns(self):
        """Should include safe patterns like basename, secure_filename."""
        prompt = build_path_traversal_prompt(candidates=[])
        prompt_lower = prompt.lower()
        # Should know what's safe to reject FPs
        assert "basename" in prompt_lower
        assert "secure_filename" in prompt_lower

    def test_includes_poc_patterns(self):
        """Should include PoC patterns like ../ and encoded variants."""
        prompt = build_path_traversal_prompt(candidates=[])
        # Check for path traversal payloads
        assert "../" in prompt
        assert "%2f" in prompt.lower() or "%2F" in prompt

    def test_framework_guidance_flask(self):
        """Should provide Flask-specific guidance for send_file."""
        prompt = build_path_traversal_prompt(candidates=[], framework="flask")
        prompt_lower = prompt.lower()
        assert "flask" in prompt_lower or "send_file" in prompt_lower

    def test_framework_guidance_django(self):
        """Should provide Django-specific guidance for FileResponse."""
        prompt = build_path_traversal_prompt(candidates=[], framework="django")
        prompt_lower = prompt.lower()
        assert "django" in prompt_lower or "fileresponse" in prompt_lower

    def test_framework_guidance_express(self):
        """Should provide Express-specific guidance for res.sendFile."""
        prompt = build_path_traversal_prompt(candidates=[], framework="express")
        prompt_lower = prompt.lower()
        assert "express" in prompt_lower or "sendfile" in prompt_lower

    def test_dangerous_sinks_attribute(self):
        """Analyzer should have dangerous_sinks with file operations."""
        sinks = PathTraversalAnalyzer.dangerous_sinks
        sinks_lower = sinks.lower()
        assert "open()" in sinks_lower or "open(" in sinks_lower
        assert "os.path.join" in sinks_lower

    def test_safe_patterns_attribute(self):
        """Analyzer should have safe_patterns with path validation."""
        patterns = PathTraversalAnalyzer.safe_patterns
        patterns_lower = patterns.lower()
        assert "basename" in patterns_lower
        assert "allowlist" in patterns_lower or "whitelist" in patterns_lower

    def test_poc_patterns_attribute(self):
        """Analyzer should have PoC patterns for path traversal."""
        pocs = PathTraversalAnalyzer.poc_patterns
        assert "/etc/passwd" in pocs
        assert "../" in pocs

    def test_candidates_included_in_prompt(self):
        """Should include candidate details in prompt."""
        candidates = [
            {
                "id": "PATH-001",
                "file": "app/views.py",
                "line": 42,
                "sink": "open()",
                "code_snippet": "open(user_path)"
            }
        ]
        prompt = build_path_traversal_prompt(candidates=candidates)
        assert "PATH-001" in prompt
        assert "app/views.py" in prompt
        assert "42" in prompt
