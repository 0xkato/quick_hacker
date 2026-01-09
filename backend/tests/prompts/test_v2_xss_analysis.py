"""Tests for XSS analysis prompt."""
import pytest
from prompts.v2.analysis.xss import XSSAnalyzer, build_xss_prompt


class TestXSSAnalyzer:
    def test_includes_xss_specific_sinks(self):
        """Should include XSS dangerous sinks."""
        prompt = build_xss_prompt(candidates=[])
        # Should have innerHTML, dangerouslySetInnerHTML, v-html
        assert "innerhtml" in prompt.lower()
        assert "dangerouslysetinnerhtml" in prompt.lower()
        assert "v-html" in prompt.lower()

    def test_includes_document_write_sink(self):
        """Should include document.write as dangerous sink."""
        prompt = build_xss_prompt(candidates=[])
        assert "document.write" in prompt.lower()

    def test_includes_safe_patterns(self):
        """Should include safe patterns for rejecting FPs."""
        prompt = build_xss_prompt(candidates=[])
        # Should know textContent and auto-escaping are safe
        assert "textcontent" in prompt.lower()
        assert "auto" in prompt.lower() and "escap" in prompt.lower()

    def test_includes_dompurify_safe_pattern(self):
        """Should recognize DOMPurify as safe sanitization."""
        prompt = build_xss_prompt(candidates=[])
        assert "dompurify" in prompt.lower()

    def test_includes_csp_safe_pattern(self):
        """Should recognize CSP headers as safe pattern."""
        prompt = build_xss_prompt(candidates=[])
        assert "csp" in prompt.lower()

    def test_includes_poc_patterns(self):
        """Should include XSS PoC patterns."""
        prompt = build_xss_prompt(candidates=[])
        # Should have <script>, onerror, javascript: patterns
        assert "<script>" in prompt.lower() or "script" in prompt
        assert "onerror" in prompt.lower()
        assert "javascript:" in prompt.lower()

    def test_framework_guidance_react(self):
        """Should provide React-specific guidance."""
        prompt = build_xss_prompt(candidates=[], framework="react")
        assert "react" in prompt.lower()

    def test_framework_guidance_angular(self):
        """Should provide Angular-specific guidance."""
        prompt = build_xss_prompt(candidates=[], framework="angular")
        assert "angular" in prompt.lower()

    def test_framework_guidance_vue(self):
        """Should provide Vue-specific guidance."""
        prompt = build_xss_prompt(candidates=[], framework="vue")
        assert "vue" in prompt.lower()

    def test_framework_guidance_django(self):
        """Should provide Django-specific guidance."""
        prompt = build_xss_prompt(candidates=[], framework="django")
        assert "django" in prompt.lower()

    def test_framework_guidance_flask(self):
        """Should provide Flask-specific guidance."""
        prompt = build_xss_prompt(candidates=[], framework="flask")
        assert "flask" in prompt.lower()

    def test_includes_candidates_in_prompt(self):
        """Should include candidate details in prompt."""
        candidates = [
            {
                "id": "XSS-001",
                "file": "components/Comment.jsx",
                "line": 15,
                "sink": "dangerouslySetInnerHTML",
                "code_snippet": "dangerouslySetInnerHTML={{__html: userInput}}"
            }
        ]
        prompt = build_xss_prompt(candidates=candidates)
        assert "XSS-001" in prompt
        assert "components/Comment.jsx" in prompt
        assert "dangerouslySetInnerHTML" in prompt

    def test_analyzer_dangerous_sinks_structure(self):
        """Dangerous sinks should be well-structured."""
        sinks = XSSAnalyzer.dangerous_sinks
        assert "innerhtml" in sinks.lower()
        assert "document.write" in sinks.lower()
        assert "v-html" in sinks.lower()

    def test_analyzer_safe_patterns_structure(self):
        """Safe patterns should include textContent and auto-escape."""
        safe = XSSAnalyzer.safe_patterns
        assert "textcontent" in safe.lower()
        assert "jinja" in safe.lower() or "autoescap" in safe.lower()

    def test_analyzer_poc_patterns_structure(self):
        """PoC patterns should include script and event handlers."""
        poc = XSSAnalyzer.poc_patterns
        assert "script" in poc.lower()
        assert "onerror" in poc.lower()

    def test_analyzer_get_full_prompt(self):
        """get_full_prompt should combine all sections."""
        prompt = XSSAnalyzer.get_full_prompt()
        assert "dangerous" in prompt.lower()
        assert "safe" in prompt.lower()
        assert "poc" in prompt.lower() or "proof" in prompt.lower()

    def test_includes_template_literal_sink(self):
        """Should include template literals as potential sink."""
        prompt = build_xss_prompt(candidates=[])
        assert "template" in prompt.lower()

    def test_includes_render_without_escape_sink(self):
        """Should include render without escape patterns."""
        sinks = XSSAnalyzer.dangerous_sinks
        assert "render" in sinks.lower() or "escape" in sinks.lower()
