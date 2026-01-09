"""Tests for SSRF analysis prompt."""
import pytest
from prompts.v2.analysis.ssrf import SSRFAnalyzer, build_ssrf_prompt


class TestSSRFAnalyzer:
    def test_includes_ssrf_specific_sinks(self):
        """Should include SSRF-specific dangerous sinks like requests, urllib, fetch."""
        prompt = build_ssrf_prompt(candidates=[])
        # Python sinks
        assert "requests" in prompt.lower()
        assert "urllib" in prompt.lower()
        # Node sinks
        assert "fetch" in prompt.lower() or "axios" in prompt.lower()

    def test_includes_safe_patterns(self):
        """Should include safe patterns like URL allowlists and IP validation."""
        prompt = build_ssrf_prompt(candidates=[])
        # Should know what's safe to reject FPs
        assert "allowlist" in prompt.lower() or "whitelist" in prompt.lower()
        assert "ip" in prompt.lower() or "private" in prompt.lower()

    def test_includes_poc_patterns(self):
        """Should include SSRF PoC patterns like metadata endpoint and localhost."""
        prompt = build_ssrf_prompt(candidates=[])
        # AWS metadata endpoint
        assert "169.254.169.254" in prompt
        # Localhost access
        assert "localhost" in prompt.lower()

    def test_includes_protocol_patterns(self):
        """Should include dangerous protocol patterns like file:// and gopher://."""
        prompt = build_ssrf_prompt(candidates=[])
        assert "file://" in prompt.lower()

    def test_framework_guidance_python_requests(self):
        """Should provide Python requests-specific SSRF guidance."""
        prompt = build_ssrf_prompt(candidates=[], framework="python-requests")
        assert "requests" in prompt.lower()
        assert "redirect" in prompt.lower() or "allow_redirect" in prompt.lower()

    def test_framework_guidance_node_axios(self):
        """Should provide Node axios-specific SSRF guidance."""
        prompt = build_ssrf_prompt(candidates=[], framework="axios")
        assert "axios" in prompt.lower()

    def test_framework_guidance_java_httpclient(self):
        """Should provide Java HttpClient-specific SSRF guidance."""
        prompt = build_ssrf_prompt(candidates=[], framework="java-httpclient")
        assert "httpclient" in prompt.lower() or "java" in prompt.lower()

    def test_includes_candidates_in_prompt(self):
        """Should include candidate details in the prompt."""
        candidates = [
            {
                "id": "SSRF-001",
                "file": "api/fetch.py",
                "line": 42,
                "sink": "requests.get",
                "code_snippet": "requests.get(user_url)",
            }
        ]
        prompt = build_ssrf_prompt(candidates=candidates)
        assert "SSRF-001" in prompt
        assert "api/fetch.py" in prompt
        assert "requests.get" in prompt

    def test_analyzer_dangerous_sinks_content(self):
        """SSRFAnalyzer.dangerous_sinks should list specific HTTP clients."""
        sinks = SSRFAnalyzer.dangerous_sinks
        assert "requests.get" in sinks or "requests" in sinks.lower()
        assert "urllib" in sinks.lower()
        assert "http.client" in sinks.lower() or "httpclient" in sinks.lower()

    def test_analyzer_safe_patterns_content(self):
        """SSRFAnalyzer.safe_patterns should list domain/IP validation patterns."""
        patterns = SSRFAnalyzer.safe_patterns
        assert "allowlist" in patterns.lower() or "whitelist" in patterns.lower()
        # Should mention private IP range blocking
        assert "private" in patterns.lower() or "internal" in patterns.lower()

    def test_analyzer_poc_patterns_content(self):
        """SSRFAnalyzer.poc_patterns should include cloud metadata and localhost."""
        poc = SSRFAnalyzer.poc_patterns
        assert "169.254.169.254" in poc
        assert "localhost" in poc.lower()
        assert "file://" in poc.lower()
