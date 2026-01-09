"""Tests for SQL injection analysis prompt."""
import pytest
from prompts.v2.analysis.sql_injection import SQLInjectionAnalyzer, build_sqli_prompt


class TestSQLInjectionAnalyzer:
    def test_includes_sqli_specific_sinks(self):
        prompt = build_sqli_prompt(candidates=[])
        assert "execute" in prompt.lower()
        assert "cursor" in prompt.lower() or "query" in prompt.lower()

    def test_includes_safe_patterns(self):
        prompt = build_sqli_prompt(candidates=[])
        # Should know what's safe to reject FPs
        assert "parameterized" in prompt.lower() or "prepared" in prompt.lower()

    def test_includes_orm_awareness(self):
        prompt = build_sqli_prompt(candidates=[], framework="django")
        assert "orm" in prompt.lower() or "django" in prompt.lower()

    def test_provides_poc_patterns(self):
        prompt = build_sqli_prompt(candidates=[])
        assert "'" in prompt or "union" in prompt.lower() or "or" in prompt.lower()
