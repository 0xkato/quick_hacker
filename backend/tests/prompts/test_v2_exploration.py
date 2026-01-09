"""Tests for exploration phase prompt."""
import pytest
from prompts.v2.phases.exploration import ExplorationPrompt, build_exploration_prompt


class TestExplorationPrompt:
    def test_focuses_on_context_gathering(self):
        prompt = build_exploration_prompt(repo_name="test-repo")
        assert "map" in prompt.lower() or "explore" in prompt.lower()
        assert "structure" in prompt.lower() or "architecture" in prompt.lower()

    def test_does_not_find_vulnerabilities(self):
        prompt = build_exploration_prompt(repo_name="test-repo")
        # Should explicitly say NOT to find vulns yet
        assert "not" in prompt.lower() and ("vulnerabilit" in prompt.lower() or "finding" in prompt.lower())

    def test_specifies_tool_usage(self):
        prompt = build_exploration_prompt(repo_name="test-repo")
        # Should mention tools it works with
        assert "file" in prompt.lower() or "tool" in prompt.lower()

    def test_defines_expected_output(self):
        prompt = build_exploration_prompt(repo_name="test-repo")
        # Should specify what to output
        assert "entry point" in prompt.lower() or "entrypoint" in prompt.lower()
        assert "tech" in prompt.lower() or "stack" in prompt.lower() or "framework" in prompt.lower()

    def test_includes_repo_context(self):
        prompt = build_exploration_prompt(
            repo_name="my-app",
            repo_root="/code/my-app",
            known_languages=["python", "javascript"]
        )
        assert "my-app" in prompt
        assert "python" in prompt.lower()
