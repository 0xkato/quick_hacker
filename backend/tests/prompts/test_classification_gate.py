"""Tests for classification gate prompt template."""

import pytest

from prompts.classification_gate import get_classification_gate_prompt


class TestGetClassificationGatePrompt:
    """Tests for get_classification_gate_prompt function."""

    def test_returns_string(self):
        """Function should return a string."""
        result = get_classification_gate_prompt("A")
        assert isinstance(result, str)

    def test_includes_threat_model_a(self):
        """Prompt should include threat model A when provided."""
        result = get_classification_gate_prompt("A")
        # Should include the threat model in the output
        assert "A" in result
        # Should be formatted properly
        assert "{{threat_model}}" not in result

    def test_includes_threat_model_ab(self):
        """Prompt should include threat model AB when provided."""
        result = get_classification_gate_prompt("AB")
        assert "AB" in result
        assert "{{threat_model}}" not in result

    def test_includes_threat_model_abc(self):
        """Prompt should include threat model ABC when provided."""
        result = get_classification_gate_prompt("ABC")
        assert "ABC" in result
        assert "{{threat_model}}" not in result

    def test_works_with_all_threat_models(self):
        """Function should work with all threat model values."""
        for threat_model in ["A", "AB", "ABC"]:
            result = get_classification_gate_prompt(threat_model)
            assert isinstance(result, str)
            assert len(result) > 0
            assert threat_model in result

    def test_prompt_contains_classification_types(self):
        """Generated prompt should mention all classification types."""
        result = get_classification_gate_prompt("A")
        result_lower = result.lower()
        assert "security_issue" in result_lower
        assert "bug" in result_lower
        assert "misconfiguration" in result_lower
        assert "hardening" in result_lower

    def test_prompt_contains_output_fields(self):
        """Generated prompt should specify all output fields."""
        result = get_classification_gate_prompt("A")
        result_lower = result.lower()
        assert "classification" in result_lower
        assert "config_dependent" in result_lower
        assert "config_flag" in result_lower
        assert "default_secure" in result_lower
        assert "contradiction_present" in result_lower
        assert "fix_type" in result_lower
        assert "classification_reasoning" in result_lower

    def test_prompt_mentions_key_constraints(self):
        """Generated prompt should preserve key classification constraints."""
        result_lower = get_classification_gate_prompt("A").lower()
        assert "not permitted" in result_lower
        assert "threat model" in result_lower


class TestGetClassificationGatePromptValidation:
    """Tests for input validation in get_classification_gate_prompt function."""

    def test_empty_string_raises_value_error(self):
        """Empty string should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_classification_gate_prompt("")
        assert "threat_model" in str(exc_info.value).lower()

    def test_invalid_threat_model_raises_value_error(self):
        """Invalid threat model value like 'X' should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_classification_gate_prompt("X")
        assert "threat_model" in str(exc_info.value).lower()

    def test_lowercase_a_raises_value_error(self):
        """Lowercase 'a' should raise ValueError (only uppercase accepted)."""
        with pytest.raises(ValueError) as exc_info:
            get_classification_gate_prompt("a")
        assert "threat_model" in str(exc_info.value).lower()

    def test_lowercase_ab_raises_value_error(self):
        """Lowercase 'ab' should raise ValueError (only uppercase accepted)."""
        with pytest.raises(ValueError) as exc_info:
            get_classification_gate_prompt("ab")
        assert "threat_model" in str(exc_info.value).lower()

    def test_lowercase_abc_raises_value_error(self):
        """Lowercase 'abc' should raise ValueError (only uppercase accepted)."""
        with pytest.raises(ValueError) as exc_info:
            get_classification_gate_prompt("abc")
        assert "threat_model" in str(exc_info.value).lower()

    def test_mixed_case_Ab_raises_value_error(self):
        """Mixed case 'Ab' should raise ValueError (only exact uppercase accepted)."""
        with pytest.raises(ValueError) as exc_info:
            get_classification_gate_prompt("Ab")
        assert "threat_model" in str(exc_info.value).lower()

    def test_whitespace_only_raises_value_error(self):
        """Whitespace-only string should raise ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_classification_gate_prompt("   ")
        assert "threat_model" in str(exc_info.value).lower()

    def test_valid_uppercase_a_does_not_raise(self):
        """Valid uppercase 'A' should not raise."""
        result = get_classification_gate_prompt("A")
        assert isinstance(result, str)

    def test_valid_uppercase_ab_does_not_raise(self):
        """Valid uppercase 'AB' should not raise."""
        result = get_classification_gate_prompt("AB")
        assert isinstance(result, str)

    def test_valid_uppercase_abc_does_not_raise(self):
        """Valid uppercase 'ABC' should not raise."""
        result = get_classification_gate_prompt("ABC")
        assert isinstance(result, str)
