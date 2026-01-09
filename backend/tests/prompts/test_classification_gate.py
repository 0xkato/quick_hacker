"""Tests for classification gate prompt template."""

import pytest

from prompts.classification_gate import (
    CLASSIFICATION_RULES,
    CLASSIFICATION_GATE_TEMPLATE,
    get_classification_gate_prompt,
)


class TestClassificationRules:
    """Tests for CLASSIFICATION_RULES constant."""

    def test_rules_is_string(self):
        """CLASSIFICATION_RULES should be a string constant."""
        assert isinstance(CLASSIFICATION_RULES, str)

    def test_rules_not_empty(self):
        """CLASSIFICATION_RULES should not be empty."""
        assert len(CLASSIFICATION_RULES) > 0

    def test_rules_mentions_security_issue_constraint(self):
        """Rules should mention NOT PERMITTED to label SECURITY_ISSUE when security disabled."""
        rules_lower = CLASSIFICATION_RULES.lower()
        assert "security" in rules_lower
        assert "disabled" in rules_lower or "not permitted" in rules_lower.replace("_", " ")

    def test_rules_mentions_config_flags_constraint(self):
        """Rules should mention NOT PERMITTED to remove documented config flags."""
        rules_lower = CLASSIFICATION_RULES.lower()
        assert "config" in rules_lower
        assert "documented" in rules_lower or "flag" in rules_lower

    def test_rules_mentions_threat_model_downgrade(self):
        """Rules should mention MUST downgrade to MISCONFIGURATION if outside threat model."""
        rules_lower = CLASSIFICATION_RULES.lower()
        assert "downgrade" in rules_lower or "misconfiguration" in rules_lower
        assert "threat" in rules_lower or "model" in rules_lower


class TestClassificationGateTemplate:
    """Tests for CLASSIFICATION_GATE_TEMPLATE constant."""

    def test_template_is_string(self):
        """CLASSIFICATION_GATE_TEMPLATE should be a string constant."""
        assert isinstance(CLASSIFICATION_GATE_TEMPLATE, str)

    def test_template_has_threat_model_placeholder(self):
        """Template should have {threat_model} placeholder."""
        assert "{threat_model}" in CLASSIFICATION_GATE_TEMPLATE

    def test_template_has_rules_placeholder(self):
        """Template should have {rules} placeholder."""
        assert "{rules}" in CLASSIFICATION_GATE_TEMPLATE

    def test_template_mentions_step1_configuration_dependency(self):
        """Template should mention Step 1: Configuration Dependency check."""
        template_lower = CLASSIFICATION_GATE_TEMPLATE.lower()
        assert "step 1" in template_lower or "configuration" in template_lower
        assert "dependency" in template_lower or "config" in template_lower

    def test_template_mentions_step2_threat_model(self):
        """Template should mention Step 2: Threat Model check."""
        template_lower = CLASSIFICATION_GATE_TEMPLATE.lower()
        assert "threat" in template_lower
        assert "model" in template_lower

    def test_template_mentions_step3_attack_scenario(self):
        """Template should mention Step 3: Attack Scenario requirements."""
        template_lower = CLASSIFICATION_GATE_TEMPLATE.lower()
        assert "attack" in template_lower
        assert "scenario" in template_lower

    def test_template_mentions_step4_classification_decision(self):
        """Template should mention Step 4: Classification Decision."""
        template_lower = CLASSIFICATION_GATE_TEMPLATE.lower()
        assert "classification" in template_lower
        assert "decision" in template_lower

    def test_template_mentions_all_classification_types(self):
        """Template should mention all 4 classification types."""
        template_lower = CLASSIFICATION_GATE_TEMPLATE.lower()
        assert "security_issue" in template_lower
        assert "bug" in template_lower
        assert "misconfiguration" in template_lower
        assert "hardening" in template_lower

    def test_template_specifies_all_output_fields(self):
        """Template should specify all required output fields."""
        template_lower = CLASSIFICATION_GATE_TEMPLATE.lower()
        # All required output fields
        assert "classification" in template_lower
        assert "config_dependent" in template_lower
        assert "config_flag" in template_lower
        assert "default_secure" in template_lower
        assert "contradiction_present" in template_lower
        assert "fix_type" in template_lower
        assert "classification_reasoning" in template_lower


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
        assert "{threat_model}" not in result

    def test_includes_threat_model_ab(self):
        """Prompt should include threat model AB when provided."""
        result = get_classification_gate_prompt("AB")
        assert "AB" in result
        assert "{threat_model}" not in result

    def test_includes_threat_model_abc(self):
        """Prompt should include threat model ABC when provided."""
        result = get_classification_gate_prompt("ABC")
        assert "ABC" in result
        assert "{threat_model}" not in result

    def test_includes_classification_rules(self):
        """Prompt should include classification rules."""
        result = get_classification_gate_prompt("A")
        # Rules should be included (not the placeholder)
        assert "{rules}" not in result
        # Should contain some of the rule content
        assert "not permitted" in result.lower() or "security" in result.lower()

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
