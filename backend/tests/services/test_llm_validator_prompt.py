"""Tests for LLM validator prompt generation with ValidationProfile."""
import pytest
from unittest.mock import MagicMock
from models.validation_profile import (
    ValidationProfile,
    AttackerRole,
    TrustBoundary,
    CategoryEvidenceGate,
)


class TestValidatorPrompt:
    @pytest.fixture
    def validator(self):
        try:
            from services.validation.llm_validator import LLMFindingValidator
            return LLMFindingValidator(
                anthropic_api_key="test-key",
                repo_root="/tmp/test",
            )
        except RuntimeError:
            pytest.skip("anthropic package not installed")

    @pytest.fixture
    def sample_profile(self):
        return ValidationProfile(
            excluded_paths=["tools/", "test/"],
            attacker_roles={
                "remote_web": AttackerRole(
                    can_control=["http_body", "url_params"],
                    cannot_control=["cli_args", "local_files"],
                ),
            },
            trust_boundaries={
                "sandbox": TrustBoundary(
                    untrusted_side=["renderer"],
                    trusted_side=["browser"],
                    description="Sandbox escape",
                ),
            },
            evidence_gates={
                "memory_corruption": CategoryEvidenceGate(
                    required=["crash_proven"],
                    reject_if=["test_only"],
                    verifiers=["gdb"],
                ),
            },
        )

    @pytest.fixture
    def sample_finding(self):
        mock = MagicMock()
        mock.title = "Buffer overflow in parse_input"
        mock.vulnerability_type = "memory_corruption"
        mock.file_path = "src/parser.c"
        mock.line_start = 100
        mock.code_snippet = "memcpy(buf, input, len);"
        return mock

    def test_prompt_includes_attacker_roles(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "remote_web" in prompt
        assert "http_body" in prompt
        assert "cli_args" in prompt

    def test_prompt_includes_trust_boundaries(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "sandbox" in prompt.lower() or "renderer" in prompt

    def test_prompt_includes_evidence_requirements(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "crash_proven" in prompt or "MISSING" in prompt

    def test_prompt_includes_excluded_paths(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "tools/" in prompt
        assert "test/" in prompt

    def test_prompt_includes_reject_conditions(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "test_only" in prompt

    def test_prompt_response_format(self, validator, sample_profile, sample_finding):
        prompt = validator._build_validation_prompt_with_profile(
            finding=sample_finding,
            validation_profile=sample_profile,
        )
        assert "CANDIDATE" in prompt
        assert "NOT_ACTIONABLE" in prompt
        assert "EVIDENCE" in prompt
