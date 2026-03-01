"""Tests for dual-model config resolution."""

import pytest
from models.schemas import ProviderConfig, ProviderType, AgentCreateRequest, AgentType, HandoffMode
from agents.dual_model_config import resolve_dual_model_config, get_handoff_mode


class TestResolveDualModelConfig:
    def test_legacy_single_model_mode(self):
        """provider_config only → single-model mode."""
        request = AgentCreateRequest(
            repo_id="test-repo",
            agent_type=AgentType.CUSTOM,
            provider_config=ProviderConfig(
                provider=ProviderType.ANTHROPIC,
                model="claude-opus-4-6"
            )
        )

        scanner, analyzer, is_dual = resolve_dual_model_config(request)

        assert scanner is None
        assert analyzer is None
        assert is_dual is False

    def test_analyzer_only_auto_selects_scanner(self):
        """analyzer_config only → auto-select cheap scanner."""
        request = AgentCreateRequest(
            repo_id="test-repo",
            agent_type=AgentType.CUSTOM,
            analyzer_config=ProviderConfig(
                provider=ProviderType.ANTHROPIC,
                model="claude-opus-4-6",
                api_key="test-key"
            )
        )

        scanner, analyzer, is_dual = resolve_dual_model_config(request)

        assert is_dual is True
        assert scanner is not None
        assert scanner.model == "claude-3-5-haiku-20241022"
        assert scanner.provider == ProviderType.ANTHROPIC
        assert scanner.api_key == "test-key"
        assert analyzer.model == "claude-opus-4-6"

    def test_both_configs_uses_as_specified(self):
        """Both scanner + analyzer → use as specified."""
        request = AgentCreateRequest(
            repo_id="test-repo",
            agent_type=AgentType.CUSTOM,
            scanner_config=ProviderConfig(
                provider=ProviderType.OPENAI,
                model="gpt-4o-mini"
            ),
            analyzer_config=ProviderConfig(
                provider=ProviderType.ANTHROPIC,
                model="claude-opus-4-6"
            )
        )

        scanner, analyzer, is_dual = resolve_dual_model_config(request)

        assert is_dual is True
        assert scanner.provider == ProviderType.OPENAI
        assert scanner.model == "gpt-4o-mini"
        assert analyzer.provider == ProviderType.ANTHROPIC
        assert analyzer.model == "claude-opus-4-6"

    def test_scanner_only_raises_error(self):
        """scanner_config only → error."""
        request = AgentCreateRequest(
            repo_id="test-repo",
            agent_type=AgentType.CUSTOM,
            scanner_config=ProviderConfig(
                provider=ProviderType.OPENAI,
                model="gpt-4o-mini"
            )
        )

        with pytest.raises(ValueError, match="scanner_config requires analyzer_config"):
            resolve_dual_model_config(request)

    def test_ollama_uses_same_model(self):
        """Ollama analyzer → scanner uses same model."""
        request = AgentCreateRequest(
            repo_id="test-repo",
            agent_type=AgentType.CUSTOM,
            analyzer_config=ProviderConfig(
                provider=ProviderType.OLLAMA,
                model="llama3.3"
            )
        )

        scanner, analyzer, is_dual = resolve_dual_model_config(request)

        assert is_dual is True
        assert scanner.model == "llama3.3"  # Same model, no cheap tier


class TestGetHandoffMode:
    def test_default_is_sink_identification(self):
        """Default handoff mode is sink_identification."""
        request = AgentCreateRequest(
            repo_id="test-repo",
            agent_type=AgentType.CUSTOM,
            provider_config=ProviderConfig(
                provider=ProviderType.ANTHROPIC,
                model="claude-opus-4-6"
            )
        )

        mode = get_handoff_mode(request)
        assert mode == HandoffMode.SINK_IDENTIFICATION

    def test_explicit_exploration_mode(self):
        """Explicit exploration handoff mode."""
        request = AgentCreateRequest(
            repo_id="test-repo",
            agent_type=AgentType.CUSTOM,
            analyzer_config=ProviderConfig(
                provider=ProviderType.ANTHROPIC,
                model="claude-opus-4-6"
            ),
            handoff_after=HandoffMode.EXPLORATION
        )

        mode = get_handoff_mode(request)
        assert mode == HandoffMode.EXPLORATION
