"""Provider adaptation layer - handles model-specific formatting."""

from enum import Enum


class ProviderType(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    GENERIC = "generic"


class ProviderAdapter:
    """Adapts prompts for different LLM providers."""

    MODEL_PREFIXES = {
        "gpt-": ProviderType.OPENAI,
        "o1": ProviderType.OPENAI,
        "claude-": ProviderType.ANTHROPIC,
        "gemini-": ProviderType.GOOGLE,
    }

    # GPT-5.2 style verbosity spec
    VERBOSITY_SPEC = """
<output_verbosity_spec>
- Progress: 3-5 lines max, one concrete outcome per update
- NO tool narration ("reading file...", "searching...")
- Findings: structured JSON only, minimal prose
- Uncertainty: explicit markers (CANDIDATE, UNCONFIRMED), no hedging
</output_verbosity_spec>
"""

    def detect_provider(self, model_name: str) -> ProviderType:
        model_lower = model_name.lower()
        for prefix, provider in self.MODEL_PREFIXES.items():
            if model_lower.startswith(prefix):
                return provider
        return ProviderType.GENERIC

    def format_prompt(
        self,
        base_prompt: str,
        model_name: str,
        include_verbosity: bool = True,
    ) -> str:
        """Format prompt with provider-specific adaptations."""
        parts = []

        if include_verbosity:
            parts.append(self.VERBOSITY_SPEC.strip())

        parts.append(base_prompt.strip())

        return "\n\n".join(parts)
