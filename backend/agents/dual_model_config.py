"""Configuration resolution for dual-model analysis."""

from typing import Optional, Tuple
from models.schemas import ProviderConfig, ProviderType, AgentCreateRequest, HandoffMode


# Default cheap models by provider
DEFAULT_SCANNER_MODELS = {
    ProviderType.ANTHROPIC: "claude-3-5-haiku-20241022",
    ProviderType.OPENAI: "gpt-4o-mini",
    ProviderType.OLLAMA: None,  # Use same model
}


def resolve_dual_model_config(
    request: AgentCreateRequest
) -> Tuple[Optional[ProviderConfig], Optional[ProviderConfig], bool]:
    """
    Resolve scanner and analyzer configs from request.

    Returns:
        (scanner_config, analyzer_config, is_dual_mode)

    Resolution logic:
    1. provider_config only → single-model mode (backwards compat)
    2. analyzer_config only → auto-select scanner from same provider
    3. both scanner + analyzer → use as specified
    4. scanner only → error
    """
    has_legacy = request.provider_config is not None
    has_scanner = request.scanner_config is not None
    has_analyzer = request.analyzer_config is not None

    # Case 1: Legacy single-model mode
    if has_legacy and not has_scanner and not has_analyzer:
        return (None, None, False)

    # Case 4: Scanner only - invalid
    if has_scanner and not has_analyzer and not has_legacy:
        raise ValueError(
            "scanner_config requires analyzer_config. "
            "Provide both or use provider_config for single-model mode."
        )

    # Case 3: Both specified - use as-is
    if has_scanner and has_analyzer:
        return (request.scanner_config, request.analyzer_config, True)

    # Case 2: Analyzer only - auto-select scanner
    if has_analyzer and not has_scanner:
        analyzer = request.analyzer_config
        scanner_model = DEFAULT_SCANNER_MODELS.get(analyzer.provider)

        if scanner_model is None:
            # For Ollama, use same model (no cheap tier)
            scanner_model = analyzer.model

        scanner_config = ProviderConfig(
            provider=analyzer.provider,
            model=scanner_model,
            api_key=analyzer.api_key,
            base_url=analyzer.base_url,
            temperature=0.0,
            max_tokens=4096,
        )

        return (scanner_config, analyzer, True)

    # Fallback: legacy mode
    return (None, None, False)


def get_handoff_mode(request: AgentCreateRequest) -> HandoffMode:
    """Get the handoff mode from request, defaulting to sink_identification."""
    return request.handoff_after if hasattr(request, 'handoff_after') else HandoffMode.SINK_IDENTIFICATION
