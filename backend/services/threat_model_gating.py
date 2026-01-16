"""
Threat model gating logic.

Provides canonical mapping from threat model profile to allowed input channels.
Centralized, unit-testable logic for determining which input channels are
attacker-controlled based on project threat model configuration.
"""

from models.schemas import InputChannel


def derive_allowed_input_channels(threat_model_profile: dict | None) -> set[InputChannel]:
    """
    Derive which input channels are enabled by the threat model profile.

    Args:
        threat_model_profile: Project threat model profile dict with
            'attacker_capabilities' list (e.g., ['remote_network', 'untrusted_file_input'])

    Returns:
        Set of allowed InputChannel enums. If no profile is provided, returns
        all channels (no gating, preserve legacy behavior).

    Example:
        >>> profile = {"attacker_capabilities": ["remote_network", "untrusted_file_input"]}
        >>> allowed = derive_allowed_input_channels(profile)
        >>> InputChannel.network in allowed
        True
        >>> InputChannel.repo_checkout in allowed
        False
    """
    if not threat_model_profile:
        # No profile = no gating (preserve legacy behavior)
        return set(InputChannel)

    caps = set(threat_model_profile.get("attacker_capabilities", []))

    # Canonical mapping: attacker capability → input channels
    cap_to_channels: dict[str, set[InputChannel]] = {
        "remote_network": {InputChannel.network},
        "untrusted_file_input": {InputChannel.file_input},
        "remote_web_content": {InputChannel.web_content},
        "untrusted_repo_content": {InputChannel.repo_checkout},
        "untrusted_ci_artifact": {InputChannel.ci_artifact},
        "local_unprivileged_user": {InputChannel.local_unprivileged},
    }

    allowed: set[InputChannel] = set()
    for cap in caps:
        allowed |= cap_to_channels.get(cap, set())

    # Always allow unknown (non-deterministic won't gate anyway)
    allowed.add(InputChannel.unknown)

    return allowed
