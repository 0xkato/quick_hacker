from __future__ import annotations

import json
from typing import Literal

from models.threat_model_profile import ThreatModelPreset, ThreatModelProfile

ProfileSource = Literal["preset", "custom", "migrated"]
ProfileReviewStatus = Literal["unreviewed", "reviewed"]


_CAPABILITY_TO_CHANNELS: dict[str, list[str]] = {
    "remote_network": ["network"],
    "remote_web_content": ["web_content"],
    "untrusted_file_input": ["file_input"],
    "untrusted_repo_content": ["repo_checkout"],
    "untrusted_ci_artifact": ["ci_artifact"],
    # Default (v1): treat local_unprivileged_user as potentially controlling these channels.
    "local_unprivileged_user": ["env", "config", "ipc", "file_input"],
}


def _canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _derived_attacker_controlled_channels(profile: ThreatModelProfile) -> list[str]:
    channels: set[str] = set()
    for cap in profile.attacker_capabilities:
        for channel in _CAPABILITY_TO_CHANNELS.get(cap, []):
            channels.add(channel)
    return sorted(channels)


def build_threat_model_prompt_block(
    *,
    threat_model_preset: ThreatModelPreset,
    profile_source: ProfileSource,
    profile_review_status: ProfileReviewStatus,
    profile_mapping_version: int,
    input_channel_semantics_version: int,
    prompt_threat_model_block_version: int,
    threat_model_profile: ThreatModelProfile,
) -> str:
    derived_channels = _derived_attacker_controlled_channels(threat_model_profile)

    payload = {
        "prompt_threat_model_block_version": int(prompt_threat_model_block_version),
        "profile_mapping_version": int(profile_mapping_version),
        "input_channel_semantics_version": int(input_channel_semantics_version),
        "threat_model_preset": threat_model_preset,
        "profile_source": profile_source,
        "profile_review_status": profile_review_status,
        "threat_model_profile": threat_model_profile.model_dump(mode="json"),
        "derived": {
            "attacker_controlled_input_channels": derived_channels,
            "repo_checkout_rule": (
                "repo_checkout attacker-controlled ONLY if untrusted_repo_content enabled; "
                "else DISPROVEN when deterministically repo_checkout"
            ),
        },
    }

    summary_lines = [
        "=== THREAT MODEL (SUMMARY) ===",
        f"Preset: {threat_model_preset} (source={profile_source}, review={profile_review_status})",
        "Execution contexts: " + ", ".join(threat_model_profile.execution_contexts) if threat_model_profile.execution_contexts else "Execution contexts: (none)",
        "Attacker capabilities: " + ", ".join(threat_model_profile.attacker_capabilities) if threat_model_profile.attacker_capabilities else "Attacker capabilities: (none)",
        "Assets: " + ", ".join(threat_model_profile.assets) if threat_model_profile.assets else "Assets: (none)",
        "Attacker-controlled input channels: " + ", ".join(derived_channels) if derived_channels else "Attacker-controlled input channels: (none)",
        "Hard rule: repo_checkout is attacker-controlled ONLY when untrusted_repo_content is enabled.",
    ]

    return "\n".join(
        summary_lines
        + [
            "",
            "=== THREAT MODEL (AUTHORITATIVE) ===",
            "```json",
            _canonical_json(payload),
            "```",
            "=== END THREAT MODEL ===",
        ]
    )

