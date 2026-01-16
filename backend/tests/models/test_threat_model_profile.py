from __future__ import annotations

from models.threat_model_profile import (
    ThreatModelProfile,
    compute_profile_hash,
    preset_to_profile,
)


def test_preset_mapping_ab_does_not_enable_untrusted_repo_content() -> None:
    profile = preset_to_profile("AB")
    assert "untrusted_repo_content" not in profile.attacker_capabilities


def test_profile_hash_changes_when_profile_source_changes() -> None:
    profile = ThreatModelProfile(
        execution_contexts=["product_runtime"],
        attacker_capabilities=["remote_network"],
        assets=["user_data"],
    )
    h1 = compute_profile_hash(
        threat_model_preset="A",
        profile_source="preset",
        profile_mapping_version=1,
        input_channel_semantics_version=1,
        prompt_threat_model_block_version=1,
        threat_model_profile=profile,
    )
    h2 = compute_profile_hash(
        threat_model_preset="A",
        profile_source="custom",
        profile_mapping_version=1,
        input_channel_semantics_version=1,
        prompt_threat_model_block_version=1,
        threat_model_profile=profile,
    )
    assert h1 != h2

