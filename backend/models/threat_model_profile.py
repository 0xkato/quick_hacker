from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, Field

ThreatModelPreset = Literal["A", "AB", "ABC"]
ProfileSource = Literal["preset", "custom", "migrated"]

ExecutionContext = Literal[
    "product_runtime",
    "server_runtime",
    "dev_tooling",
    "ci_pipeline",
    "test_harness",
    "test_code",
    "build_release",
]

AttackerCapability = Literal[
    "remote_network",
    "remote_web_content",
    "untrusted_file_input",
    "untrusted_repo_content",
    "untrusted_ci_artifact",
    "local_unprivileged_user",
]

Asset = Literal[
    "user_data",
    "credentials_secrets",
    "availability",
    "integrity_of_build",
    "integrity_of_release_artifacts",
    "developer_machine_integrity",
]


class ThreatModelProfile(BaseModel):
    execution_contexts: list[ExecutionContext] = Field(default_factory=list)
    attacker_capabilities: list[AttackerCapability] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)


def preset_to_profile(preset: ThreatModelPreset) -> ThreatModelProfile:
    if preset == "A":
        return ThreatModelProfile(
            execution_contexts=["product_runtime", "server_runtime"],
            attacker_capabilities=["remote_network", "remote_web_content", "untrusted_file_input"],
            assets=["user_data", "credentials_secrets", "availability"],
        )
    if preset == "AB":
        return ThreatModelProfile(
            execution_contexts=["product_runtime", "server_runtime", "dev_tooling", "ci_pipeline"],
            attacker_capabilities=["remote_network", "remote_web_content", "untrusted_file_input"],
            assets=["user_data", "credentials_secrets", "availability", "integrity_of_build"],
        )
    return ThreatModelProfile(
        execution_contexts=["product_runtime", "server_runtime", "dev_tooling", "ci_pipeline", "build_release", "test_harness"],
        attacker_capabilities=[
            "remote_network",
            "remote_web_content",
            "untrusted_file_input",
            "untrusted_repo_content",
            "untrusted_ci_artifact",
            "local_unprivileged_user",
        ],
        assets=[
            "user_data",
            "credentials_secrets",
            "availability",
            "integrity_of_build",
            "integrity_of_release_artifacts",
            "developer_machine_integrity",
        ],
    )


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_profile_hash(
    *,
    threat_model_preset: ThreatModelPreset,
    profile_source: ProfileSource,
    profile_mapping_version: int,
    input_channel_semantics_version: int,
    prompt_threat_model_block_version: int,
    threat_model_profile: ThreatModelProfile,
) -> str:
    payload = {
        "prompt_threat_model_block_version": int(prompt_threat_model_block_version),
        "profile_mapping_version": int(profile_mapping_version),
        "input_channel_semantics_version": int(input_channel_semantics_version),
        "threat_model_preset": threat_model_preset,
        "profile_source": profile_source,
        "threat_model_profile": {
            "execution_contexts": sorted(threat_model_profile.execution_contexts),
            "attacker_capabilities": sorted(threat_model_profile.attacker_capabilities),
            "assets": sorted(threat_model_profile.assets),
        },
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()

