from __future__ import annotations

import json

from models.threat_model_profile import ThreatModelProfile


def test_prompt_block_contains_authoritative_json_and_summary() -> None:
    from services.threat_model_prompt_block import build_threat_model_prompt_block

    block = build_threat_model_prompt_block(
        threat_model_preset="AB",
        profile_source="preset",
        profile_review_status="unreviewed",
        profile_mapping_version=1,
        input_channel_semantics_version=1,
        prompt_threat_model_block_version=1,
        threat_model_profile=ThreatModelProfile(
            execution_contexts=["product_runtime"],
            attacker_capabilities=["remote_network", "untrusted_file_input"],
            assets=["user_data"],
        ),
    )
    assert "=== THREAT MODEL (AUTHORITATIVE) ===" in block
    assert "```json" in block

    json_start = block.index("```json") + len("```json")
    json_end = block.index("```", json_start)
    payload = json.loads(block[json_start:json_end].strip())
    assert payload["threat_model_preset"] == "AB"
    assert "derived" in payload
    assert "file_input" in payload["derived"]["attacker_controlled_input_channels"]

