"""Deterministic lane planner for v1 campaigns.

Given targets extracted from an OpenAPI spec, assigns one Schemathesis lane
per API route target.  No LM needed — this is a pure, deterministic mapping.
"""

from __future__ import annotations

LANE_BUDGET_PER_PRESET: dict[str, int] = {
    "quick": 60,
    "medium": 180,
    "advanced": 600,
    "pro": 1800,
    "ultra": 3600,
    "evil": 7200,
}


def _get(target, key, default=None):
    """Read *key* from a dict or an object with attributes."""
    if isinstance(target, dict):
        return target.get(key, default)
    return getattr(target, key, default)


def plan_lanes_for_targets(
    targets: list,
    campaign_preset: str = "quick",
) -> list[dict]:
    """Generate lane spec definitions for each API route target.

    v1: One schema-property Schemathesis lane per ``api_route`` target.
    Non-``api_route`` targets are silently skipped.

    Returns a list of lane spec dicts ready for
    ``lane_service.create_lane_specs_batch``.
    """
    budget = LANE_BUDGET_PER_PRESET.get(campaign_preset, 60)
    lanes: list[dict] = []

    for target in targets:
        kind = _get(target, "kind")
        kind_str = kind.value if hasattr(kind, "value") else str(kind)
        if kind_str != "api_route":
            continue

        feedback_models = ["api_surface"]
        oracle_packs = ["status_code", "schema_conformance"]

        if _get(target, "stateful", False):
            feedback_models.append("state_depth")
            oracle_packs.append("authz_diff")

        lanes.append(
            {
                "target_id": _get(target, "id"),
                "engine": "schemathesis",
                "structure_model": "schema",
                "input_producer": "generation",
                "feedback_models": feedback_models,
                "oracle_packs": oracle_packs,
                "budget_seconds": budget,
                "seed_sources": ["openapi_examples"],
                "status": "planned",
            }
        )

    return lanes
