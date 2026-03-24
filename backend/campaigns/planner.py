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


def _select_engine(target: object, campaign_preset: str) -> str:
    """Select the best engine for a target based on its kind and language."""
    kind = str(_get(target, "kind", ""))
    # Normalise enum values
    if hasattr(kind, "value"):
        kind = kind.value  # type: ignore[union-attr]
    language = str(_get(target, "language", "")).lower()

    if kind == "api_route":
        return "schemathesis"
    elif kind == "native_function":
        if language == "python":
            return "atheris"
        elif language in ("c", "cpp", "c++"):
            return "aflpp"
        elif language == "java":
            return "jazzer"
        elif language == "go":
            return "go_fuzz"
        elif language == "rust":
            return "cargo_fuzz"
        elif language == "solidity":
            return "echidna"
        else:
            return "radamsa"
    elif kind == "parser":
        return "grammarinator"
    elif kind == "workflow":
        return "restler"
    elif kind == "message_consumer":
        return "boofuzz"
    else:
        return "schemathesis"  # default


def plan_lanes_for_targets(
    targets: list,
    campaign_preset: str = "quick",
) -> list[dict]:
    """Generate lane spec definitions for each target.

    Selects the best fuzzing engine for each target based on its kind
    and language.  API routes use Schemathesis; native functions are
    dispatched to language-specific coverage-guided fuzzers; parsers
    use grammar-based generation; etc.

    Returns a list of lane spec dicts ready for
    ``lane_service.create_lane_specs_batch``.
    """
    budget = LANE_BUDGET_PER_PRESET.get(campaign_preset, 60)
    lanes: list[dict] = []

    for target in targets:
        engine = _select_engine(target, campaign_preset)

        feedback_models = ["api_surface"]
        oracle_packs = ["status_code", "schema_conformance"]

        if _get(target, "stateful", False):
            feedback_models.append("state_depth")
            oracle_packs.append("authz_diff")

        lanes.append(
            {
                "target_id": _get(target, "id"),
                "engine": engine,
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
