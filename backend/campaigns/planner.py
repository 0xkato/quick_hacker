"""Deterministic lane planner for v1 campaigns.

Given targets, assigns one lane per target using the best engine for the
target's kind and language.  No LM needed — this is a pure, deterministic
mapping.  Targets are capped per preset to keep compilation tractable.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

LANE_BUDGET_PER_PRESET: dict[str, int] = {
    "quick": 60,
    "medium": 180,
    "advanced": 600,
    "pro": 1800,
    "ultra": 3600,
    "evil": 7200,
}

# Max lanes per preset — prevents creating thousands of lanes for large repos.
# Higher tiers get more lanes. Targets are sorted by priority_score so the
# most promising targets are always included.
MAX_LANES_PER_PRESET: dict[str, int] = {
    "quick": 10,
    "medium": 25,
    "advanced": 50,
    "pro": 100,
    "ultra": 200,
    "evil": 500,
}


def _get(target, key, default=None):
    """Read *key* from a dict or an object with attributes."""
    if isinstance(target, dict):
        return target.get(key, default)
    return getattr(target, key, default)


def _select_engine(target: object, campaign_preset: str) -> str:
    """Select the best engine for a target based on its kind and language."""
    raw_kind = _get(target, "kind", "")
    kind = raw_kind.value if hasattr(raw_kind, "value") else str(raw_kind)
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
    enabled_engines: list[str] | None = None,
) -> list[dict]:
    """Generate lane spec definitions for each target.

    Selects the best fuzzing engine for each target based on its kind
    and language.  API routes use Schemathesis; native functions are
    dispatched to language-specific coverage-guided fuzzers; parsers
    use grammar-based generation; etc.

    If ``enabled_engines`` is provided, only engines in the list are
    used.  Targets that would require a non-enabled engine are skipped.

    Returns a list of lane spec dicts ready for
    ``lane_service.create_lane_specs_batch``.
    """
    budget = LANE_BUDGET_PER_PRESET.get(campaign_preset, 60)
    max_lanes = MAX_LANES_PER_PRESET.get(campaign_preset, 50)
    lanes: list[dict] = []

    # Sort by priority so the cap keeps the most promising targets
    targets = sorted(targets, key=lambda t: _get(t, "priority_score", 0.0), reverse=True)

    for target in targets:
        engine = _select_engine(target, campaign_preset)

        # Respect enabled_engines filter: skip targets whose engine is not enabled
        if enabled_engines and engine not in enabled_engines:
            continue

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

        if len(lanes) >= max_lanes:
            break

    if len(lanes) < len(targets):
        logger.info("Planned %d lanes from %d targets (capped at %d for %s preset)",
                     len(lanes), len(targets), max_lanes, campaign_preset)

    return lanes
