"""Feature flags router - API endpoints for feature flag management."""

from fastapi import APIRouter, Query
from services.feature_flags import feature_flags, FeatureFlag

router = APIRouter()


@router.get("/feature-flags")
async def get_feature_flags(user_id: str = Query(..., description="User ID for flag evaluation")):
    """
    Get feature flags for a specific user.

    Evaluates all feature flags for the given user ID, taking into account:
    - User-specific overrides
    - Global enable/disable states
    - Percentage-based rollout (deterministic based on user ID)

    Returns:
        Dictionary with 'flags' containing flag name -> boolean mapping
    """
    flags_dict = {}

    # Evaluate each flag for this user
    for flag in FeatureFlag:
        flags_dict[flag.value] = feature_flags.is_enabled_for_user(flag, user_id)

    return {"flags": flags_dict}


@router.post("/feature-flags/{flag_name}/enable")
async def enable_flag(flag_name: str):
    """Enable a feature flag globally."""
    try:
        flag = FeatureFlag(flag_name)
        feature_flags.enable(flag)
        return {"status": "enabled", "flag": flag_name}
    except ValueError:
        return {"status": "error", "message": f"Unknown flag: {flag_name}"}


@router.post("/feature-flags/{flag_name}/disable")
async def disable_flag(flag_name: str):
    """Disable a feature flag globally."""
    try:
        flag = FeatureFlag(flag_name)
        feature_flags.disable(flag)
        return {"status": "disabled", "flag": flag_name}
    except ValueError:
        return {"status": "error", "message": f"Unknown flag: {flag_name}"}


@router.post("/feature-flags/{flag_name}/rollout")
async def set_rollout(flag_name: str, percentage: int = Query(..., ge=0, le=100)):
    """Set percentage rollout for a feature flag."""
    try:
        flag = FeatureFlag(flag_name)
        feature_flags.set_rollout_percentage(flag, percentage)
        return {"status": "updated", "flag": flag_name, "percentage": percentage}
    except ValueError as e:
        return {"status": "error", "message": str(e)}
