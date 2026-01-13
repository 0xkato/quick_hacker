"""Tests for FeatureFlagService"""
import pytest
from services.feature_flags import FeatureFlagService, FeatureFlag


def test_feature_flag_enabled():
    """Feature flags should support enable/disable operations"""
    service = FeatureFlagService()

    # Default should be False
    assert service.is_enabled(FeatureFlag.SPAN_BASED_FLOW) is False

    # Enable flag
    service.enable(FeatureFlag.SPAN_BASED_FLOW)
    assert service.is_enabled(FeatureFlag.SPAN_BASED_FLOW) is True

    # Disable flag
    service.disable(FeatureFlag.SPAN_BASED_FLOW)
    assert service.is_enabled(FeatureFlag.SPAN_BASED_FLOW) is False


def test_feature_flag_rollout_percentage():
    """Feature flags should support deterministic percentage-based rollout"""
    service = FeatureFlagService()

    # Set 50% rollout for SPAN_BASED_FLOW
    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 50)

    # Test multiple user IDs - should get consistent results
    user_ids = [f"user_{i}" for i in range(100)]

    # First pass - record results
    first_pass = {}
    enabled_count = 0
    for user_id in user_ids:
        enabled = service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id)
        first_pass[user_id] = enabled
        if enabled:
            enabled_count += 1

    # Second pass - should be identical (deterministic)
    for user_id in user_ids:
        enabled = service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id)
        assert enabled == first_pass[user_id], f"Non-deterministic result for {user_id}"

    # Should be approximately 50% (allow 35-65% range for randomness)
    assert 35 <= enabled_count <= 65, f"Expected ~50%, got {enabled_count}%"


def test_user_override():
    """User overrides should take priority over global and percentage settings"""
    service = FeatureFlagService()

    # Set 0% rollout (nobody gets it by default)
    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 0)

    user_id = "test_user"

    # Default: user should not have access (0% rollout)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is False

    # Override: enable for specific user
    service.set_user_override(FeatureFlag.SPAN_BASED_FLOW, user_id, True)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is True

    # Override: disable for specific user (even if we enable globally)
    service.enable(FeatureFlag.SPAN_BASED_FLOW)
    service.set_user_override(FeatureFlag.SPAN_BASED_FLOW, user_id, False)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is False


def test_invalid_percentage():
    """Setting rollout percentage should validate 0-100 range"""
    service = FeatureFlagService()

    # Valid percentages should work
    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 0)
    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 50)
    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 100)

    # Invalid percentages should raise ValueError
    with pytest.raises(ValueError, match="Percentage must be between 0 and 100"):
        service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, -1)

    with pytest.raises(ValueError, match="Percentage must be between 0 and 100"):
        service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 101)


def test_priority_order():
    """Priority order: user override > global enable > percentage rollout > default False"""
    service = FeatureFlagService()

    user_id = "test_user"

    # Test 1: Default False
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is False

    # Test 2: Percentage rollout (set 100% so we know user is eligible)
    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 100)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is True

    # Test 3: Global enable beats percentage
    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 0)
    service.enable(FeatureFlag.SPAN_BASED_FLOW)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is True

    # Test 4: User override beats everything
    service.set_user_override(FeatureFlag.SPAN_BASED_FLOW, user_id, False)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is False


def test_deterministic_hashing():
    """Same user_id should always get same rollout result"""
    service = FeatureFlagService()

    service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 50)

    user_id = "deterministic_user_123"

    # Call 100 times - should always be same result
    results = [
        service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id)
        for _ in range(100)
    ]

    # All results should be identical
    assert all(r == results[0] for r in results), "Hashing is not deterministic"


def test_dual_write_mode_default():
    """DUAL_WRITE_MODE should default to True, SPAN_BASED_FLOW to False"""
    service = FeatureFlagService()

    # SPAN_BASED_FLOW defaults to False
    assert service.is_enabled(FeatureFlag.SPAN_BASED_FLOW) is False

    # DUAL_WRITE_MODE defaults to True
    assert service.is_enabled(FeatureFlag.DUAL_WRITE_MODE) is True


def test_different_flags_independent():
    """Different flags should operate independently"""
    service = FeatureFlagService()

    # Enable one flag
    service.enable(FeatureFlag.SPAN_BASED_FLOW)
    assert service.is_enabled(FeatureFlag.SPAN_BASED_FLOW) is True
    assert service.is_enabled(FeatureFlag.DUAL_WRITE_MODE) is True  # Default

    # Disable the other
    service.disable(FeatureFlag.DUAL_WRITE_MODE)
    assert service.is_enabled(FeatureFlag.SPAN_BASED_FLOW) is True  # Unchanged
    assert service.is_enabled(FeatureFlag.DUAL_WRITE_MODE) is False


def test_remove_user_override():
    """Should be able to remove user override by setting to None"""
    service = FeatureFlagService()

    user_id = "test_user"

    # Set override
    service.set_user_override(FeatureFlag.SPAN_BASED_FLOW, user_id, True)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is True

    # Remove override (None means no override)
    service.set_user_override(FeatureFlag.SPAN_BASED_FLOW, user_id, None)

    # Should fall back to default (False)
    assert service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, user_id) is False
