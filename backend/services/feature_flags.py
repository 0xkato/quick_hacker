"""
Feature Flag Service for gradual feature rollout.

Supports:
- Global enable/disable flags
- Percentage-based gradual rollout with deterministic hashing
- User-specific overrides

Priority order (highest to lowest):
1. User override
2. Global enable state
3. Percentage rollout
4. Default False
"""

from enum import Enum
import hashlib
from typing import Dict, Optional


class FeatureFlag(str, Enum):
    """Feature flags for gradual rollout"""
    SPAN_BASED_FLOW = "span_based_flow"
    DUAL_WRITE_MODE = "dual_write_mode"


class FeatureFlagService:
    """
    Service for managing feature flags with percentage-based rollout.

    Features:
    - Global enable/disable: `enable(flag)`, `disable(flag)`, `is_enabled(flag)`
    - Percentage rollout: `set_rollout_percentage(flag, 0-100)`
    - User overrides: `set_user_override(flag, user_id, enabled)`
    - Deterministic: Same user_id always gets same rollout decision

    Example:
        >>> service = FeatureFlagService()
        >>> service.set_rollout_percentage(FeatureFlag.SPAN_BASED_FLOW, 25)
        >>> service.is_enabled_for_user(FeatureFlag.SPAN_BASED_FLOW, "user_123")
        True  # Deterministic - always same for this user
    """

    def __init__(self):
        """Initialize feature flag service with defaults"""
        # Global enable state for each flag
        self._enabled: Dict[FeatureFlag, bool] = {
            FeatureFlag.SPAN_BASED_FLOW: True,  # ENABLED: New span-based visualization
            FeatureFlag.DUAL_WRITE_MODE: True,  # Default: dual write enabled
        }

        # Percentage rollout for each flag (0-100)
        self._rollout_percentage: Dict[FeatureFlag, int] = {}

        # User-specific overrides: {flag: {user_id: enabled}}
        self._user_overrides: Dict[FeatureFlag, Dict[str, Optional[bool]]] = {}

    def is_enabled(self, flag: FeatureFlag) -> bool:
        """
        Check if feature flag is globally enabled.

        Args:
            flag: The feature flag to check

        Returns:
            True if flag is globally enabled, False otherwise
        """
        return self._enabled.get(flag, False)

    def enable(self, flag: FeatureFlag) -> None:
        """
        Enable feature flag globally.

        Args:
            flag: The feature flag to enable
        """
        self._enabled[flag] = True

    def disable(self, flag: FeatureFlag) -> None:
        """
        Disable feature flag globally.

        Args:
            flag: The feature flag to disable
        """
        self._enabled[flag] = False

    def set_rollout_percentage(self, flag: FeatureFlag, percentage: int) -> None:
        """
        Set percentage rollout for a feature flag.

        Uses deterministic hashing to ensure same user_id always gets
        same rollout decision. Hash is based on flag + user_id.

        Args:
            flag: The feature flag to configure
            percentage: Percentage of users who should see the feature (0-100)

        Raises:
            ValueError: If percentage is not between 0 and 100
        """
        if not 0 <= percentage <= 100:
            raise ValueError("Percentage must be between 0 and 100")

        self._rollout_percentage[flag] = percentage

    def is_enabled_for_user(self, flag: FeatureFlag, user_id: str) -> bool:
        """
        Check if feature flag is enabled for a specific user.

        Priority order (highest to lowest):
        1. User override (if set)
        2. Global enable state
        3. Percentage rollout (deterministic hash)
        4. Default False

        Args:
            flag: The feature flag to check
            user_id: The user ID to check for

        Returns:
            True if flag is enabled for this user, False otherwise
        """
        # Priority 1: User override
        user_overrides = self._user_overrides.get(flag, {})
        if user_id in user_overrides:
            override = user_overrides[user_id]
            if override is not None:
                return override

        # Priority 2: Global enable state
        if self._enabled.get(flag, False):
            return True

        # Priority 3: Percentage rollout
        if flag in self._rollout_percentage:
            percentage = self._rollout_percentage[flag]
            return self._is_user_in_rollout(flag, user_id, percentage)

        # Priority 4: Default False
        return False

    def set_user_override(
        self,
        flag: FeatureFlag,
        user_id: str,
        enabled: Optional[bool]
    ) -> None:
        """
        Set user-specific override for a feature flag.

        Override takes priority over all other settings.
        Set enabled=None to remove the override.

        Args:
            flag: The feature flag to override
            user_id: The user ID to override for
            enabled: True to force enable, False to force disable, None to remove override
        """
        if flag not in self._user_overrides:
            self._user_overrides[flag] = {}

        if enabled is None:
            # Remove override
            self._user_overrides[flag].pop(user_id, None)
        else:
            # Set override
            self._user_overrides[flag][user_id] = enabled

    def _is_user_in_rollout(
        self,
        flag: FeatureFlag,
        user_id: str,
        percentage: int
    ) -> bool:
        """
        Determine if user is in percentage rollout using deterministic hashing.

        Uses MD5 hash of "{flag}:{user_id}" to generate a stable value
        in range 0-99, then checks if it's below the percentage threshold.

        Args:
            flag: The feature flag (used in hash for independence)
            user_id: The user ID
            percentage: The rollout percentage (0-100)

        Returns:
            True if user is in rollout, False otherwise
        """
        # Create deterministic hash from flag + user_id
        hash_input = f"{flag.value}:{user_id}"
        hash_bytes = hashlib.md5(hash_input.encode()).digest()

        # Convert first 4 bytes to int, mod 100 for range 0-99
        hash_int = int.from_bytes(hash_bytes[:4], byteorder='big')
        bucket = hash_int % 100

        # User is in rollout if bucket < percentage
        return bucket < percentage


# Global singleton instance
feature_flags = FeatureFlagService()
