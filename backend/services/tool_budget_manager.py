"""
Tool budget manager for First-Party Focus.

Manages tool execution budget split between first-party and third-party code.
80/20 split: 80% for first-party, 20% for third-party (supporting evidence).
"""

from services.file_origin import FileOrigin

# Budget bucket constants
BUCKET_FIRST_PARTY = "first_party"
BUCKET_THIRD_PARTY = "third_party"


class ThirdPartyBudgetExceeded(Exception):
    """Third-party budget exhausted."""
    pass


class FirstPartyBudgetExceeded(Exception):
    """First-party budget exhausted."""
    pass


class ToolBudgetManager:
    """
    Manages tool execution budget split between first-party and third-party code.

    80/20 split: 80% for first-party, 20% for third-party (supporting evidence).
    Prevents spending excessive time analyzing library code.
    """

    def __init__(self, total_ms: int):
        """
        Initialize budget manager.

        Args:
            total_ms: Total tool execution budget in milliseconds
        """
        self.total_ms = total_ms
        self.first_party_ms_limit = int(total_ms * 0.80)
        self.third_party_ms_limit = total_ms - self.first_party_ms_limit

        self.first_party_ms_used = 0
        self.third_party_ms_used = 0

    def charge(self, origin: FileOrigin, duration_ms: int) -> None:
        """
        Charge tool execution time to appropriate budget bucket.

        Args:
            origin: File origin classification
            duration_ms: Tool execution duration in milliseconds

        Raises:
            ThirdPartyBudgetExceeded: If third-party budget exhausted
            FirstPartyBudgetExceeded: If first-party budget exhausted
        """
        if origin in {FileOrigin.third_party, FileOrigin.external}:
            if self.third_party_ms_used + duration_ms > self.third_party_ms_limit:
                raise ThirdPartyBudgetExceeded(
                    self._format_exhausted_error(BUCKET_THIRD_PARTY)
                )
            self.third_party_ms_used += duration_ms
        else:
            # Treat unknown/test/generated as first_party bucket
            if self.first_party_ms_used + duration_ms > self.first_party_ms_limit:
                raise FirstPartyBudgetExceeded(
                    self._format_exhausted_error(BUCKET_FIRST_PARTY)
                )
            self.first_party_ms_used += duration_ms

    def _format_exhausted_error(self, bucket: str) -> str:
        """Format budget exhausted error with actionable message."""
        stats = self.get_stats()
        bucket_stats = stats[bucket]  # FIXED: matches get_stats() keys

        # Display with hyphen for readability
        display_name = bucket.replace("_", "-").capitalize()

        return (
            f"{display_name} budget exhausted: "
            f"{bucket_stats['used_ms']}ms used, {bucket_stats['limit_ms']}ms limit. "
            f"Narrow your search to first-party roots or justify entering "
            f"dependencies for a concrete dataflow path."
        )

    def get_stats(self) -> dict:
        """Get budget usage statistics."""
        return {
            BUCKET_FIRST_PARTY: {
                "limit_ms": self.first_party_ms_limit,
                "used_ms": self.first_party_ms_used,
                "remaining_ms": self.first_party_ms_limit - self.first_party_ms_used,
            },
            BUCKET_THIRD_PARTY: {
                "limit_ms": self.third_party_ms_limit,
                "used_ms": self.third_party_ms_used,
                "remaining_ms": self.third_party_ms_limit - self.third_party_ms_used,
            },
        }

    def has_budget(self, origin: FileOrigin, duration_ms: int = 0) -> bool:
        """
        Check if there's remaining budget for a file origin.

        Args:
            origin: File origin classification
            duration_ms: Estimated duration (0 for existence check)

        Returns:
            True if budget available
        """
        if origin in {FileOrigin.third_party, FileOrigin.external}:
            return self.third_party_ms_used + duration_ms <= self.third_party_ms_limit
        else:
            return self.first_party_ms_used + duration_ms <= self.first_party_ms_limit
