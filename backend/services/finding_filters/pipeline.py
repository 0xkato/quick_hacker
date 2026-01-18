"""Finding filter pipeline for composable filtering."""
from typing import Sequence
from models.schemas import Finding
from .types import FindingFilter


class FilterPipeline:
    """Composable pipeline of finding filters."""

    def __init__(self, filters: Sequence[FindingFilter]):
        """
        Initialize pipeline with ordered filters.

        Args:
            filters: Ordered sequence of filters to apply
        """
        self.filters = list(filters)

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """
        Apply all filters in sequence.

        Args:
            findings: Input findings

        Returns:
            Filtered findings after all filters applied
        """
        result = findings
        for filter_instance in self.filters:
            result = filter_instance.apply(result)
        return result

    def add_filter(self, filter_instance: FindingFilter) -> None:
        """Add a filter to the end of the pipeline."""
        self.filters.append(filter_instance)
