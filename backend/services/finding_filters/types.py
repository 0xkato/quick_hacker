"""Base types for finding filters."""
from abc import ABC, abstractmethod
from typing import Protocol
from models.schemas import Finding


class FindingFilter(Protocol):
    """Protocol for finding filters."""

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """
        Apply filter to findings list.

        Args:
            findings: List of findings to filter

        Returns:
            Filtered list of findings
        """
        ...
