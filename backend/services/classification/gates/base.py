"""Base gate interface for vulnerability classification."""
from abc import ABC, abstractmethod
from typing import Optional

from models.schemas import Finding, Evidence, Disposition


class GateResult:
    """Result from gate evaluation."""
    def __init__(
        self,
        passed: bool,
        reasoning: list[str],
        proof_items: dict,
        disposition: Optional[Disposition] = None
    ):
        self.passed = passed
        self.reasoning = reasoning
        self.proof_items = proof_items
        self.disposition = disposition


class BaseGate(ABC):
    """Base classification gate for vulnerability types."""

    @abstractmethod
    def evaluate(self, finding: Finding, evidence: Evidence) -> GateResult:
        """
        Evaluate finding against gate criteria.

        Args:
            finding: Finding to evaluate
            evidence: Evidence collected for finding

        Returns:
            GateResult with evaluation outcome
        """
        pass

    @abstractmethod
    def get_category_name(self) -> str:
        """Return the vulnerability category this gate handles."""
        pass
