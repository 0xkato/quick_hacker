"""Abstract interface for execution engines (Schemathesis, Nuclei, etc.)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class EngineResult:
    """Standardised output from any execution engine run."""

    success: bool
    metrics: dict  # operations_hit, status_classes, requests_per_sec, etc.
    artifact_candidates: list[dict]  # raw failures found
    corpus_path: str | None
    errors: list[str]
    exit_code: int = 0


class EngineInterface(ABC):
    """Contract that every execution engine must implement."""

    @abstractmethod
    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        """Execute the engine against a target and return structured results.

        Parameters
        ----------
        harness_path:
            Path to the OpenAPI spec or harness file to feed the engine.
        base_url:
            The base URL of the target application under test.
        timeout_seconds:
            Maximum wall-clock time the engine is allowed to run.
        **kwargs:
            Engine-specific options.

        Returns
        -------
        EngineResult with metrics, artifact candidates, and error details.
        """
        ...
