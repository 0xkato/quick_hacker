"""LLM-based finding validator using Anthropic API with tool use."""
import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional, Any

from models.schemas import Finding, Evidence, ValidationResult
from services.classification.classifier import ClassificationResult

logger = logging.getLogger(__name__)


class LLMFindingValidator:
    """
    LLM-based validator that uses Anthropic API to deeply validate findings.

    Uses tool use (read_file, grep_code, glob_files) to investigate codebase
    and determine if findings are truly valid security issues.
    """

    def __init__(
        self,
        anthropic_api_key: str,
        repo_root: str,
        model: str = "claude-sonnet-3-5-20241022",
    ):
        """
        Initialize LLM validator.

        Args:
            anthropic_api_key: Anthropic API key
            repo_root: Path to repository root
            model: Model to use (default: claude-sonnet-3-5-20241022)

        Raises:
            RuntimeError: If anthropic package not installed
        """
        try:
            from anthropic import Anthropic
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "LLMFindingValidator requires the 'anthropic' dependency. "
                "Install it or disable LLM validation."
            ) from exc

        self.client = Anthropic(api_key=anthropic_api_key)
        self.repo_root = Path(repo_root)
        self.model = model

        # Initialize tool stubs
        self.tools = {
            "read_file": self._tool_read_file,
            "grep_code": self._tool_grep_code,
            "glob_files": self._tool_glob_files,
        }

    def _tool_read_file(self, file_path: str) -> str:
        """Stub for read_file tool."""
        return f"File content: {file_path}"

    def _tool_grep_code(self, pattern: str, glob: Optional[str] = None) -> str:
        """Stub for grep_code tool."""
        return f"Grep results for: {pattern}"

    def _tool_glob_files(self, pattern: str) -> str:
        """Stub for glob_files tool."""
        return f"Files matching: {pattern}"

    async def validate(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Any,
        criticism_level: str,
        timeout_seconds: int = 120,
    ) -> ValidationResult:
        """
        Validate a finding using LLM with tool use.

        Args:
            finding: The finding to validate
            evidence: Evidence bundle for the finding
            classification: Classification result with proof checklist
            threat_model_profile: Threat model profile for context
            criticism_level: Level of criticism to apply (low, medium, high)
            timeout_seconds: Timeout in seconds (default: 120)

        Returns:
            ValidationResult with validation decision
        """
        try:
            # Wrap _run_validation in timeout
            result = await asyncio.wait_for(
                self._run_validation(
                    finding=finding,
                    evidence=evidence,
                    classification=classification,
                    threat_model_profile=threat_model_profile,
                    criticism_level=criticism_level,
                ),
                timeout=timeout_seconds,
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(
                f"LLM validation timed out after {timeout_seconds}s for finding {finding.id}"
            )
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Validation timeout after {timeout_seconds}s",
                    "Insufficient time to prove exploitability - filtered conservatively",
                ],
                categories=["timeout"],
                confidence=0,
                timestamp=datetime.now(UTC),
            )
        except Exception as e:
            logger.error(f"Error during LLM validation for finding {finding.id}: {e}")
            return ValidationResult(
                is_valid=False,
                reasoning=[
                    f"Validation error: {str(e)[:200]}",
                    "Could not complete investigation - filtered conservatively",
                ],
                categories=["error"],
                confidence=0,
                timestamp=datetime.now(UTC),
            )

    async def _run_validation(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Any,
        criticism_level: str,
    ) -> ValidationResult:
        """
        Run the actual validation logic (stub for now).

        This will be implemented in later tasks with the full agentic loop.

        Args:
            finding: The finding to validate
            evidence: Evidence bundle
            classification: Classification result
            threat_model_profile: Threat model profile
            criticism_level: Criticism level

        Returns:
            ValidationResult
        """
        # Stub: simulate work that takes time
        await asyncio.sleep(10)

        return ValidationResult(
            is_valid=True,
            reasoning=["Stub implementation"],
            categories=["security_issue"],
            confidence=95,
            timestamp=datetime.now(UTC),
        )
