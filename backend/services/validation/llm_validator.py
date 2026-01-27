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

    def _get_tool_definitions(self) -> list[dict]:
        """
        Get tool definitions in Anthropic API format.

        Returns:
            List of tool definition dictionaries with name, description, and input_schema
        """
        return [
            {
                "name": "read_file",
                "description": "Read source file contents",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to read"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "grep_code",
                "description": "Search codebase for patterns",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex pattern to search for"
                        },
                        "glob": {
                            "type": "string",
                            "description": "Optional glob pattern to filter files"
                        }
                    },
                    "required": ["pattern"]
                }
            },
            {
                "name": "glob_files",
                "description": "Find files by name pattern",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Glob pattern to match files"
                        }
                    },
                    "required": ["pattern"]
                }
            }
        ]

    def _build_validation_prompt(
        self,
        finding: Finding,
        evidence: Evidence,
        classification: ClassificationResult,
        threat_model_profile: Optional[dict],
        criticism_level: str,
    ) -> str:
        """
        Build the validation prompt for the Anthropic API.

        Args:
            finding: The finding to validate
            evidence: Evidence bundle for the finding
            classification: Classification result with proof checklist
            threat_model_profile: Threat model profile for context
            criticism_level: Level of criticism to apply (low, medium, high)

        Returns:
            Formatted prompt string
        """
        # Build checklist text
        checklist = classification.proof_checklist
        checklist_text = f"""- Source Controlled Input: {checklist.source_controlled_input.status.value} - {checklist.source_controlled_input.reason}
- Sink Present: {checklist.sink_present.status.value} - {checklist.sink_present.reason}
- Dataflow Evidenced: {checklist.dataflow_evidenced.status.value} - {checklist.dataflow_evidenced.reason}
- Reachable: {checklist.reachable.status.value} - {checklist.reachable.reason}
- Boundary Crossed: {checklist.boundary_crossed.status.value} - {checklist.boundary_crossed.reason}
- Not Only Misconfig: {checklist.not_only_misconfig.status.value} - {checklist.not_only_misconfig.reason}"""

        return f"""You are a security validation expert performing secondary triage on a potential vulnerability.

## Your Mission
Determine if this is a TRUE EXPLOITABLE SECURITY ISSUE or should be filtered out.

## Criticism Level: {criticism_level.upper()}
HIGH: Assume NOT exploitable unless you can prove both reachability AND attacker control
MEDIUM: Accept strong evidence for one dimension, require proof for the other
LOW: Trust the initial classification unless clearly wrong

## Finding Summary
- Title: {finding.title}
- Type: {finding.vulnerability_type}
- File: {finding.file_path}:{finding.line_start}
- Disposition: {classification.disposition.value}
- Classification Confidence: {classification.classification_confidence}%

## Initial Classification Checklist
{checklist_text}

## Your Investigation Tasks

**Task 1: Validate Attacker Control**
Question: Can an attacker ACTUALLY control the input to the dangerous sink?
- Use Grep to find all call sites of the vulnerable function
- Use Read to examine the data sources
- Trace back to untrusted boundaries (HTTP, file upload, repo checkout, etc.)
- HIGH CRITICISM: Reject if no clear path from untrusted source to sink

**Task 2: Validate Reachability**
Question: Is this code path ACTUALLY reachable in production?
- Use Grep to find route registrations, entry points, or invocations
- Use Read to check if code is conditionally disabled (feature flags, env checks)
- Verify the function is actually called, not just defined
- HIGH CRITICISM: Reject if no clear invocation path

**Task 3: Differentiate Security vs Bug vs Expected Behavior**
- Security issue: Exploitable by attacker with realistic capabilities
- Bug: Functional problem without security impact
- Hardening: Dangerous pattern but not proven exploitable
- By design: Intentional behavior (e.g., eval() in template engine)
- Expected behavior: Working as designed without risk

## Tools Available
- read_file(file_path): Read source files
- grep_code(pattern, glob): Search codebase for patterns
- glob_files(pattern): Find files by name pattern

## Response Format
Respond with exactly:
```
DECISION: VALID | INVALID
CATEGORY: security_issue | bug | hardening | by_design | expected_behavior
REASONING:
- [Bullet 1: key finding from investigation]
- [Bullet 2: evidence for/against exploitability]
- [Bullet 3: final determination]
```

Be highly skeptical. Default to INVALID unless you can prove it's exploitable."""

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
