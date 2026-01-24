"""Finding management operations for ToolCore."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from services.redaction_service import redaction_service


class FindingManagementMixin:
    """Mixin for finding management operations.

    This mixin provides methods for reporting and triaging findings.
    It requires the following attributes to be set:
    - VALID_SEVERITIES: Set of valid severity levels
    - repo_path: Path to repository root
    - workspace_policy: WorkspacePolicy instance
    - DEFAULT_EXCLUDED_DIRS: Set of excluded directory names
    """

    async def report_finding(
        self,
        severity: str,
        title: str,
        vulnerability_type: str,
        file_path: str,
        line_start: int,
        vulnerable_code: str,
        description: str,
        confidence: float,
        cwe_id: str | None = None,
        line_end: int | None = None,
        source_trace: list[str] | None = None,
        attack_scenario: str | None = None,
        proof_of_concept: str | None = None,
        recommended_fix: str | None = None,
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Report a security finding.

        This returns the finding data; the actual persistence is handled
        by the orchestrator after validation.

        Args:
            severity: Severity level (critical/high/medium/low/info)
            title: Finding title
            vulnerability_type: Type of vulnerability
            file_path: Path to the vulnerable file
            line_start: Starting line number (must be positive integer)
            vulnerable_code: The vulnerable code snippet
            description: Description of the vulnerability
            confidence: Confidence score (0.0 to 1.0)
            cwe_id: Optional CWE identifier
            line_end: Optional ending line (must be >= line_start if provided)
            source_trace: Optional source trace list
            attack_scenario: Optional attack scenario description
            proof_of_concept: Optional PoC code
            recommended_fix: Optional fix recommendation

        Returns:
            Dict with reported finding data

        Raises:
            ValueError: If any input validation fails
        """
        # Require structured context metadata for explainability + threat model gating.
        if not isinstance(metadata, dict):
            raise ValueError("metadata.context is required")
        ctx = metadata.get("context")
        if not isinstance(ctx, dict):
            raise ValueError("metadata.context is required")
        if not isinstance(ctx.get("execution_context"), str) or not ctx.get("execution_context"):
            raise ValueError("metadata.context.execution_context is required")
        if not isinstance(ctx.get("input_channel"), str) or not ctx.get("input_channel"):
            raise ValueError("metadata.context.input_channel is required")
        if not isinstance(ctx.get("activation_path"), str) or not ctx.get("activation_path"):
            raise ValueError("metadata.context.activation_path is required")
        activation_path = str(ctx.get("activation_path"))
        if "\n" in activation_path or "\r" in activation_path:
            raise ValueError("metadata.context.activation_path must be single-line")
        if len(activation_path) > 300:
            raise ValueError("metadata.context.activation_path too long")
        if not any(activation_path.startswith(prefix) for prefix in ("route:", "cli:", "ci:", "import:", "unknown")):
            raise ValueError("metadata.context.activation_path must start with route:/cli:/ci:/import:/unknown")
        # Validate severity
        severity_lower = severity.lower()
        if severity_lower not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of: {sorted(self.VALID_SEVERITIES)}"
            )

        # Validate confidence (0.0-1.0 float)
        if not isinstance(confidence, (int, float)):
            raise ValueError("confidence must be a float")
        if confidence < 0.0 or confidence > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

        # Validate line_start (positive integer)
        if not isinstance(line_start, int) or line_start < 1:
            raise ValueError("line_start must be a positive integer")

        # Validate line_end >= line_start if provided
        if line_end is not None:
            if not isinstance(line_end, int) or line_end < 1:
                raise ValueError("line_end must be a positive integer")
            if line_end < line_start:
                raise ValueError("line_end must be >= line_start")

        # Normalize file_path to a repo-relative, non-escaping path. Do not require the file to exist:
        # findings can reference paths that were moved/removed, but must never leak host paths.
        raw_file_path = file_path
        file_path_candidate = Path(file_path)
        if file_path_candidate.is_absolute():
            try:
                file_path = file_path_candidate.resolve().relative_to(self.repo_path).as_posix()
            except ValueError as exc:
                raise ValueError(f"Path escapes workspace: {raw_file_path}") from exc
        else:
            file_path = Path(os.path.normpath(file_path)).as_posix()

        if not file_path or file_path == ".":
            raise ValueError("file_path must be a non-empty repo-relative path")

        # Fast lexical traversal check (doesn't follow symlinks, doesn't require existence).
        candidate = self.repo_path / file_path
        normalized = Path(os.path.normpath(str(candidate)))
        try:
            normalized.relative_to(self.repo_path)
        except ValueError as exc:
            raise ValueError(f"Path escapes workspace: {raw_file_path}") from exc

        # Reject excluded dirs even if file doesn't exist (prevents UI/path probing).
        for part in Path(file_path).parts:
            if part in self.DEFAULT_EXCLUDED_DIRS:
                raise ValueError(f"Path in excluded directory: {file_path}")

        # If the file exists, enforce full WorkspacePolicy (symlink rejection, size limits).
        if candidate.exists():
            ok, reason = self.workspace_policy.validate_path(candidate)
            if not ok:
                if reason and "excluded" in reason.lower():
                    raise ValueError(f"Path in excluded directory: {file_path}")
                raise ValueError(f"Path rejected: {reason}")

        # Deterministic input_channel inference (v1): repo-embedded secret/config artifacts.
        inferred_channel = self._infer_repo_artifact_input_channel(file_path)
        if inferred_channel is not None:
            provided_channel = ctx.get("input_channel")
            if provided_channel != inferred_channel:
                raise ValueError(
                    f"INPUT_CHANNEL_MISMATCH: provided={provided_channel} inferred={inferred_channel} "
                    f"(repo artifact: {file_path})"
                )
            ctx["input_channel"] = inferred_channel
            ctx["input_channel_deterministic"] = True

        # Redact secrets from user-provided fields (defense-in-depth).
        vulnerable_code = redaction_service.redact(vulnerable_code)
        description = redaction_service.redact(description)
        if attack_scenario is not None:
            attack_scenario = redaction_service.redact(attack_scenario)
        if proof_of_concept is not None:
            proof_of_concept = redaction_service.redact(proof_of_concept)
        if recommended_fix is not None:
            recommended_fix = redaction_service.redact(recommended_fix)
        if source_trace is not None:
            source_trace = [redaction_service.redact(str(item)) for item in source_trace]

        finding = {
            "severity": severity_lower,
            "title": title,
            "vulnerability_type": vulnerability_type,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "vulnerable_code": vulnerable_code,
            "description": description,
            "confidence": confidence,
            "cwe_id": cwe_id,
            "source_trace": source_trace,
            "attack_scenario": attack_scenario,
            "proof_of_concept": proof_of_concept,
            "recommended_fix": recommended_fix,
            "metadata": metadata,
        }

        return {"reported": True, "finding": finding}

    async def triage_finding(
        self,
        title: str,
        file_path: str,
        vulnerability_type: str,
        severity: str,
        description: str,
    ) -> dict[str, Any]:
        """Triage a finding using LLM-based production relevance filter.

        Returns:
            Dict with decision ("keep" or "filter") and reason
        """
        # NOTE: This tool is used by the Codex CLI MCP stdio server.
        # It must not raise due to missing optional dependencies (e.g., anthropic),
        # and it must never write to stdout via import-time side effects.
        from protocol_config.protocol_config import ProtocolConfig
        from models.schemas import Finding, Severity

        # Check if filter is available
        api_key = ProtocolConfig.ANTHROPIC_API_KEY
        if not api_key:
            return {
                "decision": "keep",
                "reason": "No API key configured - filter unavailable",
                "is_production_code": True,
            }

        # Create minimal Finding object for filter
        try:
            severity_enum = Severity(severity.lower())
        except ValueError:
            severity_enum = Severity.MEDIUM

        finding = Finding(
            title=title,
            file_path=file_path,
            vulnerability_type=vulnerability_type,
            severity=severity_enum,
            description=description,
        )

        # Run production relevance filter
        try:
            from services.finding_filters import ProductionRelevanceFilter

            production_filter = ProductionRelevanceFilter(api_key)
            is_relevant, reason = production_filter.is_production_relevant(finding)

            return {
                "decision": "keep" if is_relevant else "filter",
                "reason": reason,
                "is_production_code": is_relevant
            }
        except (ImportError, ModuleNotFoundError) as e:
            return {
                "decision": "keep",
                "reason": f"Filter unavailable: {str(e)}",
                "is_production_code": True,
                "error": True,
            }
        except Exception as e:
            # On error, default to keeping
            return {
                "decision": "keep",
                "reason": f"Filter error: {str(e)}",
                "is_production_code": True,
                "error": True,
            }
