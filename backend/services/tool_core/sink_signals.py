"""Sink signal management for ToolCore."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from models.sink_signals import RiskTier, SinkSignal, SinkSignalKind, SinkSignalStatus
from services.sink_signal_service import compute_signal_fingerprint, sink_signal_service


class SinkSignalsMixin:
    """Mixin for sink signal management operations.

    This mixin provides methods for listing, creating, and updating sink signals.
    It requires the following attributes to be set:
    - project_id: Project identifier
    - repo_path: Path to repository root
    - workspace_policy: WorkspacePolicy instance
    - DEFAULT_EXCLUDED_DIRS: Set of excluded directory names
    """

    async def list_sink_signals(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List sink signals for the project.

        Args:
            status: Optional status filter
            limit: Maximum signals to return

        Returns:
            Dict with signals list and count
        """
        limit = max(1, min(limit, 200))

        parsed_status = None
        if status is not None:
            try:
                parsed_status = SinkSignalStatus(status)
            except ValueError:
                raise ValueError(f"Invalid status: {status}")

        signals = await sink_signal_service.list_signals(
            project_id=self.project_id,
            status=parsed_status,
            limit=limit,
        )

        return {
            "count": len(signals),
            "signals": [s.model_dump(mode="json") for s in signals],
        }

    async def upsert_sink_signal(
        self,
        kind: str,
        label: str,
        file_path: str,
        fingerprint: str | None = None,
        line_number: int | None = None,
        status: str | None = None,
        llm_risk_tier: str | None = None,
        llm_score: int | None = None,
        llm_reasoning: str | None = None,
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Create or update a sink signal.

        Args:
            kind: Signal kind (entry_point, sink, other)
            label: Human-readable label
            file_path: File path relative to repo
            fingerprint: Optional explicit fingerprint
            line_number: Optional line number
            status: Optional status
            llm_risk_tier: Optional risk tier (S-E)
            llm_score: Optional 0-100 score
            llm_reasoning: Optional reasoning text
            metadata: Optional extra metadata

        Returns:
            Dict with created/updated signal
        """
        # Normalize file_path to a repo-relative, non-escaping path.
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

        candidate = self.repo_path / file_path
        normalized = Path(os.path.normpath(str(candidate)))
        try:
            normalized.relative_to(self.repo_path)
        except ValueError as exc:
            raise ValueError(f"Path escapes workspace: {raw_file_path}") from exc

        for part in Path(file_path).parts:
            if part in self.DEFAULT_EXCLUDED_DIRS:
                raise ValueError(f"Path in excluded directory: {file_path}")

        if candidate.exists():
            ok, reason = self.workspace_policy.validate_path(candidate)
            if not ok:
                if reason and "excluded" in reason.lower():
                    raise ValueError(f"Path in excluded directory: {file_path}")
                raise ValueError(f"Path rejected: {reason}")

        try:
            kind_enum = SinkSignalKind(kind)
        except ValueError:
            raise ValueError(f"Invalid kind: {kind}")

        status_enum = SinkSignalStatus.UNREVIEWED
        if status is not None:
            try:
                status_enum = SinkSignalStatus(status)
            except ValueError:
                raise ValueError(f"Invalid status: {status}")

        tier_enum = None
        if llm_risk_tier is not None:
            try:
                tier_enum = RiskTier(llm_risk_tier.strip().upper())
            except ValueError:
                raise ValueError(f"Invalid risk tier: {llm_risk_tier}")

        if llm_score is not None:
            if llm_score < 0 or llm_score > 100:
                raise ValueError("llm_score must be 0-100")

        resolved_metadata = metadata or {}
        # Deterministic input_channel inference (v1): repo-embedded secret/config artifacts.
        if isinstance(resolved_metadata, dict):
            ctx = resolved_metadata.get("context")
            if isinstance(ctx, dict):
                inferred_channel = self._infer_repo_artifact_input_channel(file_path)
                provided_channel = ctx.get("input_channel")
                if inferred_channel is not None:
                    if isinstance(provided_channel, str) and provided_channel and provided_channel != inferred_channel:
                        ctx["provided_input_channel"] = provided_channel
                        ctx["inferred_input_channel"] = inferred_channel
                        ctx["input_channel"] = inferred_channel
                        ctx["input_channel_deterministic"] = True
                        ctx["validation_warning"] = (
                            f"input_channel corrected from {provided_channel} -> {inferred_channel} "
                            f"(repo artifact: {file_path})"
                        )
                    else:
                        ctx["input_channel"] = inferred_channel
                        ctx["input_channel_deterministic"] = True

        signal_id = fingerprint or compute_signal_fingerprint(
            kind=kind_enum.value,
            file_path=file_path,
            line_number=line_number,
            label=label,
        )

        signal = SinkSignal(
            fingerprint=signal_id,
            kind=kind_enum,
            label=label,
            file_path=file_path,
            line_number=line_number,
            status=status_enum,
            source="llm",
            llm_risk_tier=tier_enum,
            llm_score=llm_score,
            llm_reasoning=llm_reasoning.strip() if llm_reasoning else None,
            metadata=resolved_metadata,
        )

        updated = await sink_signal_service.upsert_signals(
            project_id=self.project_id,
            signals=[signal],
        )

        result_signal = updated[0] if updated else signal
        return {"signal": result_signal.model_dump(mode="json")}

    def _infer_repo_artifact_input_channel(self, repo_relative_path: str) -> str | None:
        """Deterministically infer repo_checkout for certain repo-embedded artifacts.

        v1 scope: `.env*`, `docker-compose*`, `*.pem`, `*.key`.
        """
        name = Path(repo_relative_path).name.lower()
        if name == ".env" or name.startswith(".env."):
            return "repo_checkout"
        if name.startswith("docker-compose"):
            return "repo_checkout"
        if Path(repo_relative_path).suffix.lower() in (".pem", ".key"):
            return "repo_checkout"
        return None
