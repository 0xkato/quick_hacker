"""Schemathesis execution engine adapter.

Wraps the ``schemathesis run`` CLI to execute property-based API testing
against an OpenAPI specification and parses results into an EngineResult.
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any

from execution.engines.engine_interface import EngineInterface, EngineResult

logger = logging.getLogger(__name__)

# Matches lines like:  POST /api/users 500
_FAILURE_RE = re.compile(
    r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(\S+)\s+(\d{3})",
    re.MULTILINE,
)


class SchemathesisEngine(EngineInterface):
    """Runs ``schemathesis run`` via subprocess and parses results."""

    def __init__(self, binary: str = "schemathesis") -> None:
        self._binary = binary

    # ------------------------------------------------------------------
    # EngineInterface
    # ------------------------------------------------------------------

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        """Execute schemathesis and return structured results."""
        cmd = self._build_command(harness_path, base_url, timeout_seconds, **kwargs)
        logger.info("Running schemathesis: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 30,  # grace period on top of engine timeout
            )
        except subprocess.TimeoutExpired:
            logger.warning("Schemathesis timed out after %ds", timeout_seconds + 30)
            return EngineResult(
                success=False,
                metrics={"timed_out": True},
                artifact_candidates=[],
                corpus_path=None,
                errors=[f"Process timed out after {timeout_seconds + 30}s"],
                exit_code=-1,
            )

        return self._parse_result(proc)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_command(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> list[str]:
        """Build the schemathesis CLI command."""
        deadline_ms = timeout_seconds * 1000
        cmd = [
            self._binary,
            "run",
            harness_path,
            "--base-url",
            base_url,
            "--hypothesis-deadline",
            str(deadline_ms),
        ]

        # Forward any extra CLI flags the caller provides
        extra_flags: list[str] = kwargs.get("extra_flags", [])  # type: ignore[assignment]
        if extra_flags:
            cmd.extend(extra_flags)

        return cmd

    def _parse_result(self, proc: subprocess.CompletedProcess[str]) -> EngineResult:
        """Translate schemathesis exit code + stdout into an EngineResult."""
        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # Exit codes: 0 = all passed, 1 = failures found, 2 = errors
        success = exit_code == 0

        failures = self._extract_failures(stdout)
        metrics = self._extract_metrics(stdout, failures)
        metrics["exit_code"] = exit_code

        errors: list[str] = []
        if exit_code == 2:
            errors.append("Schemathesis encountered internal errors")
            if stderr:
                errors.append(stderr.strip())

        return EngineResult(
            success=success,
            metrics=metrics,
            artifact_candidates=failures,
            corpus_path=None,
            errors=errors,
            exit_code=exit_code,
        )

    def _extract_failures(self, stdout: str) -> list[dict[str, Any]]:
        """Parse failure summaries from schemathesis output.

        Looks for lines matching ``METHOD /path STATUS_CODE`` patterns.
        """
        failures: list[dict[str, Any]] = []
        for match in _FAILURE_RE.finditer(stdout):
            failures.append(
                {
                    "method": match.group(1),
                    "path": match.group(2),
                    "status_code": int(match.group(3)),
                }
            )
        return failures

    def _extract_metrics(
        self, stdout: str, failures: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Build a metrics dict from parsed output."""
        status_classes: dict[str, int] = {}
        for f in failures:
            code = f["status_code"]
            cls = f"{code // 100}xx"
            status_classes[cls] = status_classes.get(cls, 0) + 1

        return {
            "failures_count": len(failures),
            "status_classes": status_classes,
        }
