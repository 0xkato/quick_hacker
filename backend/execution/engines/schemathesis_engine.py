"""Schemathesis execution engine adapter.

Runs compiled Schemathesis harnesses (pytest-compatible files that use
``@schema.parametrize()``) via ``python -m pytest`` and parses the output
into an EngineResult.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any

from execution.engines.engine_interface import EngineInterface, EngineResult

logger = logging.getLogger(__name__)

# Matches pytest FAILED lines like:
#   FAILED test_harness.py::test_POST_api_users - AssertionError: ...
_PYTEST_FAILED_RE = re.compile(
    r"^FAILED\s+\S+::(\S+)",
    re.MULTILINE,
)

# Matches pytest short test summary lines like:
#   FAILED test_harness.py::test_POST_api_users[...] - assert 200 != 500
_PYTEST_SUMMARY_RE = re.compile(
    r"^FAILED\s+\S+::(test_\w+)\[?([^\]]*)\]?\s*-\s*(.*)",
    re.MULTILINE,
)

# Matches the pytest results line: "X passed, Y failed, Z errors in Ns"
_PYTEST_RESULTS_RE = re.compile(
    r"(\d+)\s+passed|(\d+)\s+failed|(\d+)\s+error",
)


class SchemathesisEngine(EngineInterface):
    """Runs compiled Schemathesis harnesses via pytest."""

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
        """Execute a compiled harness via pytest and return structured results."""
        cmd = self._build_command(harness_path, base_url, timeout_seconds, **kwargs)
        logger.info("Running schemathesis harness: %s", " ".join(cmd))

        env = os.environ.copy()
        # Ensure the harness can reach the target
        env["SCHEMATHESIS_BASE_URL"] = base_url

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 30,  # grace period
                env=env,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Schemathesis harness timed out after %ds", timeout_seconds + 30)
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
        """Build the pytest command to run the compiled harness."""
        cmd = [
            "python", "-m", "pytest",
            harness_path,
            "-v",
            "--tb=short",
            f"--timeout={timeout_seconds}",
        ]

        # Forward any extra CLI flags the caller provides
        extra_flags: list[str] = kwargs.get("extra_flags", [])  # type: ignore[assignment]
        if extra_flags:
            cmd.extend(extra_flags)

        return cmd

    def _parse_result(self, proc: subprocess.CompletedProcess[str]) -> EngineResult:
        """Translate pytest exit code + stdout into an EngineResult."""
        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # pytest exit codes: 0 = all passed, 1 = some failed, 2 = interrupted/error
        success = exit_code == 0

        failures = self._extract_failures(stdout)
        metrics = self._extract_metrics(stdout, failures, exit_code=exit_code)
        metrics["exit_code"] = exit_code

        errors: list[str] = []
        if exit_code == 2:
            errors.append("Pytest encountered collection or internal errors")
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
        """Parse failure summaries from pytest output.

        Looks for FAILED lines in the pytest short test summary and
        extracts method/path info from the test function name (which
        follows the ``test_METHOD_path`` convention used by schemathesis
        parametrize).
        """
        failures: list[dict[str, Any]] = []
        seen: set[str] = set()

        for match in _PYTEST_SUMMARY_RE.finditer(stdout):
            test_name = match.group(1)
            params = match.group(2)
            message = match.group(3).strip()

            # Deduplicate by test name
            if test_name in seen:
                continue
            seen.add(test_name)

            # Try to extract HTTP method + path from test name
            # e.g. test_POST_api_users -> POST /api/users
            method, path = self._parse_test_name(test_name)

            failures.append({
                "test_name": test_name,
                "method": method,
                "path": path,
                "params": params,
                "message": message,
            })

        # Fallback: if the summary regex didn't match, try the simpler FAILED regex
        if not failures:
            for match in _PYTEST_FAILED_RE.finditer(stdout):
                test_name = match.group(1)
                if test_name in seen:
                    continue
                seen.add(test_name)
                method, path = self._parse_test_name(test_name)
                failures.append({
                    "test_name": test_name,
                    "method": method,
                    "path": path,
                    "params": "",
                    "message": "",
                })

        return failures

    @staticmethod
    def _parse_test_name(test_name: str) -> tuple[str, str]:
        """Extract HTTP method and path from a schemathesis test name.

        Schemathesis generates test names like ``test_POST_api_users``.
        Returns (method, path) or ("UNKNOWN", test_name) if parsing fails.
        """
        methods = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE")
        # Strip leading "test_"
        name = test_name
        if name.startswith("test_"):
            name = name[5:]

        for m in methods:
            if name.startswith(m + "_"):
                path_part = name[len(m) + 1:]
                path = "/" + path_part.replace("_", "/")
                return m, path
            if name.startswith(m):
                path_part = name[len(m):]
                path = "/" + path_part.replace("_", "/")
                return m, path

        return "UNKNOWN", test_name

    def _extract_metrics(
        self, stdout: str, failures: list[dict[str, Any]],
        exit_code: int = 0,
    ) -> dict[str, Any]:
        """Build a metrics dict from parsed pytest output."""
        # Try to extract passed/failed/error counts from the results line
        passed = 0
        failed = 0
        errored = 0
        for m in _PYTEST_RESULTS_RE.finditer(stdout):
            if m.group(1):
                passed = int(m.group(1))
            if m.group(2):
                failed = int(m.group(2))
            if m.group(3):
                errored = int(m.group(3))

        total = passed + failed + errored
        unique_paths = set(f.get("path", "") for f in failures)

        return {
            "failures_count": len(failures),
            "tests_passed": passed,
            "tests_failed": failed,
            "tests_errored": errored,
            "tests_total": total,
            "operations_hit": len(unique_paths) if failures else 0,
            "validity_ratio": passed / total if total > 0 else (1.0 if exit_code == 0 else 0.0),
            "sequence_depth": 1,  # Default for non-stateful
        }
