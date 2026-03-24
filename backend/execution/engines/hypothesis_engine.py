"""Hypothesis engine adapter for property-based Python testing."""

from __future__ import annotations

import subprocess

from execution.engines.engine_interface import EngineInterface, EngineResult


class HypothesisEngine(EngineInterface):
    """Hypothesis -- property-based testing for Python."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        max_examples = kwargs.get("max_examples", 1000)

        cmd = [
            "python", "-m", "pytest", harness_path,
            "-v", "--tb=short",
            f"--timeout={timeout_seconds}",
            "--hypothesis-seed=0",
            f"--hypothesis-settings=max_examples={max_examples}",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 30,
            )

            failures = self._parse_failures(result.stdout)
            metrics = self._parse_metrics(result.stdout)

            return EngineResult(
                success=result.returncode == 0,
                metrics=metrics,
                artifact_candidates=failures,
                corpus_path=None,
                errors=[result.stderr] if result.returncode > 1 else [],
                exit_code=result.returncode,
            )
        except FileNotFoundError:
            return EngineResult(
                success=False,
                metrics={},
                artifact_candidates=[],
                corpus_path=None,
                errors=["hypothesis not found"],
                exit_code=1,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _parse_failures(self, stdout: str) -> list[dict]:
        failures: list[dict] = []
        for line in stdout.splitlines():
            if "FAILED" in line:
                failures.append({
                    "type": "oracle_hit",
                    "method": "hypothesis_property",
                    "path": line.split("::")[0] if "::" in line else "unknown",
                    "status_code": "property_violation",
                    "details": line,
                })
        return failures

    def _parse_metrics(self, stdout: str) -> dict:
        metrics: dict = {"tests_run": 0, "tests_failed": 0, "examples_generated": 0}
        for line in stdout.splitlines():
            if "passed" in line and "failed" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "passed":
                        metrics["tests_run"] += int(parts[i - 1])
                    if p == "failed":
                        metrics["tests_failed"] += int(parts[i - 1])
        return metrics
