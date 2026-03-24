"""Foundry engine adapter for Solidity fuzzing via forge."""

from __future__ import annotations

import json
import subprocess

from execution.engines.engine_interface import EngineInterface, EngineResult


class FoundryEngine(EngineInterface):
    """Foundry -- Solidity fuzzing via ``forge test``."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        runs = int(kwargs.get("fuzz_runs", 10000))  # type: ignore[arg-type]

        cmd = [
            "forge", "test",
            "--fuzz-runs", str(runs),
            "--json",
            "-vvv",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 60,
                cwd=harness_path,
            )

            failures = self._parse_results(result.stdout)

            return EngineResult(
                success=len(failures) == 0,
                metrics={"fuzz_runs": runs},
                artifact_candidates=failures,
                corpus_path=None,
                errors=[],
                exit_code=result.returncode,
            )
        except FileNotFoundError:
            return EngineResult(
                success=False,
                metrics={},
                artifact_candidates=[],
                corpus_path=None,
                errors=["forge not found"],
                exit_code=1,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _parse_results(self, stdout: str) -> list[dict]:
        failures: list[dict] = []
        try:
            data = json.loads(stdout)
            for suite_name, suite in data.items():
                if isinstance(suite, dict):
                    for test_name, test_result in suite.get("test_results", {}).items():
                        if test_result.get("status") == "Failure":
                            failures.append({
                                "type": "oracle_hit",
                                "method": "foundry_fuzz",
                                "path": f"{suite_name}::{test_name}",
                                "status_code": "fuzz_failure",
                                "details": test_result.get("reason", ""),
                            })
        except json.JSONDecodeError:
            pass
        return failures
