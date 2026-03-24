"""Cargo-fuzz engine adapter for Rust fuzzing."""

from __future__ import annotations

import subprocess

from execution.engines.engine_interface import EngineInterface, EngineResult


class CargoFuzzEngine(EngineInterface):
    """cargo-fuzz -- Rust fuzzing via libFuzzer."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        fuzz_target = str(kwargs.get("fuzz_target", "fuzz_target_1"))

        cmd = [
            "cargo", "fuzz", "run", fuzz_target,
            "--", f"-max_total_time={timeout_seconds}",
            "-print_final_stats=1",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 120,
                cwd=harness_path,
            )

            crashes: list[dict] = []
            if "SUMMARY" in result.stderr and "crash" in result.stderr.lower():
                crashes.append({
                    "type": "crash",
                    "method": "cargo_fuzz",
                    "path": fuzz_target,
                    "status_code": "crash",
                    "details": result.stderr[-500:],
                })

            return EngineResult(
                success="BINGO" not in result.stderr,
                metrics={"total_execs": 0},
                artifact_candidates=crashes,
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
                errors=["cargo-fuzz not found"],
                exit_code=1,
            )
