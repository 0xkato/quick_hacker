"""Go native fuzz engine adapter."""

from __future__ import annotations

import subprocess

from execution.engines.engine_interface import EngineInterface, EngineResult


class GoFuzzEngine(EngineInterface):
    """Go native fuzzing via ``go test -fuzz``."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        fuzz_func = str(kwargs.get("fuzz_func", "Fuzz"))
        pkg_path = str(kwargs.get("pkg_path", "."))

        cmd = [
            "go", "test",
            f"-fuzz={fuzz_func}",
            f"-fuzztime={timeout_seconds}s",
            "-v",
            pkg_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 60,
                cwd=harness_path,
            )

            crashes: list[dict] = []
            if "FAIL" in result.stdout:
                crashes.append({
                    "type": "crash",
                    "method": "go_fuzz",
                    "path": fuzz_func,
                    "status_code": "fuzz_failure",
                    "details": result.stdout[-500:],
                })

            return EngineResult(
                success=result.returncode == 0,
                metrics=self._parse_metrics(result.stdout),
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
                errors=["go not found"],
                exit_code=1,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _parse_metrics(self, stdout: str) -> dict:
        metrics: dict = {"total_execs": 0, "elapsed_seconds": 0}
        for line in stdout.splitlines():
            if "elapsed" in line and "execs" in line:
                parts = line.split(",")
                for p in parts:
                    p = p.strip()
                    if "execs" in p:
                        try:
                            metrics["total_execs"] = int(p.split()[0])
                        except (ValueError, IndexError):
                            pass
        return metrics
