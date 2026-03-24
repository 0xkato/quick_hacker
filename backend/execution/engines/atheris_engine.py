"""Atheris engine adapter for Python coverage-guided fuzzing."""

from __future__ import annotations

import os
import subprocess
import tempfile

from execution.engines.engine_interface import EngineInterface, EngineResult


class AtherisEngine(EngineInterface):
    """Atheris -- coverage-guided Python fuzzing (Google)."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        corpus_dir = str(kwargs.get("corpus_dir", ""))
        if not corpus_dir:
            corpus_dir = tempfile.mkdtemp(prefix="atheris_corpus_")

        cmd = [
            "python", harness_path,
            corpus_dir,
            f"-max_total_time={timeout_seconds}",
            "-print_final_stats=1",
        ]

        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = "."
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 30,
                env=env,
            )

            crashes = self._collect_crashes(result.stderr)
            metrics = self._parse_stats(result.stderr)

            return EngineResult(
                success="BINGO" not in result.stderr,
                metrics=metrics,
                artifact_candidates=crashes,
                corpus_path=corpus_dir,
                errors=[],
                exit_code=result.returncode,
            )
        except FileNotFoundError:
            return EngineResult(
                success=False,
                metrics={},
                artifact_candidates=[],
                corpus_path=None,
                errors=["atheris not found"],
                exit_code=1,
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                success=True,
                metrics={},
                artifact_candidates=[],
                corpus_path=corpus_dir,
                errors=[],
                exit_code=0,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _collect_crashes(self, stderr: str) -> list[dict]:
        crashes: list[dict] = []
        if "BINGO" in stderr or "ERROR" in stderr:
            crashes.append({
                "type": "crash",
                "method": "atheris_coverage",
                "path": "python_target",
                "status_code": "crash",
                "details": stderr[-500:],
            })
        return crashes

    def _parse_stats(self, stderr: str) -> dict:
        metrics: dict = {"total_execs": 0, "edges_found": 0, "corpus_size": 0}
        for line in stderr.splitlines():
            if "stat::number_of_executed_units:" in line:
                metrics["total_execs"] = int(line.split(":")[-1].strip())
            elif "stat::new_units_added:" in line:
                metrics["corpus_size"] = int(line.split(":")[-1].strip())
        return metrics
