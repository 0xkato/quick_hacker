"""Jazzer engine adapter for JVM coverage-guided fuzzing."""

from __future__ import annotations

import subprocess

from execution.engines.engine_interface import EngineInterface, EngineResult


class JazzerEngine(EngineInterface):
    """Jazzer -- coverage-guided JVM fuzzing (Google)."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        target_class = str(kwargs.get("target_class", ""))
        cp = str(kwargs.get("classpath", "."))
        corpus_dir = str(kwargs.get("corpus_dir", "/tmp/jazzer_corpus"))

        cmd = [
            "jazzer",
            f"--target_class={target_class or harness_path}",
            f"--cp={cp}",
            corpus_dir,
            f"-max_total_time={timeout_seconds}",
            "-print_final_stats=1",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 60,
            )

            crashes: list[dict] = []
            if result.returncode != 0 and "SECURITY ISSUE" in result.stderr:
                crashes.append({
                    "type": "crash",
                    "method": "jazzer_coverage",
                    "path": target_class,
                    "status_code": "security_issue",
                    "details": result.stderr[-500:],
                })

            return EngineResult(
                success=result.returncode == 0,
                metrics={"total_execs": 0},
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
                errors=["jazzer not found"],
                exit_code=1,
            )
