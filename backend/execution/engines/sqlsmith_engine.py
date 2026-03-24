"""SQLsmith engine adapter for database SQL fuzzing."""

from __future__ import annotations

import subprocess

from execution.engines.engine_interface import EngineInterface, EngineResult


class SQLsmithEngine(EngineInterface):
    """SQLsmith -- random SQL query generator for finding DB bugs."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        db_url = str(kwargs.get("db_url", base_url))
        max_queries = int(kwargs.get("max_queries", 10000))  # type: ignore[arg-type]

        cmd = [
            "sqlsmith",
            f"--target={db_url}",
            f"--max-queries={max_queries}",
            "--verbose",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 30,
            )

            crashes: list[dict] = []
            if "error" in result.stderr.lower() or "crash" in result.stderr.lower():
                crashes.append({
                    "type": "crash",
                    "method": "sqlsmith",
                    "path": "database",
                    "status_code": "sql_error",
                    "details": result.stderr[-500:],
                })

            return EngineResult(
                success=result.returncode == 0,
                metrics={"queries_executed": max_queries},
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
                errors=["sqlsmith not found"],
                exit_code=1,
            )
