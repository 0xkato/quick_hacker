"""RESTler engine adapter for stateful REST API fuzzing."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from execution.engines.engine_interface import EngineInterface, EngineResult


class RESTlerEngine(EngineInterface):
    """RESTler stateful API fuzzer -- infers producer-consumer dependencies."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        grammar_path = str(kwargs.get("grammar_path", harness_path))
        output_dir = str(kwargs.get("output_dir", "/tmp/restler_output"))

        # RESTler has two phases: compile grammar, then fuzz
        restler_dll = str(Path(self._restler_path()) / "Restler.dll")

        # Phase 1: Compile (if grammar_path is a spec, not pre-compiled)
        compile_cmd = [
            "dotnet", restler_dll,
            "compile",
            "--api_spec", grammar_path,
        ]

        # Phase 2: Fuzz
        fuzz_cmd = [
            "dotnet", restler_dll,
            "fuzz",
            "--grammar_file", str(Path(output_dir) / "Compile" / "grammar.py"),
            "--dictionary_file", str(Path(output_dir) / "Compile" / "dict.json"),
            "--settings", json.dumps({
                "max_combinations": 20,
                "max_request_execution_time": 10,
                "time_budget": timeout_seconds / 3600,  # hours
            }),
            "--target_ip", self._parse_host(base_url),
            "--target_port", str(self._parse_port(base_url)),
        ]

        try:
            # Compile
            subprocess.run(compile_cmd, capture_output=True, timeout=120)

            # Fuzz
            result = subprocess.run(
                fuzz_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 60,
            )

            bugs = self._parse_bugs(output_dir)
            metrics = self._parse_metrics(output_dir)

            return EngineResult(
                success=True,
                metrics=metrics,
                artifact_candidates=bugs,
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
                errors=["RESTler not found (requires .NET)"],
                exit_code=1,
            )
        except subprocess.TimeoutExpired:
            bugs = self._parse_bugs(output_dir)
            return EngineResult(
                success=True,
                metrics=self._parse_metrics(output_dir),
                artifact_candidates=bugs,
                corpus_path=None,
                errors=[],
                exit_code=0,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _restler_path(self) -> str:
        return os.environ.get("RESTLER_PATH", "/opt/restler")

    def _parse_host(self, url: str) -> str:
        return urlparse(url).hostname or "localhost"

    def _parse_port(self, url: str) -> int:
        return urlparse(url).port or 80

    def _parse_bugs(self, output_dir: str) -> list[dict]:
        bugs: list[dict] = []
        bug_dir = Path(output_dir) / "Fuzz" / "RestlerResults" / "bugs"
        if bug_dir.exists():
            for f in bug_dir.rglob("*.txt"):
                content = f.read_text()[:500]
                bugs.append({
                    "type": "oracle_hit",
                    "path": f.name,
                    "method": "restler_stateful",
                    "status_code": self._extract_status(content),
                    "details": content,
                })
        return bugs

    def _extract_status(self, content: str) -> str:
        for line in content.splitlines():
            if "status_code" in line.lower():
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[-1].strip()
        return "unknown"

    def _parse_metrics(self, output_dir: str) -> dict:
        return {
            "requests_sent": 0,
            "bugs_found": 0,
            "sequences_executed": 0,
            "coverage_depth": 0,
        }
