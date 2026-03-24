"""Boofuzz engine adapter for network protocol fuzzing."""

from __future__ import annotations

import subprocess
from urllib.parse import urlparse

from execution.engines.engine_interface import EngineInterface, EngineResult


class BoofuzzEngine(EngineInterface):
    """Boofuzz -- network protocol fuzzing."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        cmd = [
            "python", harness_path,
            "--timeout", str(timeout_seconds),
            "--target-host", self._parse_host(base_url),
            "--target-port", str(self._parse_port(base_url)),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 30,
            )

            crashes: list[dict] = []
            if "failure" in result.stdout.lower() or result.returncode != 0:
                crashes.append({
                    "type": "crash",
                    "method": "boofuzz_protocol",
                    "path": "network_target",
                    "status_code": "protocol_error",
                    "details": result.stdout[-500:],
                })

            return EngineResult(
                success=result.returncode == 0,
                metrics={"mutations_tested": 0},
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
                errors=["boofuzz not found"],
                exit_code=1,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _parse_host(self, url: str) -> str:
        return urlparse(url).hostname or "localhost"

    def _parse_port(self, url: str) -> int:
        return urlparse(url).port or 80
