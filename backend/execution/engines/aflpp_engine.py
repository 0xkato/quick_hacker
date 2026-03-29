"""AFL++ engine adapter for coverage-guided binary fuzzing."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from execution.engines.engine_interface import EngineInterface, EngineResult


class AFLPPEngine(EngineInterface):
    """AFL++ coverage-guided mutation fuzzer for native binaries.

    Requires: afl-fuzz installed, target compiled with AFL instrumentation.
    Harness: instrumented binary path.
    """

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        seed_dir = str(kwargs.get("seed_dir", ""))
        output_dir = str(kwargs.get("output_dir", ""))

        if not seed_dir:
            seed_dir = tempfile.mkdtemp(prefix="afl_seeds_")
            # Create at least one seed
            Path(seed_dir, "seed_0").write_bytes(b"AAAA")

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="afl_output_")

        cmd = [
            "afl-fuzz",
            "-i", seed_dir,
            "-o", output_dir,
            "-t", "1000+",                         # Per-exec timeout in ms (+ = auto-calibrate)
            "-V", str(timeout_seconds),          # Total campaign time
            "--", harness_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 60,
            )

            crashes = self._collect_crashes(output_dir)
            metrics = self._parse_stats(output_dir)

            return EngineResult(
                success=result.returncode == 0,
                metrics=metrics,
                artifact_candidates=crashes,
                corpus_path=os.path.join(output_dir, "default", "queue"),
                errors=[result.stderr] if result.returncode != 0 else [],
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            crashes = self._collect_crashes(output_dir)
            metrics = self._parse_stats(output_dir)
            return EngineResult(
                success=True,  # Timeout is normal for AFL
                metrics=metrics,
                artifact_candidates=crashes,
                corpus_path=os.path.join(output_dir, "default", "queue"),
                errors=[],
                exit_code=0,
            )
        except FileNotFoundError:
            return EngineResult(
                success=False,
                metrics={},
                artifact_candidates=[],
                corpus_path=None,
                errors=["afl-fuzz not found"],
                exit_code=1,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _collect_crashes(self, output_dir: str) -> list[dict]:
        crashes: list[dict] = []
        crash_dir = Path(output_dir) / "default" / "crashes"
        if crash_dir.exists():
            for f in crash_dir.iterdir():
                if f.is_file() and f.name != "README.txt":
                    crashes.append({
                        "type": "crash",
                        "path": str(f),
                        "input": f.read_bytes().hex()[:200],
                        "method": "afl_mutation",
                        "status_code": "crash",
                    })
        return crashes

    def _parse_stats(self, output_dir: str) -> dict:
        stats_file = Path(output_dir) / "default" / "fuzzer_stats"
        metrics: dict = {
            "total_execs": 0,
            "unique_crashes": 0,
            "unique_hangs": 0,
            "corpus_size": 0,
            "edges_found": 0,
            "exec_speed": 0,
        }
        if stats_file.exists():
            for line in stats_file.read_text().splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    key = key.strip()
                    val = val.strip()
                    try:
                        if key == "execs_done":
                            metrics["total_execs"] = int(val)
                        elif key == "saved_crashes":
                            metrics["unique_crashes"] = int(val)
                        elif key == "saved_hangs":
                            metrics["unique_hangs"] = int(val)
                        elif key == "corpus_count":
                            metrics["corpus_size"] = int(val)
                        elif key == "edges_found":
                            metrics["edges_found"] = int(val)
                        elif key == "execs_per_sec":
                            metrics["exec_speed"] = float(val)
                    except (ValueError, TypeError):
                        pass
        return metrics
