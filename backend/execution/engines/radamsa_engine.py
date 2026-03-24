"""Radamsa engine adapter for generic mutation-based fuzzing."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from execution.engines.engine_interface import EngineInterface, EngineResult


class RadamsaEngine(EngineInterface):
    """Radamsa -- generic test case mutator."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        seed_file = str(kwargs.get("seed_file", ""))
        output_dir = str(kwargs.get("output_dir", "")) or tempfile.mkdtemp(prefix="radamsa_")
        count = int(kwargs.get("count", 1000))  # type: ignore[arg-type]

        # Generate mutated inputs
        cmd = [
            "radamsa",
            "-n", str(count),
            "-o", f"{output_dir}/case_%n",
            seed_file or harness_path,
        ]

        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout_seconds)

            generated = list(Path(output_dir).glob("case_*"))

            return EngineResult(
                success=True,
                metrics={"mutations_generated": len(generated)},
                artifact_candidates=[],  # Radamsa generates, doesn't execute
                corpus_path=output_dir,
                errors=[],
                exit_code=0,
            )
        except FileNotFoundError:
            return EngineResult(
                success=False,
                metrics={},
                artifact_candidates=[],
                corpus_path=None,
                errors=["radamsa not found"],
                exit_code=1,
            )
