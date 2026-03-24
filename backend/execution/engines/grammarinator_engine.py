"""Grammarinator engine adapter for grammar-based fuzzing."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from execution.engines.engine_interface import EngineInterface, EngineResult


class GrammarinatorEngine(EngineInterface):
    """Grammarinator -- ANTLR grammar-based test generation."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        grammar_file = str(kwargs.get("grammar_file", harness_path))
        output_dir = str(kwargs.get("output_dir", "")) or tempfile.mkdtemp(prefix="grammarinator_")
        count = int(kwargs.get("count", 100))  # type: ignore[arg-type]
        max_depth = int(kwargs.get("max_depth", 20))  # type: ignore[arg-type]

        cmd = [
            "grammarinator-generate",
            "-g", grammar_file,
            "-o", output_dir,
            "-n", str(count),
            "--max-depth", str(max_depth),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            generated = list(Path(output_dir).iterdir())

            return EngineResult(
                success=result.returncode == 0,
                metrics={"tests_generated": len(generated)},
                artifact_candidates=[],
                corpus_path=output_dir,
                errors=[result.stderr] if result.returncode != 0 else [],
                exit_code=result.returncode,
            )
        except FileNotFoundError:
            return EngineResult(
                success=False,
                metrics={},
                artifact_candidates=[],
                corpus_path=None,
                errors=["grammarinator not found"],
                exit_code=1,
            )
