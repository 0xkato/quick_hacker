"""Echidna engine adapter for Solidity smart contract fuzzing."""

from __future__ import annotations

import json
import subprocess

from execution.engines.engine_interface import EngineInterface, EngineResult


class EchidnaEngine(EngineInterface):
    """Echidna -- property-based Solidity smart contract fuzzer."""

    def run(
        self,
        harness_path: str,
        base_url: str,
        timeout_seconds: int,
        **kwargs: object,
    ) -> EngineResult:
        config: dict = kwargs.get("config", {})  # type: ignore[assignment]
        test_limit = config.get("test_limit", 50000) if isinstance(config, dict) else 50000

        cmd = [
            "echidna", harness_path,
            "--test-limit", str(test_limit),
            "--timeout", str(timeout_seconds),
            "--format", "json",
        ]

        contract_name = config.get("contract_name") if isinstance(config, dict) else None
        if contract_name:
            cmd.extend(["--contract", contract_name])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 60,
            )

            findings = self._parse_results(result.stdout)

            return EngineResult(
                success=len(findings) == 0,
                metrics={"tests_run": test_limit},
                artifact_candidates=findings,
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
                errors=["echidna not found"],
                exit_code=1,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _parse_results(self, stdout: str) -> list[dict]:
        findings: list[dict] = []
        try:
            data = json.loads(stdout)
            for test in data if isinstance(data, list) else []:
                if test.get("status") == "failed":
                    findings.append({
                        "type": "oracle_hit",
                        "method": "echidna_property",
                        "path": test.get("name", "unknown"),
                        "status_code": "property_violation",
                        "details": json.dumps(test.get("reproducer", [])),
                    })
        except json.JSONDecodeError:
            pass
        return findings
