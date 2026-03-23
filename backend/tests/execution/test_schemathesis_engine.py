"""Tests for execution.engines.schemathesis_engine — Schemathesis adapter."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from execution.engines.engine_interface import EngineResult
from execution.engines.schemathesis_engine import SchemathesisEngine


class TestBuildCommand:
    """Verify CLI command construction."""

    def test_basic_command(self) -> None:
        engine = SchemathesisEngine()
        cmd = engine._build_command("/tmp/harness.py", "http://localhost:3000", 60)

        assert cmd == [
            "python", "-m", "pytest",
            "/tmp/harness.py",
            "-v",
            "--tb=short",
            "--timeout=60",
        ]

    def test_extra_flags_appended(self) -> None:
        engine = SchemathesisEngine()
        cmd = engine._build_command(
            "/spec.yaml",
            "http://localhost:3000",
            60,
            extra_flags=["--dry-run", "--workers=4"],
        )

        assert "--dry-run" in cmd
        assert "--workers=4" in cmd

    def test_timeout_flag_uses_seconds(self) -> None:
        engine = SchemathesisEngine()
        cmd = engine._build_command("/harness.py", "http://localhost", 120)

        assert "--timeout=120" in cmd


class TestRunSuccess:
    """Exit code 0 — all checks passed."""

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_success_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="All checks passed!\n", stderr=""
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert isinstance(result, EngineResult)
        assert result.success is True
        assert result.exit_code == 0
        assert result.errors == []
        assert result.artifact_candidates == []

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_success_metrics(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert result.metrics["failures_count"] == 0
        assert result.metrics["tests_passed"] == 0
        assert result.metrics["tests_failed"] == 0
        assert result.metrics["tests_total"] == 0
        assert result.metrics["validity_ratio"] == 1.0
        assert result.metrics["exit_code"] == 0


class TestRunFailuresFound:
    """Exit code 1 — schemathesis found failures."""

    SAMPLE_OUTPUT = """\
============================= test session starts ==============================
collected 5 items

test_harness.py::test_POST_api_users[Case1] FAILED
test_harness.py::test_GET_api_items_999[Case1] FAILED
test_harness.py::test_PUT_api_items_1[Case1] FAILED
test_harness.py::test_GET_api_health[Case1] PASSED
test_harness.py::test_DELETE_api_items_1[Case1] PASSED

=========================== short test summary info ============================
FAILED test_harness.py::test_POST_api_users[Case1] - assert 200 != 500
FAILED test_harness.py::test_GET_api_items_999[Case1] - assert 200 != 500
FAILED test_harness.py::test_PUT_api_items_1[Case1] - assert 200 != 422
========================= 2 passed, 3 failed in 1.23s =========================
"""

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_failures_detected(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=self.SAMPLE_OUTPUT, stderr=""
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert result.success is False
        assert result.exit_code == 1

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_artifact_candidates_parsed(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=self.SAMPLE_OUTPUT, stderr=""
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert len(result.artifact_candidates) == 3
        assert result.artifact_candidates[0] == {
            "test_name": "test_POST_api_users",
            "method": "POST",
            "path": "/api/users",
            "params": "Case1",
            "message": "assert 200 != 500",
        }
        assert result.artifact_candidates[1] == {
            "test_name": "test_GET_api_items_999",
            "method": "GET",
            "path": "/api/items/999",
            "params": "Case1",
            "message": "assert 200 != 500",
        }
        assert result.artifact_candidates[2] == {
            "test_name": "test_PUT_api_items_1",
            "method": "PUT",
            "path": "/api/items/1",
            "params": "Case1",
            "message": "assert 200 != 422",
        }

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_status_class_metrics(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=self.SAMPLE_OUTPUT, stderr=""
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert result.metrics["failures_count"] == 3
        assert result.metrics["tests_passed"] == 2
        assert result.metrics["tests_failed"] == 3
        assert result.metrics["tests_total"] == 5
        assert result.metrics["operations_hit"] == 3

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_no_errors_on_exit_1(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=self.SAMPLE_OUTPUT, stderr=""
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        # exit code 1 means failures, not engine errors
        assert result.errors == []


class TestRunErrors:
    """Exit code 2 — schemathesis internal errors."""

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_error_result(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=2,
            stdout="",
            stderr="Error: Invalid schema at /spec.yaml",
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert result.success is False
        assert result.exit_code == 2
        assert len(result.errors) == 2
        assert "internal errors" in result.errors[0]
        assert "Invalid schema" in result.errors[1]

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_error_no_stderr(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr=""
        )

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert len(result.errors) == 1


class TestRunTimeout:
    """subprocess.TimeoutExpired handling."""

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_timeout_returns_failure(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="schemathesis", timeout=90)

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert result.success is False
        assert result.exit_code == -1
        assert result.metrics["timed_out"] is True
        assert len(result.errors) == 1
        assert "timed out" in result.errors[0].lower()

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_timeout_empty_artifacts(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="schemathesis", timeout=90)

        engine = SchemathesisEngine()
        result = engine.run("/spec.yaml", "http://localhost:3000", 60)

        assert result.artifact_candidates == []
        assert result.corpus_path is None


class TestSubprocessInvocation:
    """Verify that subprocess.run is called correctly."""

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_captures_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        engine = SchemathesisEngine()
        engine.run("/spec.yaml", "http://localhost:3000", 60)

        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs["capture_output"] is True
        assert call_kwargs.kwargs["text"] is True

    @patch("execution.engines.schemathesis_engine.subprocess.run")
    def test_timeout_includes_grace_period(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

        engine = SchemathesisEngine()
        engine.run("/spec.yaml", "http://localhost:3000", 60)

        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs["timeout"] == 90  # 60 + 30 grace
