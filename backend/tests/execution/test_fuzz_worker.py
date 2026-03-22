"""Tests for execution.workers.fuzz_worker -- fuzz lane execution."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from execution.docker_manager import TargetStackInfo
from execution.engines.engine_interface import EngineResult
from execution.workers.fuzz_worker import execute_run_lane


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_stack_info(**overrides) -> TargetStackInfo:
    """Build a TargetStackInfo with sensible defaults."""
    defaults = dict(
        base_url="http://localhost:8080",
        network_name="qh_c1",
        container_ids=["abc123"],
        compose_path="/path/to/compose.yaml",
    )
    defaults.update(overrides)
    return TargetStackInfo(**defaults)


def _make_engine_result(**overrides) -> EngineResult:
    """Build a successful EngineResult with sensible defaults."""
    defaults = dict(
        success=True,
        metrics={"failures_count": 0, "status_classes": {}},
        artifact_candidates=[],
        corpus_path=None,
        errors=[],
        exit_code=0,
    )
    defaults.update(overrides)
    return EngineResult(**defaults)


def _make_docker_manager(healthy: bool = True) -> MagicMock:
    """Build a mock DockerNetworkManager."""
    dm = MagicMock()
    dm.create_campaign_network.return_value = "qh_c1"
    dm.launch_target_stack.return_value = _make_stack_info()
    dm.wait_for_healthy.return_value = healthy
    dm.teardown_target_stack.return_value = None
    dm.teardown_network.return_value = None
    return dm


def _make_engine(result: EngineResult | None = None) -> MagicMock:
    """Build a mock SchemathesisEngine."""
    eng = MagicMock()
    eng.run.return_value = result or _make_engine_result()
    return eng


def _make_object_store(harness_bytes: bytes = b"# harness code") -> MagicMock:
    """Build a mock LocalFileStore."""
    store = MagicMock()
    store.get.return_value = harness_bytes
    return store


# ===========================================================================
# Happy path
# ===========================================================================


class TestHappyPath:
    """Engine runs successfully, coverage recorded, status=completed."""

    @pytest.mark.asyncio
    async def test_happy_path_returns_completed(self):
        """Run completes: status=completed, metrics and candidates returned."""
        dm = _make_docker_manager()
        eng = _make_engine(_make_engine_result(
            success=True,
            metrics={"failures_count": 1, "status_classes": {"5xx": 1}},
            artifact_candidates=[
                {"method": "POST", "path": "/api/users", "status_code": 500},
            ],
        ))
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ) as mock_update,
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ) as mock_coverage,
            patch("tempfile.NamedTemporaryFile") as mock_tmpfile,
        ):
            mock_tmpfile.return_value.__enter__ = MagicMock(
                return_value=MagicMock(name="/tmp/harness.py", write=MagicMock())
            )
            mock_tmpfile.return_value.__enter__.return_value.name = "/tmp/harness.py"
            mock_tmpfile.return_value.__exit__ = MagicMock(return_value=False)

            result = await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="campaigns/c1/harnesses/ls1.py",
                compose_path="/path/to/compose.yaml",
                openapi_url="openapi.json",
                timeout_seconds=60,
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        assert result["status"] == "completed"
        assert result["run_lane_id"] == "rl1"
        assert result["metrics"]["failures_count"] == 1
        assert len(result["artifact_candidates"]) == 1
        assert result["artifact_candidates"][0]["method"] == "POST"

        # Run status updated: first to running, then to completed
        assert mock_update.call_count == 2
        first_call = mock_update.call_args_list[0]
        assert first_call.args == ("rl1", "running")
        last_call = mock_update.call_args_list[1]
        assert last_call.args == ("rl1", "completed")

        # Coverage snapshot recorded
        mock_coverage.assert_called_once()
        assert mock_coverage.call_args.kwargs["run_lane_id"] == "rl1"

        # Docker target was launched and torn down
        dm.create_campaign_network.assert_called_once_with("c1")
        dm.launch_target_stack.assert_called_once_with("c1", "/path/to/compose.yaml")
        dm.wait_for_healthy.assert_called_once()
        dm.teardown_target_stack.assert_called_once_with("c1", "/path/to/compose.yaml")
        dm.teardown_network.assert_called_once_with("c1")


# ===========================================================================
# Target unhealthy
# ===========================================================================


class TestTargetUnhealthy:
    """Target fails health check -- run should fail with error message."""

    @pytest.mark.asyncio
    async def test_unhealthy_target_fails(self):
        """Unhealthy target: status=failed, meaningful error message."""
        dm = _make_docker_manager(healthy=False)
        eng = _make_engine()
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ) as mock_update,
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ) as mock_coverage,
        ):
            result = await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="ref",
                compose_path="/compose.yaml",
                openapi_url="openapi.json",
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        assert result["status"] == "failed"
        assert any("healthy" in e for e in result["errors"])
        assert result["artifact_candidates"] == []

        # Engine should not have been called
        eng.run.assert_not_called()

        # Coverage should not be recorded
        mock_coverage.assert_not_called()

        # Run status updated to running then failed
        assert mock_update.call_count == 2
        last_call = mock_update.call_args_list[1]
        assert last_call.args == ("rl1", "failed")

    @pytest.mark.asyncio
    async def test_unhealthy_target_still_tears_down(self):
        """Teardown always called even when target is unhealthy."""
        dm = _make_docker_manager(healthy=False)
        eng = _make_engine()
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ),
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ),
        ):
            await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="ref",
                compose_path="/compose.yaml",
                openapi_url="openapi.json",
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        dm.teardown_target_stack.assert_called_once_with("c1", "/compose.yaml")
        dm.teardown_network.assert_called_once_with("c1")


# ===========================================================================
# Engine failure
# ===========================================================================


class TestEngineFailure:
    """Engine returns non-success result -- run should be marked failed."""

    @pytest.mark.asyncio
    async def test_engine_failure_marks_run_failed(self):
        """Engine failure (exit_code != 0): status=failed."""
        dm = _make_docker_manager()
        eng = _make_engine(_make_engine_result(
            success=False,
            metrics={"failures_count": 0, "exit_code": 2},
            errors=["Schemathesis encountered internal errors"],
            exit_code=2,
        ))
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ) as mock_update,
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ),
            patch("tempfile.NamedTemporaryFile") as mock_tmpfile,
        ):
            mock_tmpfile.return_value.__enter__ = MagicMock(
                return_value=MagicMock(name="/tmp/harness.py", write=MagicMock())
            )
            mock_tmpfile.return_value.__enter__.return_value.name = "/tmp/harness.py"
            mock_tmpfile.return_value.__exit__ = MagicMock(return_value=False)

            result = await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="ref",
                compose_path="/compose.yaml",
                openapi_url="openapi.json",
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        assert result["status"] == "failed"
        assert len(result["errors"]) > 0

        # Final status update should be "failed"
        last_call = mock_update.call_args_list[-1]
        assert last_call.args == ("rl1", "failed")

    @pytest.mark.asyncio
    async def test_engine_exception_marks_run_failed(self):
        """Engine raises exception: status=failed, error captured."""
        dm = _make_docker_manager()
        eng = _make_engine()
        eng.run.side_effect = RuntimeError("schemathesis binary not found")
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ) as mock_update,
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ),
            patch("tempfile.NamedTemporaryFile") as mock_tmpfile,
        ):
            mock_tmpfile.return_value.__enter__ = MagicMock(
                return_value=MagicMock(name="/tmp/harness.py", write=MagicMock())
            )
            mock_tmpfile.return_value.__enter__.return_value.name = "/tmp/harness.py"
            mock_tmpfile.return_value.__exit__ = MagicMock(return_value=False)

            result = await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="ref",
                compose_path="/compose.yaml",
                openapi_url="openapi.json",
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        assert result["status"] == "failed"
        assert "schemathesis binary not found" in result["errors"][0]

        # Run should still have been marked failed
        failed_calls = [
            c for c in mock_update.call_args_list
            if c.args[1] == "failed"
        ]
        assert len(failed_calls) >= 1


# ===========================================================================
# Teardown always called
# ===========================================================================


class TestTeardownAlwaysCalled:
    """Teardown must happen even when the run fails mid-execution."""

    @pytest.mark.asyncio
    async def test_teardown_on_engine_exception(self):
        """Teardown called even when engine raises."""
        dm = _make_docker_manager()
        eng = _make_engine()
        eng.run.side_effect = RuntimeError("boom")
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ),
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ),
            patch("tempfile.NamedTemporaryFile") as mock_tmpfile,
        ):
            mock_tmpfile.return_value.__enter__ = MagicMock(
                return_value=MagicMock(name="/tmp/harness.py", write=MagicMock())
            )
            mock_tmpfile.return_value.__enter__.return_value.name = "/tmp/harness.py"
            mock_tmpfile.return_value.__exit__ = MagicMock(return_value=False)

            await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="ref",
                compose_path="/compose.yaml",
                openapi_url="openapi.json",
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        dm.teardown_target_stack.assert_called_once_with("c1", "/compose.yaml")
        dm.teardown_network.assert_called_once_with("c1")

    @pytest.mark.asyncio
    async def test_teardown_on_network_create_failure(self):
        """If network creation fails, teardown is still attempted for network."""
        dm = _make_docker_manager()
        dm.create_campaign_network.side_effect = RuntimeError("docker not available")
        eng = _make_engine()
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ),
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ),
        ):
            result = await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="ref",
                compose_path="/compose.yaml",
                openapi_url="openapi.json",
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        assert result["status"] == "failed"
        # Target was never launched, so no teardown_target_stack call
        dm.teardown_target_stack.assert_not_called()

    @pytest.mark.asyncio
    async def test_teardown_on_happy_path(self):
        """Teardown called on successful completion too."""
        dm = _make_docker_manager()
        eng = _make_engine()
        store = _make_object_store()

        with (
            patch(
                "execution.workers.fuzz_worker.run_lane_service.update_run_status",
                new_callable=AsyncMock,
            ),
            patch(
                "execution.workers.fuzz_worker.coverage_service.record_snapshot",
                new_callable=AsyncMock,
            ),
            patch("tempfile.NamedTemporaryFile") as mock_tmpfile,
        ):
            mock_tmpfile.return_value.__enter__ = MagicMock(
                return_value=MagicMock(name="/tmp/harness.py", write=MagicMock())
            )
            mock_tmpfile.return_value.__enter__.return_value.name = "/tmp/harness.py"
            mock_tmpfile.return_value.__exit__ = MagicMock(return_value=False)

            await execute_run_lane(
                run_lane_id="rl1",
                execution_bundle_id="eb1",
                campaign_id="c1",
                harness_code_ref="ref",
                compose_path="/compose.yaml",
                openapi_url="openapi.json",
                docker_manager=dm,
                engine=eng,
                object_store=store,
            )

        dm.teardown_target_stack.assert_called_once()
        dm.teardown_network.assert_called_once()
