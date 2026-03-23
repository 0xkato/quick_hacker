"""Fuzz worker -- executes a run lane against a live target.

For v1 this is a regular async function.  Dramatiq actor wiring will be
added when workers actually run in production.  The function coordinates
Docker target lifecycle, engine execution, and result recording.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from datetime import datetime, timezone

from execution.docker_manager import DockerNetworkManager
from execution.engines.schemathesis_engine import SchemathesisEngine
from services.coverage_service import coverage_service
from services.run_lane_service import run_lane_service
from storage.object_store import LocalFileStore

logger = logging.getLogger(__name__)


async def execute_run_lane(
    run_lane_id: str,
    execution_bundle_id: str,
    campaign_id: str,
    harness_code_ref: str,
    compose_path: str,
    openapi_url: str,
    timeout_seconds: int = 1800,
    *,
    docker_manager: DockerNetworkManager | None = None,
    engine: SchemathesisEngine | None = None,
    object_store: LocalFileStore | None = None,
) -> dict:
    """Execute a fuzz lane against a live target.

    Steps
    -----
    1.  Update run status to RUNNING.
    2.  Create campaign Docker network.
    3.  Launch target from Compose.
    4.  Wait for healthy.
    5.  Download harness code from artifact store.
    6.  Write harness to temp file.
    7.  Run Schemathesis engine.
    8.  Record coverage snapshots.
    9.  For each failure: create raw artifact candidate dict.
    10. Update run status to COMPLETED / FAILED.
    11. Teardown target stack.
    12. Return results dict with metrics + artifact_candidates.

    Parameters
    ----------
    run_lane_id:
        The ID of the RunLane record to update.
    execution_bundle_id:
        The execution bundle this run belongs to.
    campaign_id:
        The campaign that owns this run.
    harness_code_ref:
        Key in the object store for the harness source code.
    compose_path:
        Path to the docker-compose file for the target.
    openapi_url:
        URL or path to the OpenAPI spec for the target.
    timeout_seconds:
        Maximum wall-clock time for the engine run.
    docker_manager:
        Optional injected DockerNetworkManager (for testing).
    engine:
        Optional injected SchemathesisEngine (for testing).
    object_store:
        Optional injected LocalFileStore (for testing).

    Returns
    -------
    dict with keys: run_lane_id, status, metrics, artifact_candidates, errors.
    """
    dm = docker_manager or DockerNetworkManager()
    eng = engine or SchemathesisEngine()
    store = object_store or LocalFileStore(".artifacts")

    network_name: str | None = None
    target_launched = False
    harness_path: str | None = None

    try:
        # 1. Update run status to RUNNING
        await run_lane_service.update_run_status(
            run_lane_id,
            "running",
            started_at=datetime.now(timezone.utc),
        )

        # 2. Create campaign Docker network
        network_name = await asyncio.to_thread(dm.create_campaign_network, campaign_id)

        # 3. Launch target from Compose
        stack_info = await asyncio.to_thread(dm.launch_target_stack, campaign_id, compose_path)
        target_launched = True

        # 4. Wait for healthy
        healthy = await asyncio.to_thread(dm.wait_for_healthy, stack_info.base_url)
        if not healthy:
            error_msg = (
                f"Target at {stack_info.base_url} did not become healthy"
            )
            logger.error(error_msg)
            await run_lane_service.update_run_status(
                run_lane_id,
                "failed",
                completed_at=datetime.now(timezone.utc),
            )
            return {
                "run_lane_id": run_lane_id,
                "status": "failed",
                "metrics": {},
                "artifact_candidates": [],
                "errors": [error_msg],
            }

        # 5. Download harness code from artifact store
        harness_bytes = await asyncio.to_thread(store.get, harness_code_ref)
        if harness_bytes is None:
            error_msg = f"Harness code not found: {harness_code_ref}"
            logger.error(error_msg)
            await run_lane_service.update_run_status(
                run_lane_id,
                "failed",
                completed_at=datetime.now(timezone.utc),
            )
            return {
                "run_lane_id": run_lane_id,
                "status": "failed",
                "metrics": {},
                "artifact_candidates": [],
                "errors": [error_msg],
            }

        # 6. Write harness to temp file
        def _write_temp(data: bytes) -> str:
            with tempfile.NamedTemporaryFile(
                suffix=".py", delete=False, mode="wb"
            ) as tmp:
                tmp.write(data)
                return tmp.name

        harness_path = await asyncio.to_thread(_write_temp, harness_bytes)

        # 7. Run Schemathesis engine
        result = await asyncio.to_thread(
            eng.run,
            harness_path=harness_path,
            base_url=stack_info.base_url,
            timeout_seconds=timeout_seconds,
        )

        # 8. Record coverage snapshots
        await coverage_service.record_snapshot(
            run_lane_id=run_lane_id,
            snapshot_data=result.metrics,
        )

        # 9. Build artifact candidate dicts
        artifact_candidates = []
        for failure in result.artifact_candidates:
            artifact_candidates.append(
                {
                    "run_lane_id": run_lane_id,
                    "type": "crash",
                    "method": failure.get("method"),
                    "path": failure.get("path"),
                    "status_code": failure.get("status_code"),
                }
            )

        # 10. Update run status to COMPLETED or FAILED
        final_status = "completed" if result.success else "failed"
        await run_lane_service.update_run_status(
            run_lane_id,
            final_status,
            completed_at=datetime.now(timezone.utc),
        )

        return {
            "run_lane_id": run_lane_id,
            "status": final_status,
            "metrics": result.metrics,
            "artifact_candidates": artifact_candidates,
            "errors": result.errors,
        }

    except Exception as exc:
        logger.exception("execute_run_lane failed for %s", run_lane_id)
        error_msg = str(exc)

        try:
            await run_lane_service.update_run_status(
                run_lane_id,
                "failed",
                completed_at=datetime.now(timezone.utc),
            )
        except Exception:
            logger.exception("Failed to update run status after error")

        return {
            "run_lane_id": run_lane_id,
            "status": "failed",
            "metrics": {},
            "artifact_candidates": [],
            "errors": [error_msg],
        }

    finally:
        # Clean up temp harness file
        if harness_path and os.path.exists(harness_path):
            try:
                os.unlink(harness_path)
            except OSError:
                pass

        # 11. Teardown target stack (always)
        try:
            if target_launched:
                await asyncio.to_thread(dm.teardown_target_stack, campaign_id, compose_path)
        except Exception:
            logger.exception("Failed to teardown target stack")

        try:
            if network_name:
                await asyncio.to_thread(dm.teardown_network, campaign_id)
        except Exception:
            logger.exception("Failed to teardown Docker network")
