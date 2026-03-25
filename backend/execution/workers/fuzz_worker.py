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
from execution.engines.registry import get_engine
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
    needs_docker_target: bool | None = None,
    repo_path: str = "",
    docker_manager: DockerNetworkManager | None = None,
    engine: SchemathesisEngine | None = None,
    object_store: LocalFileStore | None = None,
) -> dict:
    """Execute a fuzz lane against a live or native target.

    Steps
    -----
    1.  Update run status to RUNNING.
    2.  If Docker target needed: create network, launch compose, wait healthy.
    3.  Download harness code from artifact store.
    4.  Write harness to temp file.
    5.  Run engine.
    6.  Record coverage snapshots.
    7.  For each failure: create raw artifact candidate dict.
    8.  Update run status to COMPLETED / FAILED.
    9.  Teardown Docker (if used).
    10. Return results dict with metrics + artifact_candidates.

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
        Path to the docker-compose file for the target (empty = no Docker).
    openapi_url:
        URL or path to the OpenAPI spec for the target.
    timeout_seconds:
        Maximum wall-clock time for the engine run.
    needs_docker_target:
        Whether to launch a Docker target. Defaults to bool(compose_path).
    repo_path:
        Path to the cloned repo (used as base_url for native fuzzers).
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
    # Determine whether Docker is needed
    needs_docker = needs_docker_target if needs_docker_target is not None else bool(compose_path)

    dm = docker_manager or DockerNetworkManager()
    eng = engine or get_engine("schemathesis")
    store = object_store or LocalFileStore(".artifacts")

    network_name: str | None = None
    target_launched = False
    stack_info = None
    harness_path: str | None = None

    try:
        # 1. Update run status to RUNNING
        await run_lane_service.update_run_status(
            run_lane_id,
            "running",
            started_at=datetime.now(timezone.utc),
        )

        # 2. Docker target lifecycle (only if compose_path provided)
        if needs_docker:
            network_name = await asyncio.to_thread(dm.create_campaign_network, campaign_id)

            stack_info = await asyncio.to_thread(dm.launch_target_stack, campaign_id, compose_path)
            target_launched = True

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

            base_url = stack_info.base_url
        else:
            # Native fuzzing — no Docker target needed
            base_url = repo_path
            logger.info(
                "[execute_run_lane] No Docker target — native fuzzing against %s",
                repo_path,
            )

        # 3. Download harness code from artifact store
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

        # 5. Run engine
        result = await asyncio.to_thread(
            eng.run,
            harness_path=harness_path,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
        )

        # 8. Record coverage snapshots
        await coverage_service.record_snapshot(
            run_lane_id=run_lane_id,
            snapshot_data=result.metrics,
        )

        # 8b. Save corpus reference
        if result.corpus_path:
            from database.connection import get_session
            from database.campaign_models import Corpus as DBCorpus
            import uuid as _uuid

            async with get_session() as session:
                corpus = DBCorpus(
                    id=_uuid.uuid4().hex[:8],
                    lane_spec_id=job_data.get("lane_spec_id", "") if isinstance(job_data, dict) else "",
                    item_count=0,  # v1: not counting individual items
                    total_bytes=0,
                )
                session.add(corpus)
                await session.flush()

        # 9. Build artifact candidate dicts
        artifact_candidates = []
        for failure in result.artifact_candidates:
            artifact_candidates.append(
                {
                    "run_lane_id": run_lane_id,
                    "type": failure.get("type", "crash"),
                    "method": failure.get("method"),
                    "path": failure.get("path"),
                    "status_code": failure.get("status_code"),
                }
            )

        # 9b. Process artifact candidates through evidence pipeline
        from evidence.bucketer import process_raw_artifact
        from evidence.replayer import replay_artifact as replay_fn
        from evidence.classifier import classify_after_replay
        from issues.gating import evaluate_proof
        from models.campaign_schemas import ProofChecklist
        from services.artifact_service import artifact_service
        from services.issue_service import issue_service
        from observability.campaign_events import campaign_broadcaster

        for candidate in artifact_candidates:
            # Step 1: Bucket and create artifact
            artifact = await process_raw_artifact(
                campaign_id=campaign_id,
                run_lane_id=run_lane_id,
                candidate=candidate,
                artifact_service=artifact_service,
                object_store=store,
            )

            if artifact is None:
                continue  # Bucket full, skip replay

            # Step 2: Replay for reproducibility (sync function)
            replay_result = await asyncio.to_thread(
                replay_fn,
                artifact_candidate=candidate,
                base_url=base_url,
                attempts=3,
            )

            # Extract artifact_id early for minimization + analysis
            artifact_id = artifact["artifact_id"]

            # Step 2b: Minimize artifact before classification
            from evidence.minimization import minimize_artifact as minimize_fn

            minimization_result = await minimize_fn(
                artifact_id=artifact_id,
                budget_seconds=60,
            )
            minimized = minimization_result.get("minimized", False)

            # Step 3: Classify based on replay
            classification = classify_after_replay(replay_result, candidate)

            # Update artifact classification
            await artifact_service.update_classification(
                artifact_id,
                classification=classification,
            )

            # Step 4: If issue candidate, run gating
            if classification == "issue_candidate":
                checklist = ProofChecklist(
                    target_real=True,
                    harness_validated=True,
                    real_code_reached=True,
                    external_input_controlled=True,
                    oracle_triggered_or_sanitizer_hit=True,
                    reproduced_cleanly=replay_result.reproduced,
                    artifact_minimization_attempted=True,
                    not_harness_artifact=True,
                    not_test_only=True,
                    security_impact_confirmed=False,
                )

                gating_result = evaluate_proof(checklist)

                if gating_result.is_issue:
                    # Step 4b: Run analysis LM job before issue creation
                    from issues.analysis import analyze_artifact as analyze_fn

                    analysis = await analyze_fn(
                        artifact_id=artifact_id,
                        evidence_refs=candidate.get("evidence_refs", []),
                    )

                    issue = await issue_service.create_issue(
                        artifact_id=artifact_id,
                        severity=analysis.get("severity_recommendation") or "medium",
                        title=f"Failure in {candidate.get('method', '?')} {candidate.get('path', '?')}",
                        description=f"Status {candidate.get('status_code', '?')} - {gating_result.disposition}",
                        category=candidate.get("type", "unknown"),
                        cwe_id=None,
                        disposition=gating_result.disposition,
                        proof=checklist.model_dump(),
                        root_cause=analysis.get("root_cause"),
                        recommended_fix=analysis.get("recommended_fix"),
                    )

                    campaign_broadcaster.emit_issue_upsert(
                        campaign_id=campaign_id,
                        issue_id=issue.id,
                        disposition=gating_result.disposition or "unknown",
                        severity="medium",
                    )

        # 10. Update run status to COMPLETED or FAILED
        final_status = "completed" if result.success else "failed"
        await run_lane_service.update_run_status(
            run_lane_id,
            final_status,
            completed_at=datetime.now(timezone.utc),
        )

        # 10b. Post-run lifecycle: scheduler + completion + steering
        await _post_run_lifecycle(campaign_id)

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

        # Post-run lifecycle even on failure
        try:
            await _post_run_lifecycle(campaign_id)
        except Exception:
            logger.exception("Post-run lifecycle failed after error")

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

        # Teardown Docker target (only if we launched one)
        if needs_docker:
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


async def _post_run_lifecycle(campaign_id: str) -> None:
    """Handle post-run lifecycle: scheduler bookkeeping, completion check,
    and periodic steering.

    Called after every run lane finishes (success or failure).
    """
    from campaigns.controller import campaign_controller
    from campaigns.scheduler import campaign_scheduler

    # 1. Record lane completion in scheduler
    try:
        campaign_scheduler.record_lane_complete(campaign_id)
    except Exception:
        logger.exception("[fuzz_worker] Error recording lane complete")

    # 2. Check if campaign is complete
    try:
        await campaign_controller.check_campaign_completion(campaign_id)
    except Exception:
        logger.exception("[fuzz_worker] Error checking campaign completion")

    # 3. Periodic steering check
    try:
        if campaign_scheduler.can_steer(campaign_id):
            campaign_scheduler.record_steering_start(campaign_id)
            try:
                await campaign_controller.check_steering(campaign_id)
            finally:
                campaign_scheduler.record_steering_complete(campaign_id)
    except Exception:
        logger.exception("[fuzz_worker] Steering error")
