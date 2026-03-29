"""Campaign controller -- orchestrates intake, extraction, compilation, and execution.

The controller ties together validation, capability profiling, target
extraction, harness compilation, and run lane creation into lifecycle
phase methods that transition a campaign from CREATED through RUNNING.
"""

from __future__ import annotations

import logging
import os

from campaigns.intake import detect_capability_profile, validate_support_contract
from campaigns.planner import plan_lanes_for_targets
from lanes.harness_compiler import compile_harness
from lanes.validators import validate_harness
from models.campaign_enums import CampaignStatus
from models.campaign_schemas import CampaignResponse
from services.campaign_service import campaign_service
from services.execution_bundle_service import execution_bundle_service
from services.harness_service import harness_service
from services.lane_service import lane_service
from services.oracle_pack_service import oracle_pack_service
from services.project_service import project_service
from services.run_lane_service import run_lane_service
from services.seed_set_service import seed_set_service
from services.target_service import target_service
from storage.object_store import LocalFileStore
from targets.extractors.multi_extractor import extract_all_targets

logger = logging.getLogger(__name__)


class CampaignController:
    """High-level controller for campaign lifecycle phases."""

    async def plan_campaign(self, campaign_id: str) -> CampaignResponse:
        """Run intake + extraction for a campaign.

        1. Fetch the campaign from the campaign service.
        2. Resolve the repo path from the project service.
        3. Validate the v1 support contract.
        4. Detect capability profile.
        5. Extract targets from OpenAPI spec (if present).
        6. Persist targets and update campaign status to EXTRACTING.

        Raises:
            ValueError: If the campaign does not exist, the repo path
                cannot be resolved, or the support contract is invalid.
        """
        # 1. Fetch campaign
        campaign = await campaign_service.get_campaign(campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign not found: {campaign_id}")

        # 2. Resolve repo path (sync method)
        repo_path = project_service.get_project_repo_path(campaign.repo_id)
        if repo_path is None:
            raise ValueError("Project repo not found")

        # 3. Validate repo capabilities (advisory, not blocking)
        contract = validate_support_contract(repo_path)
        if contract.reasons:
            import logging as _logging
            _log = _logging.getLogger(__name__)
            for reason in contract.reasons:
                _log.warning("[plan_campaign] %s", reason)

        # 4. Detect capability profile
        profile = detect_capability_profile(repo_path)

        # 5. Extract targets (multi-language + OpenAPI)
        # Get scope from campaign config
        config = await campaign_service.get_campaign_config(campaign_id) or {}
        target_scope = config.get("target_scope")
        target_filters = config.get("target_filters")
        directed_targets = config.get("directed_targets")

        full_openapi_path = profile.openapi_path if profile.openapi_path else None
        targets = extract_all_targets(
            repo_path=repo_path,
            openapi_path=full_openapi_path,
            languages=None,  # Always detect from search paths, not profile
            target_scope=target_scope,
            target_filters=target_filters,
            directed_targets=directed_targets,
        )

        # 6. Persist targets
        logger.info("[plan] Campaign %s: extracted %d targets from %s",
                     campaign_id, len(targets), target_scope or "full repo")
        if targets:
            await target_service.create_targets_batch(campaign_id, targets)
        else:
            logger.warning("[plan] Campaign %s: NO targets extracted", campaign_id)

        # 7. Transition status to EXTRACTING with started_at
        from datetime import datetime, timezone

        from observability.campaign_events import campaign_broadcaster

        updated = await campaign_service.update_campaign_status(
            campaign_id,
            CampaignStatus.EXTRACTING.value,
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )

        # Emit WebSocket event
        campaign_broadcaster.emit_campaign_status(campaign_id, "extracting")

        return updated

    async def compile_campaign(self, campaign_id: str) -> CampaignResponse:
        """Run planning + compilation for a campaign.

        1. Get campaign and its config.
        2. Get targets from target_service.
        3. Plan lanes via planner.plan_lanes_for_targets.
        4. For each planned lane:
           a. Create lane spec via lane_service.
           b. Get target info for compiler.
           c. Compile harness (compile_schemathesis_config).
           d. Validate harness (validate_harness).
           e. If valid: store harness artifact, create harness record,
              oracle pack, seed set, and execution bundle.
           f. If invalid: retire lane immediately (v1: one attempt per lane).
        5. Update campaign status to COMPILING.
        6. If all lanes retired: update to FAILED.

        Raises:
            ValueError: If the campaign does not exist.
        """
        # 1. Fetch campaign + config
        campaign = await campaign_service.get_campaign(campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign not found: {campaign_id}")

        # 2. Get campaign config (needed for engine filter + retry limits)
        campaign_config = await campaign_service.get_campaign_config(campaign_id) or {}

        # 3. Get targets
        targets = await target_service.list_targets(campaign_id)
        if not targets:
            await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="No targets found for compilation",
            )
            raise ValueError("No targets found for compilation")

        # 4. Plan lanes
        planned_lanes = plan_lanes_for_targets(
            targets,
            campaign_preset=campaign.preset.value,
            enabled_engines=campaign_config.get("enabled_engines"),
        )

        if not planned_lanes:
            await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="No lanes planned from targets",
            )
            raise ValueError("No lanes planned from targets")

        # 4. Compile each lane (with retry loop)
        # Resolve repo path for capability profile (openapi_url)
        repo_path = project_service.get_project_repo_path(campaign.repo_id)
        profile = detect_capability_profile(repo_path) if repo_path else None
        openapi_filename = (
            os.path.basename(profile.openapi_path)
            if profile and profile.openapi_path
            else "openapi.json"
        )

        # Set up artifact store under a campaign-specific directory
        artifact_root = os.environ.get(
            "ARTIFACT_STORE_ROOT",
            os.path.join(os.getcwd(), ".artifacts"),
        )
        store = LocalFileStore(artifact_root)

        # Get retry limit from campaign config (fetched earlier)
        max_failures = campaign_config.get("max_compilation_failures_per_lane", 3)

        total_lanes = len(planned_lanes)
        retired_count = 0
        compiled_count = 0

        logger.info("[compile] Campaign %s: compiling %d lanes", campaign_id, total_lanes)

        for lane_idx, lane_dict in enumerate(planned_lanes):
            lane_spec = None
            try:
                # 4a. Create lane spec
                lane_spec = await lane_service.create_lane_spec(
                    target_id=lane_dict["target_id"],
                    engine=lane_dict["engine"],
                    structure_model=lane_dict["structure_model"],
                    input_producer=lane_dict["input_producer"],
                    feedback_models=lane_dict.get("feedback_models"),
                    oracle_packs=lane_dict.get("oracle_packs"),
                    budget_seconds=lane_dict.get("budget_seconds"),
                    seed_sources=lane_dict.get("seed_sources"),
                )

                # 4b. Get target info
                target = await target_service.get_target(lane_dict["target_id"])
                if target is None:
                    logger.warning("[compile] Target %s not found, retiring lane %s",
                                   lane_dict["target_id"], lane_spec.id)
                    await lane_service.update_lane_spec_status(lane_spec.id, "retired")
                    retired_count += 1
                    continue

                # 4c-d. Compile and validate harness with retry loop
                attempt = 0
                compiled = False
                while attempt < max_failures and not compiled:
                    attempt += 1

                    engine = lane_dict.get("engine", "schemathesis")

                    harness_result = compile_harness(
                        engine=engine,
                        target={
                            "entrypoint": target.entrypoint,
                            "language": target.language or "c",
                            "stateful": target.stateful,
                        },
                        repo_path=repo_path or "",
                        openapi_url=openapi_filename,
                        base_url="http://target:8080",
                        lane_spec=lane_dict,
                    )

                    harness_code = harness_result["code"]
                    harness_language = harness_result.get("language", "python")

                    validation = validate_harness(harness_code, language=harness_language)

                    if validation.passed:
                        compiled = True

                        ext_map = {
                            "python": ".py", "c": ".c", "cpp": ".cpp",
                            "java": ".java", "go": "_test.go", "rust": ".rs",
                            "solidity": ".sol", "json": ".json",
                            "config": ".conf", "sql": ".sql",
                        }
                        ext = ext_map.get(harness_language, ".txt")
                        harness_ref = f"campaigns/{campaign_id}/harnesses/{lane_spec.id}{ext}"
                        store.put(harness_ref, harness_code.encode("utf-8"))

                        harness = await harness_service.create_harness(
                            lane_spec_id=lane_spec.id,
                            code_ref=harness_ref,
                            validation_results=validation.gates,
                        )

                        oracle_pack = await oracle_pack_service.create_oracle_pack(
                            lane_spec_id=lane_spec.id,
                            config={"packs": lane_dict.get("oracle_packs", [])},
                        )

                        seed_set = await seed_set_service.create_seed_set(
                            lane_spec_id=lane_spec.id,
                            sources=lane_dict.get("seed_sources", []),
                        )

                        await execution_bundle_service.create_bundle(
                            campaign_id=campaign_id,
                            campaign_plan_revision=1,
                            lane_spec_id=lane_spec.id,
                            lane_spec_revision=lane_spec.revision,
                            harness_id=harness["id"],
                            harness_revision=harness.get("revision", 1),
                            oracle_pack_id=oracle_pack["id"],
                            oracle_pack_revision=oracle_pack.get("revision", 1),
                            seed_set_id=seed_set["id"],
                        )

                        await lane_service.update_lane_spec_status(
                            lane_spec.id, "validated"
                        )
                        compiled_count += 1
                    else:
                        logger.warning(
                            "[compile] Lane %s attempt %d/%d failed: %s",
                            lane_spec.id, attempt, max_failures, validation.errors,
                        )

                if not compiled:
                    await lane_service.update_lane_spec_status(
                        lane_spec.id, "retired"
                    )
                    retired_count += 1

                    from observability.campaign_events import campaign_broadcaster
                    campaign_broadcaster.emit_lane_retired(
                        campaign_id, lane_spec.id,
                        f"Failed after {max_failures} attempts",
                    )

            except Exception:
                lane_id = lane_spec.id if lane_spec else "unknown"
                logger.exception("[compile] Unexpected error compiling lane %s", lane_id)
                if lane_spec:
                    await lane_service.update_lane_spec_status(lane_spec.id, "retired")
                retired_count += 1

        # 5. Update campaign status
        from observability.campaign_events import campaign_broadcaster

        logger.info("[compile] Campaign %s: %d compiled, %d retired out of %d lanes",
                     campaign_id, compiled_count, retired_count, total_lanes)

        if compiled_count == 0:
            # All lanes retired
            updated = await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="All lanes retired due to compilation failures",
            )
            campaign_broadcaster.emit_campaign_status(campaign_id, "failed")
        else:
            updated = await campaign_service.update_campaign_status(
                campaign_id, CampaignStatus.COMPILING.value
            )
            campaign_broadcaster.emit_campaign_status(campaign_id, "compiling")

        return updated

    async def execute_campaign(self, campaign_id: str) -> CampaignResponse:
        """Create run lanes, enqueue Dramatiq jobs, and start execution.

        1. Get campaign.
        2. Get all validated execution bundles.
        3. For each bundle (respecting scheduler limits): create RunLane
           record (status=queued) and enqueue job.
        4. Update campaign status to RUNNING with started_at timestamp.
        5. Emit WebSocket event.
        6. Return campaign.

        Raises:
            ValueError: If the campaign does not exist or has no bundles.
        """
        from datetime import datetime, timezone

        from campaigns.scheduler import campaign_scheduler
        from execution.workers.fuzz_worker_actor import run_lane
        from observability.campaign_events import campaign_broadcaster

        # 1. Get campaign
        campaign = await campaign_service.get_campaign(campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign not found: {campaign_id}")

        # 2. Get all validated execution bundles
        bundles = await execution_bundle_service.list_bundles(campaign_id)
        if not bundles:
            await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="No execution bundles found",
            )
            raise ValueError("No execution bundles found")

        # Resolve repo path for compose file discovery
        repo_path = project_service.get_project_repo_path(campaign.repo_id)

        # Resolve compose_path and openapi_url for env snapshot
        compose_path = ""
        openapi_url = "openapi.json"
        if repo_path:
            for name in [
                "docker-compose.yml",
                "compose.yaml",
                "docker-compose.yaml",
                "compose.yml",
            ]:
                candidate_path = os.path.join(repo_path, name)
                if os.path.exists(candidate_path):
                    compose_path = candidate_path
                    break

        # 2b. Create env snapshot
        import uuid as _uuid

        from database.campaign_models import EnvSnapshot as DBEnvSnapshot
        from database.connection import get_session

        env_snap_id = _uuid.uuid4().hex[:8]
        async with get_session() as session:
            snap = DBEnvSnapshot(
                id=env_snap_id,
                campaign_id=campaign_id,
                target_base_url=None,  # Will be set when target launches
                network_name=f"qh_{campaign_id}",
                reset_command=None,
                config={"compose_path": compose_path, "openapi_url": openapi_url},
            )
            session.add(snap)
            await session.flush()

        # Initialize scheduler tracker with campaign parallelism limit
        max_parallel = campaign.max_parallel_lanes or 2
        campaign_scheduler.get_tracker(campaign_id, max_parallel=max_parallel)

        # 3. For each bundle: create RunLane record and enqueue Dramatiq job
        created_runs = []
        for bundle in bundles:
            if not campaign_scheduler.can_enqueue_lane(campaign_id):
                # Scheduler limit reached; remaining bundles will be
                # picked up when a running lane completes.
                break

            run = await run_lane_service.create_run(
                lane_spec_id=bundle.lane_spec_id,
                execution_bundle_id=bundle.id,
            )

            # Resolve lane spec engine for correct harness ref + engine routing
            lane_spec_info = await lane_service.get_lane_spec(bundle.lane_spec_id)
            lane_engine = lane_spec_info.engine if lane_spec_info else "schemathesis"

            # Determine harness file extension from engine
            engine_ext_map = {
                "schemathesis": ".py", "atheris": ".py", "hypothesis": ".py",
                "boofuzz": ".py", "aflpp": ".c", "jazzer": ".java",
                "go_fuzz": "_test.go", "cargo_fuzz": ".rs",
                "echidna": ".sol", "foundry": ".sol",
                "restler": ".json", "grammarinator": ".conf",
                "sqlsmith": ".sql", "radamsa": ".conf",
            }
            harness_ext = engine_ext_map.get(lane_engine, ".py")

            # Build job data for the Dramatiq actor
            job_data = {
                "run_lane_id": run.id,
                "execution_bundle_id": bundle.id,
                "campaign_id": campaign_id,
                "harness_code_ref": f"campaigns/{campaign_id}/harnesses/{bundle.lane_spec_id}{harness_ext}",
                "compose_path": compose_path or "",  # Empty = no Docker target
                "needs_docker_target": bool(compose_path),
                "openapi_url": openapi_url,
                "timeout_seconds": run.timeout_seconds or 1800,
                "lane_spec_id": bundle.lane_spec_id,
                "env_snapshot_id": env_snap_id,
                "repo_path": repo_path or "",
                "engine_name": lane_engine,
            }

            run_lane.send(job_data)
            campaign_scheduler.record_lane_start(campaign_id)
            created_runs.append(run)

        # 4. Update campaign status to RUNNING with started_at
        updated = await campaign_service.update_campaign_status(
            campaign_id,
            CampaignStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )

        # 5. Emit WebSocket event
        campaign_broadcaster.emit_campaign_status(campaign_id, "running")

        return updated

    async def check_campaign_completion(
        self, campaign_id: str
    ) -> CampaignResponse | None:
        """Check if all runs are done and transition campaign accordingly.

        Gets all RunLane records for the campaign (through bundles).
        If ALL runs are in a terminal state (completed/failed/cancelled/
        superseded): transitions campaign to COMPLETED (or FAILED if every
        run failed).  Sets ``completed_at`` timestamp.

        Returns the updated campaign, or ``None`` if the campaign is not
        yet ready for completion.
        """
        from datetime import datetime, timezone

        from observability.campaign_events import campaign_broadcaster

        campaign = await campaign_service.get_campaign(campaign_id)
        if not campaign or campaign.status != CampaignStatus.RUNNING:
            return None

        bundles = await execution_bundle_service.list_bundles(campaign_id)
        if not bundles:
            return None

        all_runs = []
        for bundle in bundles:
            lane_spec_id = bundle.lane_spec_id if hasattr(bundle, "lane_spec_id") else bundle.get("lane_spec_id")
            runs = await run_lane_service.list_runs(lane_spec_id)
            all_runs.extend(runs)

        if not all_runs:
            return None

        terminal = {"completed", "failed", "cancelled", "superseded"}
        statuses = []
        for r in all_runs:
            s = r.status if hasattr(r, "status") else r.get("status", "")
            statuses.append(s)

        if not all(s in terminal for s in statuses):
            return None  # Still running

        # All done -- determine final status
        completed_count = sum(1 for s in statuses if s == "completed")

        if completed_count > 0:
            final_status = CampaignStatus.COMPLETED.value
        else:
            final_status = CampaignStatus.FAILED.value

        result = await campaign_service.update_campaign_status(
            campaign_id,
            final_status,
            completed_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )

        campaign_broadcaster.emit_campaign_status(campaign_id, final_status)

        return result

    async def check_steering(self, campaign_id: str) -> dict | None:
        """Check if steering action needed. Returns decision or None.

        Aggregates real coverage snapshots, lane metrics, and artifact
        counts from the database before feeding them to the steering
        engine.
        """
        from campaigns.steering import generate_steering_decision
        from services.coverage_service import coverage_service
        from services.steering_service import steering_service
        from services.run_lane_service import run_lane_service
        from services.artifact_service import artifact_service

        # Get campaign + config
        campaign = await campaign_service.get_campaign(campaign_id)
        if not campaign:
            return None

        config = await campaign_service.get_campaign_config(campaign_id) or {}

        # Get all execution bundles for this campaign
        bundles = await execution_bundle_service.list_bundles(campaign_id)

        # Aggregate coverage snapshots and lane metrics from real data
        snapshots: list[dict] = []
        lane_metrics: list[dict] = []
        for bundle in bundles:
            runs = await run_lane_service.list_runs(bundle.lane_spec_id)
            for run in runs:
                run_coverage = await coverage_service.get_lane_coverage(run.id)
                snapshots.extend(run_coverage)

                lane_metrics.append({
                    "lane_id": bundle.lane_spec_id,
                    "validity_ratio": (
                        run_coverage[-1].get("snapshot_data", {}).get("validity_ratio", 1.0)
                        if run_coverage else 1.0
                    ),
                    "requests_per_sec": 0,
                    "budget_used_pct": 50.0,  # estimate until real tracking (percentage)
                })

        # Count artifacts
        artifacts = await artifact_service.list_artifacts(campaign_id)
        artifact_counts = {"total": len(artifacts)}

        plateau_window = config.get("plateau_window_seconds", 300)

        decision = generate_steering_decision(
            campaign_id, lane_metrics, snapshots, artifact_counts, plateau_window
        )

        if decision:
            await steering_service.record_decision(
                campaign_id=decision.campaign_id,
                decision_type=decision.decision_type,
                triggering_metrics=decision.triggering_metrics,
                recommendation=decision.recommendation,
                affected_lane_ids=decision.affected_lane_ids,
            )

        return decision

    async def start_campaign(self, campaign_id: str) -> CampaignResponse:
        """Full pipeline: plan -> compile -> execute."""
        await self.plan_campaign(campaign_id)
        result = await self.compile_campaign(campaign_id)

        # Don't proceed to execute if compilation failed all lanes
        if result and result.status == CampaignStatus.FAILED:
            logger.error("[start] Campaign %s failed during compilation: %s",
                         campaign_id, result.error_message)
            return result

        return await self.execute_campaign(campaign_id)


# Module-level singleton
campaign_controller = CampaignController()
