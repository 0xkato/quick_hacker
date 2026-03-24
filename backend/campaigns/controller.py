"""Campaign controller -- orchestrates intake, extraction, compilation, and execution.

The controller ties together validation, capability profiling, target
extraction, harness compilation, and run lane creation into lifecycle
phase methods that transition a campaign from CREATED through RUNNING.
"""

from __future__ import annotations

import os

from campaigns.intake import detect_capability_profile, validate_support_contract
from campaigns.planner import plan_lanes_for_targets
from lanes.compiler import compile_schemathesis_config
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
from targets.extractors.openapi_extractor import extract_targets_from_file


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

        # 3. Validate v1 support contract
        contract = validate_support_contract(repo_path)
        if not contract.valid:
            await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="; ".join(contract.reasons),
            )
            raise ValueError(
                f"Support contract invalid: {'; '.join(contract.reasons)}"
            )

        # 4. Detect capability profile
        profile = detect_capability_profile(repo_path)

        # 5. Extract targets from OpenAPI spec
        targets: list[dict] = []
        if profile.openapi_path:
            language = profile.languages[0] if profile.languages else None
            targets = extract_targets_from_file(
                profile.openapi_path,
                language=language,
            )

        # 6. Persist targets
        if targets:
            await target_service.create_targets_batch(campaign_id, targets)

        # 7. Transition status to EXTRACTING with started_at
        from datetime import datetime, timezone

        from observability.campaign_events import campaign_broadcaster

        updated = await campaign_service.update_campaign_status(
            campaign_id,
            CampaignStatus.EXTRACTING.value,
            started_at=datetime.now(timezone.utc),
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

        # 2. Get targets
        targets = await target_service.list_targets(campaign_id)
        if not targets:
            await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="No targets found for compilation",
            )
            raise ValueError("No targets found for compilation")

        # 3. Plan lanes
        planned_lanes = plan_lanes_for_targets(
            targets, campaign_preset=campaign.preset.value
        )

        if not planned_lanes:
            await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="No lanes planned from targets",
            )
            raise ValueError("No lanes planned from targets")

        # 4. Compile each lane
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

        total_lanes = len(planned_lanes)
        retired_count = 0

        for lane_dict in planned_lanes:
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

            # 4c. Compile harness
            harness_code = compile_schemathesis_config(
                lane_spec=lane_dict,
                target={
                    "entrypoint": target.entrypoint,
                    "stateful": target.stateful,
                },
                openapi_url=openapi_filename,
            )

            # 4d. Validate harness
            validation = validate_harness(harness_code)

            if validation.passed:
                # 4e. Store harness code in artifact store
                harness_ref = f"campaigns/{campaign_id}/harnesses/{lane_spec.id}.py"
                store.put(harness_ref, harness_code.encode("utf-8"))

                # Create harness record
                harness = await harness_service.create_harness(
                    lane_spec_id=lane_spec.id,
                    code_ref=harness_ref,
                    validation_results=validation.gates,
                )

                # Create oracle pack
                oracle_pack = await oracle_pack_service.create_oracle_pack(
                    lane_spec_id=lane_spec.id,
                    config={"packs": lane_dict.get("oracle_packs", [])},
                )

                # Create seed set
                seed_set = await seed_set_service.create_seed_set(
                    lane_spec_id=lane_spec.id,
                    sources=lane_dict.get("seed_sources", []),
                )

                # Create execution bundle
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

                # Mark lane as validated
                await lane_service.update_lane_spec_status(
                    lane_spec.id, "validated"
                )
            else:
                # 4f. Per-lane failure: v1 has no retry loop, so a single
                # compilation failure immediately retires the lane.
                await lane_service.update_lane_spec_status(
                    lane_spec.id, "retired"
                )
                retired_count += 1

                # Emit lane retired event
                from observability.campaign_events import campaign_broadcaster
                campaign_broadcaster.emit_lane_retired(
                    campaign_id, lane_spec.id, "validation_failed"
                )

        # 5. Update campaign status
        from observability.campaign_events import campaign_broadcaster

        if retired_count == total_lanes:
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

            # Build job data for the Dramatiq actor
            job_data = {
                "run_lane_id": run.id,
                "execution_bundle_id": bundle.id,
                "campaign_id": campaign_id,
                "harness_code_ref": f"campaigns/{campaign_id}/harnesses/{bundle.lane_spec_id}.py",
                "compose_path": "",
                "openapi_url": "openapi.json",
                "timeout_seconds": run.timeout_seconds or 1800,
            }

            # Resolve compose_path from project repo
            if repo_path:
                for name in [
                    "docker-compose.yml",
                    "compose.yaml",
                    "docker-compose.yaml",
                    "compose.yml",
                ]:
                    candidate = os.path.join(repo_path, name)
                    if os.path.exists(candidate):
                        job_data["compose_path"] = candidate
                        break

            run_lane.send(job_data)
            campaign_scheduler.record_lane_start(campaign_id)
            created_runs.append(run)

        # 4. Update campaign status to RUNNING with started_at
        updated = await campaign_service.update_campaign_status(
            campaign_id,
            CampaignStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
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
            bundle_id = bundle.id if hasattr(bundle, "id") else bundle.get("id")
            runs = await run_lane_service.list_runs(bundle_id)
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
            completed_at=datetime.now(timezone.utc),
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
        await self.compile_campaign(campaign_id)
        return await self.execute_campaign(campaign_id)


# Module-level singleton
campaign_controller = CampaignController()
