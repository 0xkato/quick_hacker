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

        # 7. Transition status to EXTRACTING
        updated = await campaign_service.update_campaign_status(
            campaign_id, CampaignStatus.EXTRACTING.value
        )

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

        # 5. Update campaign status
        if retired_count == total_lanes:
            # All lanes retired
            updated = await campaign_service.update_campaign_status(
                campaign_id,
                CampaignStatus.FAILED.value,
                error_message="All lanes retired due to compilation failures",
            )
        else:
            updated = await campaign_service.update_campaign_status(
                campaign_id, CampaignStatus.COMPILING.value
            )

        return updated

    async def execute_campaign(self, campaign_id: str) -> CampaignResponse:
        """Create run lanes and prepare for execution.

        1. Get campaign.
        2. Get all validated execution bundles.
        3. For each bundle: create RunLane record (status=queued).
        4. Update campaign status to RUNNING.
        5. Return campaign (runs will be executed by workers).

        Raises:
            ValueError: If the campaign does not exist or has no bundles.
        """
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

        # 3. For each bundle: create RunLane record
        for bundle in bundles:
            await run_lane_service.create_run(
                lane_spec_id=bundle.lane_spec_id,
                execution_bundle_id=bundle.id,
            )

        # 4. Update campaign status to RUNNING
        updated = await campaign_service.update_campaign_status(
            campaign_id, CampaignStatus.RUNNING.value
        )

        return updated

    async def check_steering(self, campaign_id: str) -> dict | None:
        """Check if steering action needed. Returns decision or None.

        v1 stub: wires steering engine to the controller but does not
        implement full metrics aggregation yet.
        """
        from campaigns.steering import generate_steering_decision
        from services.coverage_service import coverage_service
        from services.steering_service import steering_service

        # Get coverage snapshots for all runs in this campaign
        snapshots: list[dict] = []  # aggregate from coverage_service
        lane_metrics: list[dict] = []  # aggregate from lane metrics
        artifact_counts: dict = {}  # count per bucket

        decision = generate_steering_decision(
            campaign_id, lane_metrics, snapshots, artifact_counts
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
