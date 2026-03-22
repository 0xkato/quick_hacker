"""Campaign controller -- orchestrates intake and target extraction.

The controller ties together validation, capability profiling, and target
extraction into a single ``plan_campaign`` workflow that transitions a
campaign from CREATED through EXTRACTING.
"""

from __future__ import annotations

import os

from campaigns.intake import detect_capability_profile, validate_support_contract
from models.campaign_enums import CampaignStatus
from models.campaign_schemas import CampaignResponse
from services.campaign_service import campaign_service
from services.project_service import project_service
from services.target_service import target_service
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


# Module-level singleton
campaign_controller = CampaignController()
