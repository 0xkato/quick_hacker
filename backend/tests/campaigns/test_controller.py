"""Tests for campaigns.controller -- campaign planning workflow."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from campaigns.controller import CampaignController
from models.campaign_enums import CampaignPreset, CampaignStatus
from models.campaign_schemas import CampaignResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_campaign(**overrides) -> CampaignResponse:
    """Build a CampaignResponse with sensible defaults."""
    defaults = dict(
        id="c1",
        repo_id="proj1",
        status=CampaignStatus.CREATED,
        preset=CampaignPreset.QUICK,
        budget_seconds=600,
        max_parallel_lanes=2,
        lm_provider="claude_cli",
        lm_model="claude-opus-4-6",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return CampaignResponse(**defaults)


# ===========================================================================
# CampaignController.plan_campaign
# ===========================================================================


class TestCampaignController:
    """Tests for CampaignController.plan_campaign."""

    @pytest.mark.asyncio
    async def test_plan_valid_repo(self, tmp_path):
        """Valid repo: contract passes, targets extracted, status updated."""
        # Arrange: create valid repo files
        (tmp_path / "docker-compose.yml").write_text(
            "version: '3'\nservices:\n  app:\n    build: ."
        )
        (tmp_path / "openapi.json").write_text(
            json.dumps(
                {
                    "openapi": "3.0.0",
                    "info": {"title": "Test API"},
                    "paths": {
                        "/api/users": {
                            "get": {"responses": {"200": {}}},
                            "post": {"responses": {"201": {}}},
                        }
                    },
                }
            )
        )

        mock_campaign = _make_campaign()
        updated_campaign = _make_campaign(status=CampaignStatus.EXTRACTING)

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=str(tmp_path),
            ),
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=updated_campaign,
            ) as mock_update,
            patch(
                "campaigns.controller.target_service.create_targets_batch",
                new_callable=AsyncMock,
                return_value=[],
            ) as mock_batch,
        ):
            result = await controller.plan_campaign("c1")

        # Assert status updated to EXTRACTING
        mock_update.assert_called_once_with("c1", CampaignStatus.EXTRACTING.value)
        assert result.status == CampaignStatus.EXTRACTING

        # Assert targets were created (2 operations: GET + POST)
        mock_batch.assert_called_once()
        call_args = mock_batch.call_args
        assert call_args[0][0] == "c1"  # campaign_id
        targets = call_args[0][1]
        assert len(targets) == 2
        entrypoints = {t["entrypoint"] for t in targets}
        assert "GET /api/users" in entrypoints
        assert "POST /api/users" in entrypoints

    @pytest.mark.asyncio
    async def test_plan_invalid_repo_fails(self, tmp_path):
        """Missing compose: plan fails, status set to FAILED."""
        # Only openapi, no compose
        (tmp_path / "openapi.json").write_text(
            json.dumps({"openapi": "3.0.0", "paths": {}})
        )

        mock_campaign = _make_campaign()

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=str(tmp_path),
            ),
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=_make_campaign(status=CampaignStatus.FAILED),
            ) as mock_update,
        ):
            with pytest.raises(ValueError, match="Support contract invalid"):
                await controller.plan_campaign("c1")

        # Assert status set to FAILED with an error message
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        assert call_args[0][1] == CampaignStatus.FAILED.value
        assert "error_message" in call_args[1]
        assert "compose" in call_args[1]["error_message"].lower()

    @pytest.mark.asyncio
    async def test_plan_missing_campaign_fails(self):
        """Non-existent campaign raises ValueError."""
        controller = CampaignController()

        with patch(
            "campaigns.controller.campaign_service.get_campaign",
            new_callable=AsyncMock,
            return_value=None,
        ):
            with pytest.raises(ValueError, match="Campaign not found"):
                await controller.plan_campaign("nonexistent")

    @pytest.mark.asyncio
    async def test_plan_missing_repo_fails(self):
        """Campaign with no repo path raises ValueError."""
        mock_campaign = _make_campaign()

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=None,
            ),
        ):
            with pytest.raises(ValueError, match="Project repo not found"):
                await controller.plan_campaign("c1")

    @pytest.mark.asyncio
    async def test_plan_no_openapi_skips_extraction(self, tmp_path):
        """Repo with compose but no OpenAPI: no targets extracted, still succeeds."""
        (tmp_path / "docker-compose.yml").write_text(
            "version: '3'\nservices:\n  app:\n    build: ."
        )
        (tmp_path / "openapi.json").write_text(
            json.dumps({"openapi": "3.0.0", "paths": {}})
        )

        mock_campaign = _make_campaign()
        updated_campaign = _make_campaign(status=CampaignStatus.EXTRACTING)

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=str(tmp_path),
            ),
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=updated_campaign,
            ) as mock_update,
            patch(
                "campaigns.controller.target_service.create_targets_batch",
                new_callable=AsyncMock,
                return_value=[],
            ) as mock_batch,
        ):
            result = await controller.plan_campaign("c1")

        # Status still transitions to EXTRACTING
        mock_update.assert_called_once_with("c1", CampaignStatus.EXTRACTING.value)
        assert result.status == CampaignStatus.EXTRACTING

        # No targets to create, so batch should not be called
        mock_batch.assert_not_called()
