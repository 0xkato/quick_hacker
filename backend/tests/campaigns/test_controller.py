"""Tests for campaigns.controller -- campaign planning, compilation, and execution."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from campaigns.controller import CampaignController
from models.campaign_enums import (
    CampaignPreset,
    CampaignStatus,
    FeedbackModel,
    InputProducer,
    LaneSpecStatus,
    StructureModel,
    TargetKind,
)
from models.campaign_schemas import (
    CampaignResponse,
    ExecutionBundleResponse,
    LaneSpecResponse,
    TargetResponse,
)


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


def _make_target(**overrides) -> TargetResponse:
    """Build a TargetResponse with sensible defaults."""
    defaults = dict(
        id="t1",
        campaign_id="c1",
        kind=TargetKind.API_ROUTE,
        entrypoint="GET /api/users",
        language="python",
        stateful=False,
        priority_score=0.0,
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return TargetResponse(**defaults)


def _make_lane_spec(**overrides) -> LaneSpecResponse:
    """Build a LaneSpecResponse with sensible defaults."""
    defaults = dict(
        id="ls1",
        target_id="t1",
        revision=1,
        structure_model=StructureModel.SCHEMA,
        input_producer=InputProducer.GENERATION,
        feedback_models=[FeedbackModel.API_SURFACE],
        oracle_packs=["status_code", "schema_conformance"],
        engine="schemathesis",
        budget_seconds=60,
        seed_sources=["openapi_examples"],
        status=LaneSpecStatus.PLANNED,
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return LaneSpecResponse(**defaults)


def _make_bundle(**overrides) -> ExecutionBundleResponse:
    """Build an ExecutionBundleResponse with sensible defaults."""
    defaults = dict(
        id="eb1",
        campaign_id="c1",
        campaign_plan_revision=1,
        lane_spec_id="ls1",
        lane_spec_revision=1,
        harness_id="h1",
        harness_revision=1,
        oracle_pack_id="op1",
        oracle_pack_revision=1,
        seed_set_id="ss1",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return ExecutionBundleResponse(**defaults)


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

        # Assert status updated to EXTRACTING (with started_at kwarg)
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        assert call_args[0] == ("c1", CampaignStatus.EXTRACTING.value)
        assert "started_at" in call_args[1]
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

        # Status still transitions to EXTRACTING (with started_at kwarg)
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        assert call_args[0] == ("c1", CampaignStatus.EXTRACTING.value)
        assert "started_at" in call_args[1]
        assert result.status == CampaignStatus.EXTRACTING

        # No targets to create, so batch should not be called
        mock_batch.assert_not_called()


# ===========================================================================
# CampaignController.compile_campaign
# ===========================================================================


class TestCompileCampaign:
    """Tests for CampaignController.compile_campaign."""

    @pytest.mark.asyncio
    async def test_compile_creates_lanes_and_bundles(self, tmp_path):
        """compile_campaign creates lane specs and execution bundles."""
        mock_campaign = _make_campaign(status=CampaignStatus.EXTRACTING)
        mock_target = _make_target(id="t1", entrypoint="GET /api/users")
        mock_lane_spec = _make_lane_spec(id="ls1", target_id="t1")
        compiling_campaign = _make_campaign(status=CampaignStatus.COMPILING)

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.campaign_service.get_campaign_config",
                new_callable=AsyncMock,
                return_value={"max_compilation_failures_per_lane": 3},
            ),
            patch(
                "campaigns.controller.target_service.list_targets",
                new_callable=AsyncMock,
                return_value=[mock_target],
            ),
            patch(
                "campaigns.controller.target_service.get_target",
                new_callable=AsyncMock,
                return_value=mock_target,
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=str(tmp_path),
            ),
            patch(
                "campaigns.controller.detect_capability_profile",
                return_value=MagicMock(openapi_path="openapi.json"),
            ),
            patch(
                "campaigns.controller.lane_service.create_lane_spec",
                new_callable=AsyncMock,
                return_value=mock_lane_spec,
            ) as mock_create_lane,
            patch(
                "campaigns.controller.harness_service.create_harness",
                new_callable=AsyncMock,
                return_value={"id": "h1", "revision": 1, "code_ref": "ref"},
            ) as mock_create_harness,
            patch(
                "campaigns.controller.oracle_pack_service.create_oracle_pack",
                new_callable=AsyncMock,
                return_value={"id": "op1", "revision": 1, "config": {}},
            ) as mock_create_oracle,
            patch(
                "campaigns.controller.seed_set_service.create_seed_set",
                new_callable=AsyncMock,
                return_value={"id": "ss1", "sources": [], "item_count": 0},
            ) as mock_create_seed,
            patch(
                "campaigns.controller.execution_bundle_service.create_bundle",
                new_callable=AsyncMock,
                return_value=_make_bundle(),
            ) as mock_create_bundle,
            patch(
                "campaigns.controller.lane_service.update_lane_spec_status",
                new_callable=AsyncMock,
                return_value=mock_lane_spec,
            ) as mock_update_lane,
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=compiling_campaign,
            ) as mock_update_status,
            patch(
                "campaigns.controller.LocalFileStore",
            ) as MockStore,
        ):
            MockStore.return_value.put = MagicMock()

            result = await controller.compile_campaign("c1")

        # Lane spec was created
        mock_create_lane.assert_called_once()

        # Harness, oracle, seed, and bundle were created
        mock_create_harness.assert_called_once()
        mock_create_oracle.assert_called_once()
        mock_create_seed.assert_called_once()
        mock_create_bundle.assert_called_once()

        # Lane marked as validated
        mock_update_lane.assert_called_once_with("ls1", "validated")

        # Campaign status updated to COMPILING
        mock_update_status.assert_called_once_with(
            "c1", CampaignStatus.COMPILING.value
        )
        assert result.status == CampaignStatus.COMPILING

    @pytest.mark.asyncio
    async def test_compile_retires_invalid_lanes(self, tmp_path):
        """Invalid harness -> lane marked retired."""
        mock_campaign = _make_campaign(status=CampaignStatus.EXTRACTING)
        mock_target = _make_target(id="t1", entrypoint="GET /api/users")
        mock_lane_spec = _make_lane_spec(id="ls1", target_id="t1")

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.campaign_service.get_campaign_config",
                new_callable=AsyncMock,
                return_value={"max_compilation_failures_per_lane": 1},
            ),
            patch(
                "campaigns.controller.target_service.list_targets",
                new_callable=AsyncMock,
                return_value=[mock_target],
            ),
            patch(
                "campaigns.controller.target_service.get_target",
                new_callable=AsyncMock,
                return_value=mock_target,
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=str(tmp_path),
            ),
            patch(
                "campaigns.controller.detect_capability_profile",
                return_value=MagicMock(openapi_path="openapi.json"),
            ),
            patch(
                "campaigns.controller.lane_service.create_lane_spec",
                new_callable=AsyncMock,
                return_value=mock_lane_spec,
            ),
            # Force invalid harness by making compiler return bad code
            patch(
                "campaigns.controller.compile_schemathesis_config",
                return_value="invalid python code }{}{",
            ),
            patch(
                "campaigns.controller.validate_harness",
                return_value=MagicMock(passed=False, errors=["Syntax error"]),
            ),
            patch(
                "campaigns.controller.lane_service.update_lane_spec_status",
                new_callable=AsyncMock,
                return_value=mock_lane_spec,
            ) as mock_update_lane,
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=_make_campaign(status=CampaignStatus.FAILED),
            ),
            patch(
                "campaigns.controller.LocalFileStore",
            ) as MockStore,
        ):
            MockStore.return_value.put = MagicMock()

            result = await controller.compile_campaign("c1")

        # Lane marked as retired (failure_count=1 >= max_failures=1)
        mock_update_lane.assert_called_once_with("ls1", "retired")

    @pytest.mark.asyncio
    async def test_compile_fails_if_all_retired(self, tmp_path):
        """All lanes retired -> campaign status FAILED."""
        mock_campaign = _make_campaign(status=CampaignStatus.EXTRACTING)
        mock_target = _make_target(id="t1", entrypoint="GET /api/users")
        mock_lane_spec = _make_lane_spec(id="ls1", target_id="t1")

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.campaign_service.get_campaign_config",
                new_callable=AsyncMock,
                return_value={"max_compilation_failures_per_lane": 1},
            ),
            patch(
                "campaigns.controller.target_service.list_targets",
                new_callable=AsyncMock,
                return_value=[mock_target],
            ),
            patch(
                "campaigns.controller.target_service.get_target",
                new_callable=AsyncMock,
                return_value=mock_target,
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=str(tmp_path),
            ),
            patch(
                "campaigns.controller.detect_capability_profile",
                return_value=MagicMock(openapi_path="openapi.json"),
            ),
            patch(
                "campaigns.controller.lane_service.create_lane_spec",
                new_callable=AsyncMock,
                return_value=mock_lane_spec,
            ),
            patch(
                "campaigns.controller.compile_schemathesis_config",
                return_value="bad code",
            ),
            patch(
                "campaigns.controller.validate_harness",
                return_value=MagicMock(passed=False, errors=["Syntax error"]),
            ),
            patch(
                "campaigns.controller.lane_service.update_lane_spec_status",
                new_callable=AsyncMock,
                return_value=mock_lane_spec,
            ),
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=_make_campaign(status=CampaignStatus.FAILED),
            ) as mock_update_status,
            patch(
                "campaigns.controller.LocalFileStore",
            ) as MockStore,
        ):
            MockStore.return_value.put = MagicMock()

            result = await controller.compile_campaign("c1")

        # Campaign FAILED because all lanes retired
        mock_update_status.assert_called_once_with(
            "c1",
            CampaignStatus.FAILED.value,
            error_message="All lanes retired due to compilation failures",
        )
        assert result.status == CampaignStatus.FAILED

    @pytest.mark.asyncio
    async def test_compile_no_targets_fails(self):
        """No targets -> ValueError raised."""
        mock_campaign = _make_campaign(status=CampaignStatus.EXTRACTING)
        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.campaign_service.get_campaign_config",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "campaigns.controller.target_service.list_targets",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=_make_campaign(status=CampaignStatus.FAILED),
            ),
        ):
            with pytest.raises(ValueError, match="No targets found"):
                await controller.compile_campaign("c1")


# ===========================================================================
# CampaignController.start_campaign
# ===========================================================================


class TestStartCampaign:
    """Tests for CampaignController.start_campaign."""

    @pytest.mark.asyncio
    async def test_start_chains_plan_compile_execute(self):
        """start_campaign calls plan, compile, then execute."""
        controller = CampaignController()

        mock_plan_result = _make_campaign(status=CampaignStatus.EXTRACTING)
        mock_compile_result = _make_campaign(status=CampaignStatus.COMPILING)
        mock_execute_result = _make_campaign(status=CampaignStatus.RUNNING)

        with (
            patch.object(
                controller,
                "plan_campaign",
                new_callable=AsyncMock,
                return_value=mock_plan_result,
            ) as mock_plan,
            patch.object(
                controller,
                "compile_campaign",
                new_callable=AsyncMock,
                return_value=mock_compile_result,
            ) as mock_compile,
            patch.object(
                controller,
                "execute_campaign",
                new_callable=AsyncMock,
                return_value=mock_execute_result,
            ) as mock_execute,
        ):
            result = await controller.start_campaign("c1")

        mock_plan.assert_called_once_with("c1")
        mock_compile.assert_called_once_with("c1")
        mock_execute.assert_called_once_with("c1")
        assert result.status == CampaignStatus.RUNNING


# ===========================================================================
# CampaignController.execute_campaign
# ===========================================================================


class TestExecuteCampaign:
    """Tests for CampaignController.execute_campaign."""

    @pytest.mark.asyncio
    async def test_execute_creates_run_records(self):
        """execute_campaign creates a RunLane for each bundle and enqueues jobs."""
        mock_campaign = _make_campaign(status=CampaignStatus.COMPILING)
        bundle1 = _make_bundle(id="eb1", lane_spec_id="ls1")
        bundle2 = _make_bundle(id="eb2", lane_spec_id="ls2")
        running_campaign = _make_campaign(status=CampaignStatus.RUNNING)

        mock_run = MagicMock()
        mock_run.id = "run1"
        mock_run.timeout_seconds = 1800

        controller = CampaignController()

        # Mock get_session for env snapshot creation
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _mock_get_session():
            yield mock_session

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.execution_bundle_service.list_bundles",
                new_callable=AsyncMock,
                return_value=[bundle1, bundle2],
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=None,
            ),
            patch(
                "database.connection.get_session",
                _mock_get_session,
            ),
            patch(
                "campaigns.controller.run_lane_service.create_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ) as mock_create_run,
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=running_campaign,
            ) as mock_update_status,
            patch(
                "execution.workers.fuzz_worker_actor.run_lane",
            ) as mock_run_lane_actor,
        ):
            result = await controller.execute_campaign("c1")

        # A run was created for each bundle
        assert mock_create_run.call_count == 2
        call_kwargs_0 = mock_create_run.call_args_list[0].kwargs
        assert call_kwargs_0["lane_spec_id"] == "ls1"
        assert call_kwargs_0["execution_bundle_id"] == "eb1"

        call_kwargs_1 = mock_create_run.call_args_list[1].kwargs
        assert call_kwargs_1["lane_spec_id"] == "ls2"
        assert call_kwargs_1["execution_bundle_id"] == "eb2"

        # Dramatiq jobs were enqueued
        assert mock_run_lane_actor.send.call_count == 2

        # Campaign status transitioned to RUNNING (with started_at)
        mock_update_status.assert_called_once()
        call_args = mock_update_status.call_args
        assert call_args[0] == ("c1", CampaignStatus.RUNNING.value)
        assert "started_at" in call_args[1]
        assert result.status == CampaignStatus.RUNNING

    @pytest.mark.asyncio
    async def test_execute_transitions_to_running(self):
        """execute_campaign transitions campaign status to RUNNING."""
        mock_campaign = _make_campaign(status=CampaignStatus.COMPILING)
        bundle = _make_bundle(id="eb1", lane_spec_id="ls1")
        running_campaign = _make_campaign(status=CampaignStatus.RUNNING)

        mock_run = MagicMock()
        mock_run.id = "run1"
        mock_run.timeout_seconds = 1800

        controller = CampaignController()

        # Mock get_session for env snapshot creation
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _mock_get_session():
            yield mock_session

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.execution_bundle_service.list_bundles",
                new_callable=AsyncMock,
                return_value=[bundle],
            ),
            patch(
                "campaigns.controller.project_service.get_project_repo_path",
                return_value=None,
            ),
            patch(
                "database.connection.get_session",
                _mock_get_session,
            ),
            patch(
                "campaigns.controller.run_lane_service.create_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ),
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=running_campaign,
            ) as mock_update_status,
            patch(
                "execution.workers.fuzz_worker_actor.run_lane",
            ),
        ):
            result = await controller.execute_campaign("c1")

        mock_update_status.assert_called_once()
        call_args = mock_update_status.call_args
        assert call_args[0] == ("c1", CampaignStatus.RUNNING.value)
        assert "started_at" in call_args[1]
        assert result.status == CampaignStatus.RUNNING

    @pytest.mark.asyncio
    async def test_execute_no_bundles_fails(self):
        """execute_campaign with no bundles raises ValueError."""
        mock_campaign = _make_campaign(status=CampaignStatus.COMPILING)

        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=mock_campaign,
            ),
            patch(
                "campaigns.controller.execution_bundle_service.list_bundles",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "campaigns.controller.campaign_service.update_campaign_status",
                new_callable=AsyncMock,
                return_value=_make_campaign(status=CampaignStatus.FAILED),
            ) as mock_update_status,
            patch(
                "execution.workers.fuzz_worker_actor.run_lane",
            ),
        ):
            with pytest.raises(ValueError, match="No execution bundles found"):
                await controller.execute_campaign("c1")

        mock_update_status.assert_called_once_with(
            "c1",
            CampaignStatus.FAILED.value,
            error_message="No execution bundles found",
        )

    @pytest.mark.asyncio
    async def test_execute_missing_campaign_fails(self):
        """execute_campaign with non-existent campaign raises ValueError."""
        controller = CampaignController()

        with (
            patch(
                "campaigns.controller.campaign_service.get_campaign",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "execution.workers.fuzz_worker_actor.run_lane",
            ),
        ):
            with pytest.raises(ValueError, match="Campaign not found"):
                await controller.execute_campaign("nonexistent")
