"""Unit tests for CampaignService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.campaign_enums import CampaignPreset, CampaignStatus
from models.campaign_schemas import CampaignCreateRequest, CampaignResponse
from services.campaign_service import (
    PRESET_BUDGETS,
    CampaignService,
    _short_id,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session_mock():
    """Return an AsyncMock that behaves like an async context-managed session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.execute = AsyncMock()
    return session


def _fake_get_session(session_mock):
    """Return an async context manager that yields *session_mock*."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _ctx():
        yield session_mock

    return _ctx


def _make_db_campaign(**overrides):
    """Build a minimal fake DBCampaign-like object."""
    defaults = dict(
        id="abcd1234",
        repo_id="repo_1",
        status="created",
        preset="quick",
        budget_seconds=600,
        max_parallel_lanes=2,
        lm_provider="claude_cli",
        lm_model="claude-opus-4-6",
        config=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        started_at=None,
        completed_at=None,
        error_message=None,
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestShortId:
    def test_length_is_8(self):
        sid = _short_id()
        assert len(sid) == 8

    def test_is_hex(self):
        sid = _short_id()
        int(sid, 16)  # will raise if not valid hex

    def test_unique(self):
        ids = {_short_id() for _ in range(100)}
        assert len(ids) == 100


class TestCreateCampaign:
    @pytest.fixture()
    def service(self):
        return CampaignService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.campaign_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_campaign_response(self, service, session):
        """create_campaign should return a CampaignResponse."""
        db_camp = _make_db_campaign()

        # After session.refresh, the mock's attributes are what _db_to_response reads.
        async def _refresh(obj):
            for attr in ("id", "repo_id", "status", "preset", "budget_seconds",
                         "max_parallel_lanes", "lm_provider", "lm_model",
                         "created_at", "started_at", "completed_at", "error_message"):
                setattr(obj, attr, getattr(db_camp, attr))

        session.refresh.side_effect = _refresh

        req = CampaignCreateRequest(repo_id="repo_1")

        with self._patch_session(session):
            resp = await service.create_campaign(req)

        assert isinstance(resp, CampaignResponse)
        assert resp.repo_id == "repo_1"
        assert resp.status == CampaignStatus.CREATED

    @pytest.mark.asyncio
    async def test_resolves_budget_from_preset(self, service, session):
        """When budget_seconds is None, the preset determines the budget."""
        db_camp = _make_db_campaign(preset="advanced", budget_seconds=7200)

        async def _refresh(obj):
            for attr in ("id", "repo_id", "status", "preset", "budget_seconds",
                         "max_parallel_lanes", "lm_provider", "lm_model",
                         "created_at", "started_at", "completed_at", "error_message"):
                setattr(obj, attr, getattr(db_camp, attr))

        session.refresh.side_effect = _refresh

        req = CampaignCreateRequest(repo_id="repo_1", campaign_preset="advanced")

        with self._patch_session(session):
            resp = await service.create_campaign(req)

        assert resp.budget_seconds == PRESET_BUDGETS["advanced"]

    @pytest.mark.asyncio
    async def test_budget_override(self, service, session):
        """Explicit budget_seconds on the request takes precedence."""
        db_camp = _make_db_campaign(budget_seconds=9999)

        async def _refresh(obj):
            for attr in ("id", "repo_id", "status", "preset", "budget_seconds",
                         "max_parallel_lanes", "lm_provider", "lm_model",
                         "created_at", "started_at", "completed_at", "error_message"):
                setattr(obj, attr, getattr(db_camp, attr))

        session.refresh.side_effect = _refresh

        req = CampaignCreateRequest(repo_id="repo_1", budget_seconds=9999)

        with self._patch_session(session):
            resp = await service.create_campaign(req)

        assert resp.budget_seconds == 9999

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The campaign id stored via session.add must be 8 hex chars."""
        db_camp = _make_db_campaign()

        async def _refresh(obj):
            for attr in ("id", "repo_id", "status", "preset", "budget_seconds",
                         "max_parallel_lanes", "lm_provider", "lm_model",
                         "created_at", "started_at", "completed_at", "error_message"):
                setattr(obj, attr, getattr(db_camp, attr))

        session.refresh.side_effect = _refresh

        req = CampaignCreateRequest(repo_id="repo_1")

        with self._patch_session(session):
            await service.create_campaign(req)

        # session.add was called with a DBCampaign whose id is 8 hex chars
        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestGetCampaign:
    @pytest.fixture()
    def service(self):
        return CampaignService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.campaign_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, session):
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_campaign("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_campaign_response(self, service, session):
        db_camp = _make_db_campaign(id="abcd1234")
        session.get.return_value = db_camp

        with self._patch_session(session):
            result = await service.get_campaign("abcd1234")

        assert isinstance(result, CampaignResponse)
        assert result.id == "abcd1234"


class TestListCampaigns:
    @pytest.fixture()
    def service(self):
        return CampaignService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.campaign_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list(self, service, session):
        db_camp = _make_db_campaign()
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_camp]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_campaigns()

        assert len(results) == 1
        assert isinstance(results[0], CampaignResponse)

    @pytest.mark.asyncio
    async def test_empty_list(self, service, session):
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_campaigns(repo_id="no_such_repo")

        assert results == []


class TestUpdateCampaignStatus:
    @pytest.fixture()
    def service(self):
        return CampaignService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.campaign_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, session):
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.update_campaign_status("nope", "running")

        assert result is None

    @pytest.mark.asyncio
    async def test_updates_status(self, service, session):
        db_camp = _make_db_campaign(status="created")
        session.get.return_value = db_camp

        async def _refresh(obj):
            obj.status = "running"

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.update_campaign_status("abcd1234", "running")

        assert result is not None
        assert result.status == CampaignStatus.RUNNING

    @pytest.mark.asyncio
    async def test_updates_optional_fields(self, service, session):
        ts = datetime(2026, 3, 1, tzinfo=timezone.utc)
        db_camp = _make_db_campaign(status="created")
        session.get.return_value = db_camp

        async def _refresh(obj):
            obj.status = "failed"
            # kwargs should have been applied before refresh
            pass

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.update_campaign_status(
                "abcd1234",
                "failed",
                started_at=ts,
                error_message="boom",
            )

        # Verify the kwargs were applied to the row object
        assert db_camp.started_at == ts
        assert db_camp.error_message == "boom"
