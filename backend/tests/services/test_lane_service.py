"""Unit tests for LaneService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.campaign_enums import (
    FeedbackModel,
    InputProducer,
    LaneSpecStatus,
    StructureModel,
)
from models.campaign_schemas import LaneSpecResponse
from services.lane_service import LaneService, _short_id


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


def _make_db_lane(**overrides):
    """Build a minimal fake DBLaneSpec-like object."""
    defaults = dict(
        id="lane0001",
        target_id="tgt00001",
        revision=1,
        structure_model="schema",
        input_producer="mutation",
        feedback_models=["api_surface"],
        oracle_packs=["status_code"],
        engine="schemathesis",
        budget_seconds=300,
        seed_sources=None,
        status="planned",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


_LANE_ATTRS = (
    "id", "target_id", "revision", "structure_model", "input_producer",
    "feedback_models", "oracle_packs", "engine", "budget_seconds",
    "seed_sources", "status", "created_at",
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateLaneSpec:
    @pytest.fixture()
    def service(self):
        return LaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_lane_spec_response(self, service, session):
        """create_lane_spec should return a LaneSpecResponse with correct fields."""
        db_lane = _make_db_lane()

        async def _refresh(obj):
            for attr in _LANE_ATTRS:
                setattr(obj, attr, getattr(db_lane, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_lane_spec(
                target_id="tgt00001",
                engine="schemathesis",
                structure_model="schema",
                input_producer="mutation",
                feedback_models=["api_surface"],
                oracle_packs=["status_code"],
                budget_seconds=300,
            )

        assert isinstance(resp, LaneSpecResponse)
        assert resp.target_id == "tgt00001"
        assert resp.engine == "schemathesis"
        assert resp.structure_model == StructureModel.SCHEMA
        assert resp.input_producer == InputProducer.MUTATION
        assert resp.feedback_models == [FeedbackModel.API_SURFACE]
        assert resp.status == LaneSpecStatus.PLANNED

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The lane spec id stored via session.add must be 8 hex chars."""
        db_lane = _make_db_lane()

        async def _refresh(obj):
            # Skip 'id' so the original generated hex id is preserved
            for attr in _LANE_ATTRS:
                if attr == "id":
                    continue
                setattr(obj, attr, getattr(db_lane, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.create_lane_spec(
                target_id="tgt00001",
                engine="schemathesis",
                structure_model="schema",
                input_producer="mutation",
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestCreateLaneSpecsBatch:
    @pytest.fixture()
    def service(self):
        return LaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list_with_correct_count(self, service, session):
        """create_lane_specs_batch should return a list matching input count."""
        db_l1 = _make_db_lane(id="llll1111", engine="schemathesis")
        db_l2 = _make_db_lane(id="llll2222", engine="schemathesis")
        fake_lanes = [db_l1, db_l2]

        refresh_call_count = 0

        async def _refresh(obj):
            nonlocal refresh_call_count
            fake = fake_lanes[refresh_call_count]
            for attr in _LANE_ATTRS:
                setattr(obj, attr, getattr(fake, attr))
            refresh_call_count += 1

        session.refresh.side_effect = _refresh

        specs_input = [
            {
                "target_id": "tgt00001",
                "engine": "schemathesis",
                "structure_model": "schema",
                "input_producer": "mutation",
                "feedback_models": ["api_surface"],
                "oracle_packs": ["status_code"],
            },
            {
                "target_id": "tgt00001",
                "engine": "schemathesis",
                "structure_model": "raw",
                "input_producer": "generation",
                "feedback_models": ["directed"],
                "oracle_packs": ["crash"],
            },
        ]

        with self._patch_session(session):
            results = await service.create_lane_specs_batch("tgt00001", specs_input)

        assert len(results) == 2
        assert all(isinstance(r, LaneSpecResponse) for r in results)


class TestGetLaneSpec:
    @pytest.fixture()
    def service(self):
        return LaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_lane_spec should return None when the lane spec does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_lane_spec("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_lane_spec_response(self, service, session):
        """get_lane_spec should return a LaneSpecResponse when found."""
        db_lane = _make_db_lane(id="lane0001")
        session.get.return_value = db_lane

        with self._patch_session(session):
            result = await service.get_lane_spec("lane0001")

        assert isinstance(result, LaneSpecResponse)
        assert result.id == "lane0001"


class TestListLaneSpecs:
    @pytest.fixture()
    def service(self):
        return LaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list(self, service, session):
        """list_lane_specs should return a list of LaneSpecResponse objects."""
        db_l1 = _make_db_lane(id="llll1111")
        db_l2 = _make_db_lane(id="llll2222")
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_l1, db_l2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_lane_specs(target_id="tgt00001")

        assert len(results) == 2
        assert all(isinstance(r, LaneSpecResponse) for r in results)

    @pytest.mark.asyncio
    async def test_returns_empty_list(self, service, session):
        """list_lane_specs should return an empty list when no specs exist."""
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_lane_specs(target_id="no_such_target")

        assert results == []


class TestUpdateLaneSpecStatus:
    @pytest.fixture()
    def service(self):
        return LaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, session):
        """update_lane_spec_status should return None for nonexistent spec."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.update_lane_spec_status("nope", "compiled")

        assert result is None

    @pytest.mark.asyncio
    async def test_updates_status(self, service, session):
        """update_lane_spec_status should update and return the lane spec."""
        db_lane = _make_db_lane(status="planned")
        session.get.return_value = db_lane

        async def _refresh(obj):
            obj.status = "compiled"

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.update_lane_spec_status("lane0001", "compiled")

        assert result is not None
        assert result.status == LaneSpecStatus.COMPILED
