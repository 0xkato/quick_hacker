"""Unit tests for RunLaneService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.campaign_enums import ResourceProfile, RunLaneStatus
from models.campaign_schemas import RunLaneResponse
from services.run_lane_service import RunLaneService, _short_id


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


def _make_db_run(**overrides):
    """Build a minimal fake DBRunLane-like object."""
    defaults = dict(
        id="run00001",
        lane_spec_id="lane0001",
        execution_bundle_id="bndl0001",
        status="queued",
        started_at=None,
        completed_at=None,
        cpu_limit=1.0,
        memory_limit_mb=1024,
        disk_limit_mb=2048,
        timeout_seconds=1800,
        resource_profile="light",
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


_RUN_ATTRS = (
    "id", "lane_spec_id", "execution_bundle_id", "status",
    "started_at", "completed_at", "cpu_limit", "memory_limit_mb",
    "disk_limit_mb", "timeout_seconds", "resource_profile",
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateRun:
    @pytest.fixture()
    def service(self):
        return RunLaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.run_lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_run_lane_response(self, service, session):
        """create_run should return a RunLaneResponse with correct fields."""
        db_run = _make_db_run()

        async def _refresh(obj):
            for attr in _RUN_ATTRS:
                setattr(obj, attr, getattr(db_run, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_run(
                lane_spec_id="lane0001",
                execution_bundle_id="bndl0001",
            )

        assert isinstance(resp, RunLaneResponse)
        assert resp.lane_spec_id == "lane0001"
        assert resp.execution_bundle_id == "bndl0001"
        assert resp.status == RunLaneStatus.QUEUED
        assert resp.resource_profile == ResourceProfile.LIGHT
        assert resp.timeout_seconds == 1800
        assert resp.cpu_limit == 1.0
        assert resp.memory_limit_mb == 1024
        assert resp.disk_limit_mb == 2048

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The run lane id stored via session.add must be 8 hex chars."""
        db_run = _make_db_run()

        async def _refresh(obj):
            for attr in _RUN_ATTRS:
                if attr == "id":
                    continue
                setattr(obj, attr, getattr(db_run, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.create_run(
                lane_spec_id="lane0001",
                execution_bundle_id="bndl0001",
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestGetRun:
    @pytest.fixture()
    def service(self):
        return RunLaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.run_lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_run should return None when the run does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_run("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_run_lane_response(self, service, session):
        """get_run should return a RunLaneResponse when found."""
        db_run = _make_db_run(id="run00001")
        session.get.return_value = db_run

        with self._patch_session(session):
            result = await service.get_run("run00001")

        assert isinstance(result, RunLaneResponse)
        assert result.id == "run00001"


class TestListRuns:
    @pytest.fixture()
    def service(self):
        return RunLaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.run_lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list(self, service, session):
        """list_runs should return a list of RunLaneResponse objects."""
        db_r1 = _make_db_run(id="run00001")
        db_r2 = _make_db_run(id="run00002")
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_r1, db_r2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_runs("lane0001")

        assert len(results) == 2
        assert all(isinstance(r, RunLaneResponse) for r in results)

    @pytest.mark.asyncio
    async def test_returns_empty_list(self, service, session):
        """list_runs should return an empty list when no runs exist."""
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_runs("no_such_lane")

        assert results == []


class TestUpdateRunStatus:
    @pytest.fixture()
    def service(self):
        return RunLaneService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.run_lane_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, session):
        """update_run_status should return None for nonexistent run."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.update_run_status("nope", "running")

        assert result is None

    @pytest.mark.asyncio
    async def test_updates_status(self, service, session):
        """update_run_status should update and return the run lane."""
        now = datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc)
        db_run = _make_db_run(status="queued")
        session.get.return_value = db_run

        async def _refresh(obj):
            obj.status = "running"
            obj.started_at = now

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.update_run_status(
                "run00001", "running", started_at=now,
            )

        assert result is not None
        assert result.status == RunLaneStatus.RUNNING
        assert result.started_at == now
