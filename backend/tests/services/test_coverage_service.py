"""Unit tests for CoverageService operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.coverage_service import CoverageService, _short_id


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


_SAMPLE_SNAPSHOT_DATA = {
    "operations_hit": 12,
    "parameters_exercised": 45,
    "status_classes_seen": ["2xx", "4xx", "5xx"],
    "sequence_depth": 3,
    "validity_ratio": 0.78,
    "requests_per_sec": 42.5,
}


def _make_db_snapshot(**overrides):
    """Build a minimal fake DBCoverageSnapshot-like object."""
    defaults = dict(
        id="snap0001",
        run_lane_id="run00001",
        snapshot_data=_SAMPLE_SNAPSHOT_DATA,
        created_at=datetime(2026, 3, 22, 10, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


_SNAP_ATTRS = ("id", "run_lane_id", "snapshot_data", "created_at")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRecordSnapshot:
    @pytest.fixture()
    def service(self):
        return CoverageService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.coverage_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_dict_with_expected_keys(self, service, session):
        """record_snapshot should return a dict with id, run_lane_id, snapshot_data, created_at."""
        db_snap = _make_db_snapshot()

        async def _refresh(obj):
            for attr in _SNAP_ATTRS:
                setattr(obj, attr, getattr(db_snap, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.record_snapshot(
                run_lane_id="run00001",
                snapshot_data=_SAMPLE_SNAPSHOT_DATA,
            )

        assert isinstance(result, dict)
        assert result["run_lane_id"] == "run00001"
        assert result["snapshot_data"] == _SAMPLE_SNAPSHOT_DATA
        assert "id" in result
        assert "created_at" in result

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The snapshot id stored via session.add must be 8 hex chars."""
        db_snap = _make_db_snapshot()

        async def _refresh(obj):
            for attr in _SNAP_ATTRS:
                if attr == "id":
                    continue
                setattr(obj, attr, getattr(db_snap, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.record_snapshot(
                run_lane_id="run00001",
                snapshot_data=_SAMPLE_SNAPSHOT_DATA,
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestGetLaneCoverage:
    @pytest.fixture()
    def service(self):
        return CoverageService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.coverage_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list_of_dicts(self, service, session):
        """get_lane_coverage should return a list of snapshot dicts."""
        db_s1 = _make_db_snapshot(id="snap0001")
        db_s2 = _make_db_snapshot(id="snap0002")
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_s1, db_s2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.get_lane_coverage("run00001")

        assert len(results) == 2
        assert all(isinstance(r, dict) for r in results)
        assert results[0]["id"] == "snap0001"
        assert results[1]["id"] == "snap0002"

    @pytest.mark.asyncio
    async def test_returns_empty_list(self, service, session):
        """get_lane_coverage should return an empty list when no snapshots exist."""
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.get_lane_coverage("no_such_run")

        assert results == []


class TestGetCampaignCoverageSummary:
    @pytest.fixture()
    def service(self):
        return CoverageService()

    @pytest.mark.asyncio
    async def test_returns_empty_dict_placeholder(self, service):
        """v1 placeholder should return an empty dict."""
        result = await service.get_campaign_coverage_summary("camp0001")

        assert result == {}
        assert isinstance(result, dict)
