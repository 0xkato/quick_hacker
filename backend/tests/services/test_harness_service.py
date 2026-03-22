"""Unit tests for HarnessService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.harness_service import HarnessService


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


def _make_db_harness(**overrides):
    """Build a minimal fake DBHarness-like object."""
    defaults = dict(
        id="harn0001",
        lane_spec_id="lane0001",
        revision=1,
        code_ref="harnesses/lane0001/v1.py",
        validation_results=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


_HARNESS_ATTRS = (
    "id", "lane_spec_id", "revision", "code_ref",
    "validation_results", "created_at",
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateHarness:
    @pytest.fixture()
    def service(self):
        return HarnessService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.harness_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_dict_with_correct_fields(self, service, session):
        """create_harness should return a dict with all expected keys."""
        db_harness = _make_db_harness()

        async def _refresh(obj):
            for attr in _HARNESS_ATTRS:
                setattr(obj, attr, getattr(db_harness, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_harness(
                lane_spec_id="lane0001",
                code_ref="harnesses/lane0001/v1.py",
            )

        assert isinstance(resp, dict)
        assert resp["lane_spec_id"] == "lane0001"
        assert resp["code_ref"] == "harnesses/lane0001/v1.py"
        assert resp["revision"] == 1
        assert "id" in resp
        assert "created_at" in resp


class TestGetHarness:
    @pytest.fixture()
    def service(self):
        return HarnessService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.harness_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_harness should return None when the harness does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_harness("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_dict_when_found(self, service, session):
        """get_harness should return a dict when found."""
        db_harness = _make_db_harness(id="harn0001")
        session.get.return_value = db_harness

        with self._patch_session(session):
            result = await service.get_harness("harn0001")

        assert isinstance(result, dict)
        assert result["id"] == "harn0001"


class TestGetLatestForLane:
    @pytest.fixture()
    def service(self):
        return HarnessService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.harness_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_empty(self, service, session):
        """get_latest_for_lane should return None when no harnesses exist."""
        scalars_mock = MagicMock()
        scalars_mock.first.return_value = None
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            result = await service.get_latest_for_lane("lane0001")

        assert result is None
