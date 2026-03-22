"""Unit tests for SteeringService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.steering_service import SteeringService, _short_id


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


_DECISION_ATTRS = (
    "id", "campaign_id", "triggering_metrics", "decision",
    "expected_effect", "actual_effect", "created_at",
)


def _make_db_decision(**overrides):
    """Build a minimal fake DBSteeringDecision-like object."""
    defaults = dict(
        id="steer001",
        campaign_id="camp0001",
        triggering_metrics={"snapshot_count": 5, "window_seconds": 300},
        decision={
            "decision_type": "plateau_recovery",
            "recommendation": "Inject new seeds or increase mutation rate",
            "affected_lane_ids": ["lane1", "lane2"],
        },
        expected_effect="Inject new seeds or increase mutation rate",
        actual_effect=None,
        created_at=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRecordDecision:
    @pytest.fixture()
    def service(self):
        return SteeringService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.steering_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_dict_with_expected_keys(self, service, session):
        """record_decision should return a dict with all expected fields."""
        db_dec = _make_db_decision()

        async def _refresh(obj):
            for attr in _DECISION_ATTRS:
                setattr(obj, attr, getattr(db_dec, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.record_decision(
                campaign_id="camp0001",
                decision_type="plateau_recovery",
                triggering_metrics={"snapshot_count": 5},
                recommendation="Inject new seeds or increase mutation rate",
                affected_lane_ids=["lane1", "lane2"],
            )

        assert isinstance(result, dict)
        assert result["campaign_id"] == "camp0001"
        assert result["decision_type"] == "plateau_recovery"
        assert result["recommendation"] == "Inject new seeds or increase mutation rate"
        assert result["affected_lane_ids"] == ["lane1", "lane2"]
        assert "id" in result
        assert "created_at" in result

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The decision id stored via session.add must be 8 hex chars."""
        db_dec = _make_db_decision()

        async def _refresh(obj):
            for attr in _DECISION_ATTRS:
                if attr == "id":
                    continue
                setattr(obj, attr, getattr(db_dec, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.record_decision(
                campaign_id="camp0001",
                decision_type="plateau_recovery",
                triggering_metrics={},
                recommendation="test",
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestListDecisions:
    @pytest.fixture()
    def service(self):
        return SteeringService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.steering_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list_of_dicts(self, service, session):
        """list_decisions should return a list of decision dicts."""
        db_d1 = _make_db_decision(id="steer001")
        db_d2 = _make_db_decision(id="steer002", decision={
            "decision_type": "validity_fix",
            "recommendation": "Refine schema constraints",
            "affected_lane_ids": ["lane3"],
        })
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_d1, db_d2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_decisions("camp0001")

        assert len(results) == 2
        assert all(isinstance(r, dict) for r in results)
        assert results[0]["id"] == "steer001"
        assert results[1]["id"] == "steer002"

    @pytest.mark.asyncio
    async def test_returns_empty_list(self, service, session):
        """list_decisions should return [] when no decisions exist."""
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_decisions("camp0001")

        assert results == []


class TestGetLatestDecision:
    @pytest.fixture()
    def service(self):
        return SteeringService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.steering_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_empty(self, service, session):
        """get_latest_decision should return None when no decisions exist."""
        scalars_mock = MagicMock()
        scalars_mock.first.return_value = None
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            result = await service.get_latest_decision("camp0001")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_latest_decision(self, service, session):
        """get_latest_decision should return the most recent decision dict."""
        db_dec = _make_db_decision(id="steer005")
        scalars_mock = MagicMock()
        scalars_mock.first.return_value = db_dec
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            result = await service.get_latest_decision("camp0001")

        assert result is not None
        assert result["id"] == "steer005"
        assert result["campaign_id"] == "camp0001"
        assert result["decision_type"] == "plateau_recovery"
