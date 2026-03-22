"""Unit tests for ExecutionBundleService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.campaign_schemas import ExecutionBundleResponse
from services.execution_bundle_service import ExecutionBundleService, _short_id


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


_BUNDLE_ATTRS = (
    "id", "campaign_id", "campaign_plan_revision",
    "lane_spec_id", "lane_spec_revision",
    "harness_id", "harness_revision",
    "oracle_pack_id", "oracle_pack_revision",
    "seed_set_id", "dictionary_id", "mutator_id",
    "build_artifact_ref", "env_snapshot_id", "created_at",
)


def _make_db_bundle(**overrides):
    """Build a minimal fake DBExecutionBundle-like object."""
    defaults = dict(
        id="bndl0001",
        campaign_id="camp0001",
        campaign_plan_revision=1,
        lane_spec_id="lane0001",
        lane_spec_revision=2,
        harness_id="harn0001",
        harness_revision=3,
        oracle_pack_id="orac0001",
        oracle_pack_revision=1,
        seed_set_id=None,
        dictionary_id=None,
        mutator_id=None,
        build_artifact_ref=None,
        env_snapshot_id=None,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateBundle:
    @pytest.fixture()
    def service(self):
        return ExecutionBundleService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.execution_bundle_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_response_with_all_revisions(self, service, session):
        """create_bundle should return an ExecutionBundleResponse with all revision fields populated."""
        db_bundle = _make_db_bundle()

        async def _refresh(obj):
            for attr in _BUNDLE_ATTRS:
                setattr(obj, attr, getattr(db_bundle, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_bundle(
                campaign_id="camp0001",
                campaign_plan_revision=1,
                lane_spec_id="lane0001",
                lane_spec_revision=2,
                harness_id="harn0001",
                harness_revision=3,
                oracle_pack_id="orac0001",
                oracle_pack_revision=1,
            )

        assert isinstance(resp, ExecutionBundleResponse)
        assert resp.campaign_id == "camp0001"
        assert resp.campaign_plan_revision == 1
        assert resp.lane_spec_id == "lane0001"
        assert resp.lane_spec_revision == 2
        assert resp.harness_id == "harn0001"
        assert resp.harness_revision == 3
        assert resp.oracle_pack_id == "orac0001"
        assert resp.oracle_pack_revision == 1

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The bundle id stored via session.add must be 8 hex chars."""
        db_bundle = _make_db_bundle()

        async def _refresh(obj):
            for attr in _BUNDLE_ATTRS:
                if attr == "id":
                    continue  # preserve the real generated id
                setattr(obj, attr, getattr(db_bundle, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.create_bundle(
                campaign_id="camp0001",
                campaign_plan_revision=1,
                lane_spec_id="lane0001",
                lane_spec_revision=2,
                harness_id="harn0001",
                harness_revision=3,
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestGetBundle:
    @pytest.fixture()
    def service(self):
        return ExecutionBundleService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.execution_bundle_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_bundle should return None when the bundle does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_bundle("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_bundle_response(self, service, session):
        """get_bundle should return an ExecutionBundleResponse when found."""
        db_bundle = _make_db_bundle(id="bndl0001")
        session.get.return_value = db_bundle

        with self._patch_session(session):
            result = await service.get_bundle("bndl0001")

        assert isinstance(result, ExecutionBundleResponse)
        assert result.id == "bndl0001"


class TestListBundles:
    @pytest.fixture()
    def service(self):
        return ExecutionBundleService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.execution_bundle_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list_filtered_by_campaign(self, service, session):
        """list_bundles should return a list of ExecutionBundleResponse objects."""
        db_b1 = _make_db_bundle(id="aaaa1111", campaign_id="camp0001")
        db_b2 = _make_db_bundle(id="bbbb2222", campaign_id="camp0001")
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_b1, db_b2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_bundles("camp0001")

        assert len(results) == 2
        assert all(isinstance(r, ExecutionBundleResponse) for r in results)
        assert all(r.campaign_id == "camp0001" for r in results)

    @pytest.mark.asyncio
    async def test_returns_empty_list(self, service, session):
        """list_bundles should return an empty list when no bundles exist."""
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_bundles("no_such_campaign")

        assert results == []


class TestShortId:
    def test_length_is_8(self):
        """_short_id should return an 8-character string."""
        sid = _short_id()
        assert len(sid) == 8

    def test_is_valid_hex(self):
        """_short_id should return valid hex characters."""
        sid = _short_id()
        int(sid, 16)  # raises ValueError if not valid hex
