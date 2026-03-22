"""Unit tests for TargetService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.campaign_enums import TargetKind
from models.campaign_schemas import TargetResponse
from services.target_service import TargetService, _short_id


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


def _make_db_target(**overrides):
    """Build a minimal fake DBTarget-like object."""
    defaults = dict(
        id="abcd1234",
        campaign_id="camp0001",
        kind="api_route",
        entrypoint="/api/v1/users",
        language="python",
        schemas=None,
        stateful=False,
        actors=None,
        reset_strategy=None,
        priority_score=0.0,
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


class TestCreateTarget:
    @pytest.fixture()
    def service(self):
        return TargetService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.target_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_target_response(self, service, session):
        """create_target should return a TargetResponse with correct fields."""
        db_target = _make_db_target()

        async def _refresh(obj):
            for attr in (
                "id", "campaign_id", "kind", "entrypoint", "language",
                "schemas", "stateful", "actors", "reset_strategy",
                "priority_score", "created_at",
            ):
                setattr(obj, attr, getattr(db_target, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_target(
                campaign_id="camp0001",
                kind="api_route",
                entrypoint="/api/v1/users",
                language="python",
            )

        assert isinstance(resp, TargetResponse)
        assert resp.campaign_id == "camp0001"
        assert resp.kind == TargetKind.API_ROUTE
        assert resp.entrypoint == "/api/v1/users"
        assert resp.language == "python"

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The target id stored via session.add must be 8 hex chars."""
        db_target = _make_db_target()

        async def _refresh(obj):
            for attr in (
                "id", "campaign_id", "kind", "entrypoint", "language",
                "schemas", "stateful", "actors", "reset_strategy",
                "priority_score", "created_at",
            ):
                setattr(obj, attr, getattr(db_target, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.create_target(
                campaign_id="camp0001",
                kind="api_route",
                entrypoint="/api/v1/users",
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestCreateTargetsBatch:
    @pytest.fixture()
    def service(self):
        return TargetService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.target_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list_with_correct_count(self, service, session):
        """create_targets_batch should return a list matching input count."""
        db_t1 = _make_db_target(id="aaaa1111", entrypoint="/api/v1/a")
        db_t2 = _make_db_target(id="bbbb2222", entrypoint="/api/v1/b")
        db_t3 = _make_db_target(id="cccc3333", entrypoint="/api/v1/c")
        fake_targets = [db_t1, db_t2, db_t3]

        refresh_call_count = 0

        async def _refresh(obj):
            nonlocal refresh_call_count
            fake = fake_targets[refresh_call_count]
            for attr in (
                "id", "campaign_id", "kind", "entrypoint", "language",
                "schemas", "stateful", "actors", "reset_strategy",
                "priority_score", "created_at",
            ):
                setattr(obj, attr, getattr(fake, attr))
            refresh_call_count += 1

        session.refresh.side_effect = _refresh

        targets_input = [
            {"kind": "api_route", "entrypoint": "/api/v1/a"},
            {"kind": "api_route", "entrypoint": "/api/v1/b"},
            {"kind": "parser", "entrypoint": "/api/v1/c"},
        ]

        with self._patch_session(session):
            results = await service.create_targets_batch("camp0001", targets_input)

        assert len(results) == 3
        assert all(isinstance(r, TargetResponse) for r in results)


class TestGetTarget:
    @pytest.fixture()
    def service(self):
        return TargetService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.target_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_target should return None when the target does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_target("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_target_response(self, service, session):
        """get_target should return a TargetResponse when found."""
        db_target = _make_db_target(id="abcd1234")
        session.get.return_value = db_target

        with self._patch_session(session):
            result = await service.get_target("abcd1234")

        assert isinstance(result, TargetResponse)
        assert result.id == "abcd1234"


class TestListTargets:
    @pytest.fixture()
    def service(self):
        return TargetService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.target_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list(self, service, session):
        """list_targets should return a list of TargetResponse objects."""
        db_t1 = _make_db_target(id="aaaa1111")
        db_t2 = _make_db_target(id="bbbb2222")
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_t1, db_t2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_targets("camp0001")

        assert len(results) == 2
        assert all(isinstance(r, TargetResponse) for r in results)

    @pytest.mark.asyncio
    async def test_returns_empty_list(self, service, session):
        """list_targets should return an empty list when no targets exist."""
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_targets("no_such_campaign")

        assert results == []


class TestUpdateTargetPriority:
    @pytest.fixture()
    def service(self):
        return TargetService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.target_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, session):
        """update_target_priority should return None for nonexistent target."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.update_target_priority("nope", 0.95)

        assert result is None

    @pytest.mark.asyncio
    async def test_updates_priority(self, service, session):
        """update_target_priority should update and return the target."""
        db_target = _make_db_target(priority_score=0.5)
        session.get.return_value = db_target

        async def _refresh(obj):
            obj.priority_score = 0.95

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.update_target_priority("abcd1234", 0.95)

        assert result is not None
        assert result.priority_score == 0.95
