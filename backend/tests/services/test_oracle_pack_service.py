"""Unit tests for OraclePackService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.oracle_pack_service import OraclePackService


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


def _make_db_oracle_pack(**overrides):
    """Build a minimal fake DBOraclePack-like object."""
    defaults = dict(
        id="orac0001",
        lane_spec_id="lane0001",
        revision=1,
        config={"oracles": ["status_code", "response_schema"]},
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


_ORACLE_ATTRS = ("id", "lane_spec_id", "revision", "config", "created_at")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateOraclePack:
    @pytest.fixture()
    def service(self):
        return OraclePackService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.oracle_pack_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_dict_with_correct_fields(self, service, session):
        """create_oracle_pack should return a dict with all expected keys."""
        db_pack = _make_db_oracle_pack()

        async def _refresh(obj):
            for attr in _ORACLE_ATTRS:
                setattr(obj, attr, getattr(db_pack, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_oracle_pack(
                lane_spec_id="lane0001",
                config={"oracles": ["status_code", "response_schema"]},
            )

        assert isinstance(resp, dict)
        assert resp["lane_spec_id"] == "lane0001"
        assert resp["config"] == {"oracles": ["status_code", "response_schema"]}
        assert resp["revision"] == 1
        assert "id" in resp
        assert "created_at" in resp


class TestGetOraclePack:
    @pytest.fixture()
    def service(self):
        return OraclePackService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.oracle_pack_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_oracle_pack should return None when the pack does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_oracle_pack("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_dict_when_found(self, service, session):
        """get_oracle_pack should return a dict when found."""
        db_pack = _make_db_oracle_pack(id="orac0001")
        session.get.return_value = db_pack

        with self._patch_session(session):
            result = await service.get_oracle_pack("orac0001")

        assert isinstance(result, dict)
        assert result["id"] == "orac0001"
        assert result["config"] == {"oracles": ["status_code", "response_schema"]}
