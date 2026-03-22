"""Unit tests for ArtifactService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.campaign_enums import (
    ArtifactClassification,
    ArtifactType,
    AnalysisOutcome,
)
from models.campaign_schemas import ArtifactResponse
from services.artifact_service import ArtifactService, _short_id


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


_ARTIFACT_ATTRS = (
    "id", "run_lane_id", "type", "bucket_key", "artifact_classification",
    "analysis_outcome", "reproducible", "stability_score", "minimized",
    "replay_recipe", "evidence_refs", "created_at",
)


def _make_db_artifact(**overrides):
    """Build a minimal fake DBArtifact-like object."""
    defaults = dict(
        id="art00001",
        run_lane_id="run00001",
        type="crash",
        bucket_key="abcdef0123456789",
        artifact_classification="issue_candidate",
        analysis_outcome=None,
        reproducible=None,
        stability_score=None,
        minimized=False,
        replay_recipe=None,
        evidence_refs=None,
        created_at=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


def _make_db_bucket(**overrides):
    """Build a minimal fake DBArtifactBucket-like object."""
    defaults = dict(
        id="bkt00001",
        campaign_id="camp0001",
        bucket_key="abcdef0123456789",
        artifact_count=1,
        first_seen_at=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateArtifact:
    @pytest.fixture()
    def service(self):
        return ArtifactService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.artifact_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_artifact_response(self, service, session):
        """create_artifact should return an ArtifactResponse with correct fields."""
        db_art = _make_db_artifact()

        async def _refresh(obj):
            for attr in _ARTIFACT_ATTRS:
                setattr(obj, attr, getattr(db_art, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_artifact(
                run_lane_id="run00001",
                type="crash",
                bucket_key="abcdef0123456789",
            )

        assert isinstance(resp, ArtifactResponse)
        assert resp.run_lane_id == "run00001"
        assert resp.type == ArtifactType.CRASH
        assert resp.bucket_key == "abcdef0123456789"
        assert resp.artifact_classification == ArtifactClassification.ISSUE_CANDIDATE

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The artifact id stored via session.add must be 8 hex chars."""
        db_art = _make_db_artifact()

        async def _refresh(obj):
            for attr in _ARTIFACT_ATTRS:
                if attr == "id":
                    continue
                setattr(obj, attr, getattr(db_art, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.create_artifact(
                run_lane_id="run00001",
                type="crash",
                bucket_key="abcdef0123456789",
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestGetArtifact:
    @pytest.fixture()
    def service(self):
        return ArtifactService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.artifact_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_artifact should return None when the artifact does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_artifact("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_artifact_response(self, service, session):
        """get_artifact should return an ArtifactResponse when found."""
        db_art = _make_db_artifact(id="art00001")
        session.get.return_value = db_art

        with self._patch_session(session):
            result = await service.get_artifact("art00001")

        assert isinstance(result, ArtifactResponse)
        assert result.id == "art00001"


class TestUpdateClassification:
    @pytest.fixture()
    def service(self):
        return ArtifactService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.artifact_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, service, session):
        """update_classification should return None for nonexistent artifact."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.update_classification("nope", "harness_artifact")

        assert result is None

    @pytest.mark.asyncio
    async def test_updates_classification(self, service, session):
        """update_classification should update and return the artifact."""
        db_art = _make_db_artifact(artifact_classification="issue_candidate")
        session.get.return_value = db_art

        async def _refresh(obj):
            obj.artifact_classification = "harness_artifact"
            obj.analysis_outcome = "by_design"

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.update_classification(
                "art00001", "harness_artifact", analysis_outcome="by_design",
            )

        assert result is not None
        assert result.artifact_classification == ArtifactClassification.HARNESS_ARTIFACT
        assert result.analysis_outcome == AnalysisOutcome.BY_DESIGN


class TestCreateOrUpdateBucket:
    @pytest.fixture()
    def service(self):
        return ArtifactService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.artifact_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_creates_new_bucket(self, service, session):
        """create_or_update_bucket should create a new bucket when none exists."""
        # No existing bucket
        scalars_mock = MagicMock()
        scalars_mock.first.return_value = None
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        db_bucket = _make_db_bucket(artifact_count=1)

        async def _refresh(obj):
            for attr in ("id", "campaign_id", "bucket_key", "artifact_count",
                         "first_seen_at", "last_seen_at"):
                setattr(obj, attr, getattr(db_bucket, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.create_or_update_bucket(
                campaign_id="camp0001",
                bucket_key="abcdef0123456789",
                artifact_type="crash",
            )

        assert result["campaign_id"] == "camp0001"
        assert result["bucket_key"] == "abcdef0123456789"
        assert result["artifact_count"] == 1
        session.add.assert_called_once()


class TestListBuckets:
    @pytest.fixture()
    def service(self):
        return ArtifactService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.artifact_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list_of_dicts(self, service, session):
        """list_buckets should return a list of bucket dicts."""
        db_b1 = _make_db_bucket(id="bkt00001", bucket_key="key1")
        db_b2 = _make_db_bucket(id="bkt00002", bucket_key="key2")
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_b1, db_b2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_buckets("camp0001")

        assert len(results) == 2
        assert results[0]["bucket_key"] == "key1"
        assert results[1]["bucket_key"] == "key2"
