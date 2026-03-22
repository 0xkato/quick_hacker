"""Unit tests for the artifact bucketer.

Tests cover bucket-key computation, replay decisions, and the
process_raw_artifact integration pipeline.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from evidence.bucketer import compute_bucket_key, should_replay, process_raw_artifact


# ---------------------------------------------------------------------------
# compute_bucket_key
# ---------------------------------------------------------------------------


class TestComputeBucketKey:
    def test_same_endpoint_and_error_produce_same_key(self):
        """Identical endpoint + error_type + status_code -> same bucket key."""
        c1 = {"endpoint": "/api/users", "error_type": "500", "status_code": 500}
        c2 = {"endpoint": "/api/users", "error_type": "500", "status_code": 500}
        assert compute_bucket_key(c1) == compute_bucket_key(c2)

    def test_different_endpoints_produce_different_keys(self):
        """Different endpoints should produce different bucket keys."""
        c1 = {"endpoint": "/api/users", "error_type": "500", "status_code": 500}
        c2 = {"endpoint": "/api/orders", "error_type": "500", "status_code": 500}
        assert compute_bucket_key(c1) != compute_bucket_key(c2)

    def test_different_error_types_produce_different_keys(self):
        """Different error types on the same endpoint -> different keys."""
        c1 = {"endpoint": "/api/users", "error_type": "timeout", "status_code": 504}
        c2 = {"endpoint": "/api/users", "error_type": "crash", "status_code": 500}
        assert compute_bucket_key(c1) != compute_bucket_key(c2)

    def test_key_is_16_hex_chars(self):
        """Bucket key should be a 16-character hex string."""
        key = compute_bucket_key({"endpoint": "/test", "error_type": "err"})
        assert len(key) == 16
        int(key, 16)  # valid hex

    def test_missing_fields_use_defaults(self):
        """Missing fields should fall back to defaults without crashing."""
        key = compute_bucket_key({})
        assert len(key) == 16
        int(key, 16)


# ---------------------------------------------------------------------------
# should_replay
# ---------------------------------------------------------------------------


class TestShouldReplay:
    def test_new_bucket_returns_true(self):
        """A new bucket (None) should trigger replay."""
        assert should_replay("somekey", None) is True

    def test_bucket_with_fewer_than_3_returns_true(self):
        """A bucket with < 3 artifacts should still trigger replay."""
        assert should_replay("somekey", {"artifact_count": 1}) is True
        assert should_replay("somekey", {"artifact_count": 2}) is True

    def test_bucket_with_3_or_more_returns_false(self):
        """A bucket with 3+ artifacts should NOT trigger replay."""
        assert should_replay("somekey", {"artifact_count": 3}) is False
        assert should_replay("somekey", {"artifact_count": 10}) is False


# ---------------------------------------------------------------------------
# process_raw_artifact
# ---------------------------------------------------------------------------


class TestProcessRawArtifact:
    @pytest.fixture()
    def artifact_service(self):
        svc = AsyncMock()
        svc.create_or_update_bucket = AsyncMock(return_value={
            "id": "bkt00001",
            "campaign_id": "camp0001",
            "bucket_key": "abcdef0123456789",
            "artifact_count": 1,
            "first_seen_at": "2026-03-22T12:00:00+00:00",
            "last_seen_at": "2026-03-22T12:00:00+00:00",
        })
        art_response = MagicMock()
        art_response.id = "art00001"
        svc.create_artifact = AsyncMock(return_value=art_response)
        return svc

    @pytest.fixture()
    def object_store(self):
        store = AsyncMock()
        store.put = AsyncMock()
        return store

    @pytest.mark.asyncio
    async def test_creates_artifact_and_updates_bucket(
        self, artifact_service, object_store
    ):
        """process_raw_artifact should create both artifact and bucket."""
        candidate = {
            "endpoint": "/api/test",
            "error_type": "crash",
            "status_code": 500,
            "type": "crash",
        }

        result = await process_raw_artifact(
            campaign_id="camp0001",
            run_lane_id="run00001",
            candidate=candidate,
            artifact_service=artifact_service,
            object_store=object_store,
        )

        artifact_service.create_or_update_bucket.assert_awaited_once()
        artifact_service.create_artifact.assert_awaited_once()
        assert result is not None
        assert result["artifact_id"] == "art00001"
        assert result["campaign_id"] == "camp0001"

    @pytest.mark.asyncio
    async def test_returns_none_when_bucket_full(
        self, artifact_service, object_store
    ):
        """process_raw_artifact should return None when bucket has 3+ artifacts."""
        # Bucket already has 3 artifacts
        artifact_service.create_or_update_bucket.return_value = {
            "id": "bkt00001",
            "campaign_id": "camp0001",
            "bucket_key": "abcdef0123456789",
            "artifact_count": 3,
        }

        candidate = {
            "endpoint": "/api/test",
            "error_type": "crash",
            "status_code": 500,
            "type": "crash",
        }

        result = await process_raw_artifact(
            campaign_id="camp0001",
            run_lane_id="run00001",
            candidate=candidate,
            artifact_service=artifact_service,
            object_store=object_store,
        )

        # Artifact and bucket should still be created/updated
        artifact_service.create_or_update_bucket.assert_awaited_once()
        artifact_service.create_artifact.assert_awaited_once()
        # But result should be None (no replay needed)
        assert result is None

    @pytest.mark.asyncio
    async def test_stores_evidence_when_present(
        self, artifact_service, object_store
    ):
        """process_raw_artifact should store evidence in object store."""
        candidate = {
            "endpoint": "/api/test",
            "error_type": "crash",
            "status_code": 500,
            "type": "crash",
            "evidence": {"trace": "stack trace here"},
        }

        await process_raw_artifact(
            campaign_id="camp0001",
            run_lane_id="run00001",
            candidate=candidate,
            artifact_service=artifact_service,
            object_store=object_store,
        )

        object_store.put.assert_awaited_once()
        call_args = object_store.put.call_args
        assert "artifacts/camp0001/art00001/evidence" == call_args[0][0]
        assert call_args[0][1] == {"trace": "stack trace here"}
