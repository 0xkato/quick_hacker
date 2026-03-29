"""Artifact bucketing and deduplication.

Artifacts from fuzzing lanes are grouped into buckets by crash signature
so that duplicate crashes are counted but not re-analysed endlessly.
"""

from __future__ import annotations

import hashlib


def compute_bucket_key(artifact_candidate: dict) -> str:
    """Compute a dedup bucket key from an artifact candidate.

    Key is based on: method + path + status_code (the fields produced
    by the fuzz worker / schemathesis engine).
    Same method + path + status_code -> same bucket.
    """
    method = artifact_candidate.get("method", "unknown")
    path = artifact_candidate.get("path", "unknown")
    status_code = str(artifact_candidate.get("status_code", ""))
    raw = f"{method} {path}:{status_code}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def should_replay(bucket_key: str, existing_bucket: dict | None) -> bool:
    """Decide if this artifact should be replayed.

    - New bucket (no existing) -> True
    - Existing bucket with < 3 artifacts -> True
    - Existing bucket with 3+ artifacts -> False (already well-represented)
    """
    if existing_bucket is None:
        return True
    return existing_bucket.get("artifact_count", 0) < 3


async def process_raw_artifact(
    campaign_id: str,
    run_lane_id: str,
    candidate: dict,
    artifact_service,
    object_store,
) -> dict | None:
    """Process a raw artifact candidate through bucketing.

    1. Compute bucket key
    2. Create/update bucket
    3. Create artifact record
    4. Store evidence in object store
    5. Return artifact dict if should_replay, else None
    """
    # 1. Compute bucket key
    bucket_key = compute_bucket_key(candidate)

    # 2. Create/update bucket
    artifact_type = candidate.get("type", "crash")
    bucket = await artifact_service.create_or_update_bucket(
        campaign_id=campaign_id,
        bucket_key=bucket_key,
        artifact_type=artifact_type,
    )

    # 3. Create artifact record
    artifact = await artifact_service.create_artifact(
        run_lane_id=run_lane_id,
        type=artifact_type,
        bucket_key=bucket_key,
        artifact_classification=candidate.get("classification", "issue_candidate"),
        replay_recipe=candidate.get("replay_recipe"),
        evidence_refs=candidate.get("evidence_refs"),
    )

    # 4. Store evidence in object store
    evidence_data = candidate.get("evidence")
    if evidence_data is not None and object_store is not None:
        import json as _json
        store_key = f"artifacts/{campaign_id}/{artifact.id}/evidence"
        if isinstance(evidence_data, bytes):
            object_store.put(store_key, evidence_data)
        else:
            object_store.put(store_key, _json.dumps(evidence_data, default=str).encode())

    # 5. Return artifact dict if should_replay, else None
    if should_replay(bucket_key, bucket):
        return {
            "artifact_id": artifact.id,
            "bucket_key": bucket_key,
            "type": artifact_type,
            "run_lane_id": run_lane_id,
            "campaign_id": campaign_id,
        }

    return None
