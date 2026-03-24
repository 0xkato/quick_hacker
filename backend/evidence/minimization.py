"""Artifact minimization -- shrink artifacts to their minimal reproducing form.

For HTTP artifacts: iteratively remove headers, body fields, query params
while checking if the failure still reproduces.

For binary artifacts: binary search / delta debugging on the input bytes.
"""
from __future__ import annotations

import copy
import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def minimize_artifact(
    artifact_id: str,
    artifact_candidate: dict | None = None,
    replay_fn: callable | None = None,
    base_url: str = "http://localhost:8080",
    budget_seconds: int = 60,
) -> dict:
    """Minimize an artifact to its smallest reproducing form.

    Args:
        artifact_id: The artifact being minimized
        artifact_candidate: The raw artifact data (method, path, headers, body, etc.)
        replay_fn: Function to replay the artifact (returns ReplayResult-like dict)
        base_url: Target base URL for replay
        budget_seconds: Time budget for minimization

    Returns:
        {
            "artifact_id": str,
            "minimized": bool,
            "original_size": int,
            "minimized_size": int,
            "attempts": int,
            "budget_seconds": int,
            "minimized_candidate": dict | None,
        }
    """
    result = {
        "artifact_id": artifact_id,
        "minimized": False,
        "original_size": 0,
        "minimized_size": 0,
        "attempts": 0,
        "budget_seconds": budget_seconds,
        "minimized_candidate": None,
    }

    if not artifact_candidate or not replay_fn:
        return result

    # Determine artifact type and apply appropriate minimization
    artifact_type = artifact_candidate.get("type", "unknown")

    if artifact_type in ("oracle_hit", "differential_failure"):
        # HTTP artifact -- minimize request
        minimized = await _minimize_http_artifact(artifact_candidate, replay_fn, base_url, budget_seconds)
    elif artifact_type == "crash":
        # Binary crash -- minimize input
        minimized = await _minimize_binary_artifact(artifact_candidate, replay_fn, base_url, budget_seconds)
    else:
        return result

    if minimized:
        result["minimized"] = True
        result["minimized_candidate"] = minimized["candidate"]
        result["original_size"] = minimized["original_size"]
        result["minimized_size"] = minimized["minimized_size"]
        result["attempts"] = minimized["attempts"]

    return result


async def _minimize_http_artifact(
    candidate: dict,
    replay_fn: callable,
    base_url: str,
    budget_seconds: int,
) -> dict | None:
    """Minimize an HTTP artifact by removing headers, body fields, query params."""
    import time

    start = time.monotonic()
    attempts = 0
    current = copy.deepcopy(candidate)
    original_size = _estimate_size(current)

    # Step 1: Try removing headers one by one
    headers = current.get("headers", {})
    if isinstance(headers, dict):
        for key in list(headers.keys()):
            if time.monotonic() - start > budget_seconds:
                break

            reduced = copy.deepcopy(current)
            del reduced.get("headers", {})[key]

            attempts += 1
            if await _still_reproduces(reduced, replay_fn, base_url):
                current = reduced

    # Step 2: Try removing body fields (if JSON body)
    body = current.get("body", "")
    if isinstance(body, dict):
        for key in list(body.keys()):
            if time.monotonic() - start > budget_seconds:
                break

            reduced = copy.deepcopy(current)
            del reduced["body"][key]

            attempts += 1
            if await _still_reproduces(reduced, replay_fn, base_url):
                current = reduced

    # Step 3: Try simplifying string body
    if isinstance(body, str) and len(body) > 10:
        # Binary search for minimum body length
        lo, hi = 0, len(body)
        while lo < hi and time.monotonic() - start < budget_seconds:
            mid = (lo + hi) // 2
            reduced = copy.deepcopy(current)
            reduced["body"] = body[:mid]

            attempts += 1
            if await _still_reproduces(reduced, replay_fn, base_url):
                current = reduced
                hi = mid
            else:
                lo = mid + 1

    minimized_size = _estimate_size(current)

    if minimized_size < original_size:
        return {
            "candidate": current,
            "original_size": original_size,
            "minimized_size": minimized_size,
            "attempts": attempts,
        }

    return None


async def _minimize_binary_artifact(
    candidate: dict,
    replay_fn: callable,
    base_url: str,
    budget_seconds: int,
) -> dict | None:
    """Minimize a binary crash artifact using delta debugging."""
    import time

    start = time.monotonic()
    attempts = 0

    input_data = candidate.get("input", "")
    if not input_data:
        return None

    # Convert hex string to bytes if needed
    if isinstance(input_data, str):
        try:
            input_bytes = bytes.fromhex(input_data)
        except ValueError:
            input_bytes = input_data.encode()
    else:
        input_bytes = input_data

    original_size = len(input_bytes)
    current = input_bytes

    # Delta debugging: try removing chunks of decreasing size
    chunk_size = max(1, len(current) // 2)

    while chunk_size >= 1 and time.monotonic() - start < budget_seconds:
        i = 0
        while i < len(current) and time.monotonic() - start < budget_seconds:
            reduced = current[:i] + current[i + chunk_size:]

            reduced_candidate = copy.deepcopy(candidate)
            reduced_candidate["input"] = reduced.hex()

            attempts += 1
            if await _still_reproduces(reduced_candidate, replay_fn, base_url):
                current = reduced
            else:
                i += chunk_size

        chunk_size //= 2

    minimized_size = len(current)

    if minimized_size < original_size:
        minimized_candidate = copy.deepcopy(candidate)
        minimized_candidate["input"] = current.hex()
        return {
            "candidate": minimized_candidate,
            "original_size": original_size,
            "minimized_size": minimized_size,
            "attempts": attempts,
        }

    return None


async def _still_reproduces(candidate: dict, replay_fn: callable, base_url: str) -> bool:
    """Check if a reduced artifact still triggers the same failure."""
    try:
        import asyncio
        result = await asyncio.to_thread(replay_fn, candidate, base_url, attempts=1)
        return result.reproduced if hasattr(result, "reproduced") else result.get("reproduced", False)
    except Exception:
        return False


def _estimate_size(candidate: dict) -> int:
    """Estimate the serialized size of an artifact candidate."""
    import json
    try:
        return len(json.dumps(candidate, default=str))
    except Exception:
        return 0
