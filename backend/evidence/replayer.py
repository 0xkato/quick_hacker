"""Artifact replayer -- reproduce artifacts against the target.

v1: For HTTP artifacts, re-send the request and check if the same
failure occurs.  Uses httpx to send requests from the artifact candidate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx


@dataclass
class ReplayResult:
    """Result of replaying an artifact candidate."""

    reproduced: bool
    stability_score: float  # 0.0 to 1.0
    attempts: int
    errors: list[str] = field(default_factory=list)


def replay_artifact(
    artifact_candidate: dict,
    base_url: str,
    attempts: int = 3,
) -> ReplayResult:
    """Replay an artifact candidate against the target.

    v1: For HTTP artifacts, re-send the request and check if same failure
    occurs.  The artifact_candidate dict is expected to have:

        method   - HTTP method (GET, POST, etc.)
        path     - URL path
        status_code - expected failure status code
        headers  - optional request headers
        body     - optional request body

    Returns a ReplayResult with reproduction statistics.
    """
    method = artifact_candidate.get("method", "GET").upper()
    path = artifact_candidate.get("path", "/")
    expected_status = artifact_candidate.get("status_code")
    headers = artifact_candidate.get("headers") or {}
    body = artifact_candidate.get("body")

    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    reproductions = 0
    errors: list[str] = []

    for _ in range(attempts):
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                )

                if expected_status is not None and response.status_code == expected_status:
                    reproductions += 1
        except Exception as exc:
            errors.append(str(exc))
            # Connection errors or timeouts count as reproduction if the
            # original artifact was also an error/hang
            if expected_status is None:
                reproductions += 1

    stability_score = reproductions / attempts if attempts > 0 else 0.0

    return ReplayResult(
        reproduced=stability_score > 0.0,
        stability_score=stability_score,
        attempts=attempts,
        errors=errors,
    )
