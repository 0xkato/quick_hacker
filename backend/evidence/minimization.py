"""Artifact minimization -- shrink artifacts to minimal reproducing form.

v1: Stub. For Schemathesis HTTP artifacts, minimization means reducing
request body/headers to the smallest set that still triggers the failure.
"""


async def minimize_artifact(artifact_id: str, budget_seconds: int = 60) -> dict:
    """Minimize an artifact. Returns minimization result.

    v1: No-op stub. Returns the artifact unchanged.
    """
    return {
        "artifact_id": artifact_id,
        "minimized": False,
        "original_size": 0,
        "minimized_size": 0,
        "attempts": 0,
        "budget_seconds": budget_seconds,
    }
