"""Artifact reclassification after replay.

After an artifact is replayed, classify it based on the replay result
to determine whether it should advance through the issue pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ReplayResult:
    """Minimal replay result fields needed for classification."""

    reproduced: bool
    stability_score: float = 1.0


def classify_after_replay(replay_result: ReplayResult, artifact: dict) -> str:
    """Classify artifact based on replay result.

    Returns one of:
        ``"issue_candidate"`` -- replay confirmed, advance to gating.
        ``"flaky_unconfirmed"`` -- could not reproduce or low stability.
        ``"harness_artifact"`` -- artefact of the harness, not real
            (v1 always returns ``"issue_candidate"`` when reproduced since
            distinguishing harness artefacts requires a known-good baseline).
    """
    if not replay_result.reproduced:
        return "flaky_unconfirmed"
    if replay_result.stability_score < 0.5:
        return "flaky_unconfirmed"
    # For v1, we can't distinguish harness_artifact from real issues
    # without running against a known-good version. Default to issue_candidate.
    return "issue_candidate"
