"""Job type definitions and queue mapping for campaign execution.

Defines the job types used across the campaign pipeline, their queue
assignments, and the dataclasses that carry job-specific payloads.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Queue name constants
# ---------------------------------------------------------------------------
QUEUE_CONTROL = "qh_control"
QUEUE_PACKAGE = "qh_package"
QUEUE_FUZZ = "qh_fuzz"
QUEUE_REPLAY = "qh_replay"


# ---------------------------------------------------------------------------
# JobType enum
# ---------------------------------------------------------------------------
class JobType(str, Enum):
    """Discriminator for every job the pipeline can enqueue."""

    # Control plane
    EXTRACTOR = "extractor"
    PLANNER = "planner"
    COMPILER = "compiler"
    STEERING = "steering"
    ANALYST = "analyst"

    # Package workers
    PACKAGE_LANE_BUNDLE = "package_lane_bundle"
    HARNESS_VALIDATION = "harness_validation"

    # Fuzz workers
    RUN_LANE = "run_lane"

    # Replay workers
    REPLAY = "replay"
    MINIMIZATION = "minimization"

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# Queue mapping
# ---------------------------------------------------------------------------
JOB_QUEUE_MAP: dict[JobType, str] = {
    # Control plane
    JobType.EXTRACTOR: QUEUE_CONTROL,
    JobType.PLANNER: QUEUE_CONTROL,
    JobType.COMPILER: QUEUE_CONTROL,
    JobType.STEERING: QUEUE_CONTROL,
    JobType.ANALYST: QUEUE_CONTROL,
    # Package workers
    JobType.PACKAGE_LANE_BUNDLE: QUEUE_PACKAGE,
    JobType.HARNESS_VALIDATION: QUEUE_PACKAGE,
    # Fuzz workers
    JobType.RUN_LANE: QUEUE_FUZZ,
    # Replay workers
    JobType.REPLAY: QUEUE_REPLAY,
    JobType.MINIMIZATION: QUEUE_REPLAY,
}


# ---------------------------------------------------------------------------
# Job dataclasses
# ---------------------------------------------------------------------------
@dataclass
class PackageLaneBundleJob:
    """Package a lane spec into an execution bundle."""

    campaign_id: str
    lane_spec_id: str
    lane_spec_revision: int
    job_type: JobType = field(default=JobType.PACKAGE_LANE_BUNDLE, init=False)


@dataclass
class HarnessValidationJob:
    """Validate a compiled execution bundle before running."""

    campaign_id: str
    execution_bundle_id: str
    job_type: JobType = field(default=JobType.HARNESS_VALIDATION, init=False)


@dataclass
class RunLaneJob:
    """Execute a fuzz lane against a target."""

    campaign_id: str
    execution_bundle_id: str
    cpu_limit: float
    memory_limit_mb: int
    timeout_seconds: int
    resource_profile: str
    job_type: JobType = field(default=JobType.RUN_LANE, init=False)


@dataclass
class ReplayJob:
    """Replay a crash artifact to confirm reproducibility."""

    campaign_id: str
    artifact_id: str
    execution_bundle_id: str
    job_type: JobType = field(default=JobType.REPLAY, init=False)


@dataclass
class MinimizationJob:
    """Minimize a crash artifact to its smallest reproducer."""

    campaign_id: str
    artifact_id: str
    execution_bundle_id: str
    budget_seconds: int
    job_type: JobType = field(default=JobType.MINIMIZATION, init=False)
