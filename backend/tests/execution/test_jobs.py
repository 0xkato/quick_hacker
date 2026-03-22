"""Tests for job type definitions and queue mapping."""
from __future__ import annotations

from execution.jobs import (
    QUEUE_CONTROL,
    QUEUE_FUZZ,
    QUEUE_PACKAGE,
    QUEUE_REPLAY,
    JOB_QUEUE_MAP,
    HarnessValidationJob,
    JobType,
    MinimizationJob,
    PackageLaneBundleJob,
    ReplayJob,
    RunLaneJob,
)


class TestJobTypeEnum:
    """JobType enum completeness."""

    EXPECTED_MEMBERS = {
        "EXTRACTOR",
        "PLANNER",
        "COMPILER",
        "STEERING",
        "ANALYST",
        "PACKAGE_LANE_BUNDLE",
        "HARNESS_VALIDATION",
        "RUN_LANE",
        "REPLAY",
        "MINIMIZATION",
    }

    def test_has_all_10_values(self) -> None:
        members = set(JobType.__members__.keys())
        assert members == self.EXPECTED_MEMBERS
        assert len(members) == 10

    def test_str_returns_value(self) -> None:
        assert str(JobType.EXTRACTOR) == "extractor"
        assert str(JobType.RUN_LANE) == "run_lane"


class TestJobQueueMap:
    """JOB_QUEUE_MAP covers every JobType."""

    def test_maps_every_job_type(self) -> None:
        for jt in JobType:
            assert jt in JOB_QUEUE_MAP, f"{jt} missing from JOB_QUEUE_MAP"

    def test_control_plane_jobs_route_to_control_queue(self) -> None:
        control_types = {
            JobType.EXTRACTOR,
            JobType.PLANNER,
            JobType.COMPILER,
            JobType.STEERING,
            JobType.ANALYST,
        }
        for jt in control_types:
            assert JOB_QUEUE_MAP[jt] == QUEUE_CONTROL

    def test_package_jobs_route_to_package_queue(self) -> None:
        assert JOB_QUEUE_MAP[JobType.PACKAGE_LANE_BUNDLE] == QUEUE_PACKAGE
        assert JOB_QUEUE_MAP[JobType.HARNESS_VALIDATION] == QUEUE_PACKAGE

    def test_fuzz_jobs_route_to_fuzz_queue(self) -> None:
        assert JOB_QUEUE_MAP[JobType.RUN_LANE] == QUEUE_FUZZ

    def test_replay_jobs_route_to_replay_queue(self) -> None:
        assert JOB_QUEUE_MAP[JobType.REPLAY] == QUEUE_REPLAY
        assert JOB_QUEUE_MAP[JobType.MINIMIZATION] == QUEUE_REPLAY


class TestPackageLaneBundleJob:
    def test_auto_job_type(self) -> None:
        job = PackageLaneBundleJob(
            campaign_id="c1",
            lane_spec_id="ls1",
            lane_spec_revision=3,
        )
        assert job.job_type == JobType.PACKAGE_LANE_BUNDLE
        assert job.campaign_id == "c1"
        assert job.lane_spec_id == "ls1"
        assert job.lane_spec_revision == 3


class TestHarnessValidationJob:
    def test_auto_job_type(self) -> None:
        job = HarnessValidationJob(
            campaign_id="c2",
            execution_bundle_id="eb1",
        )
        assert job.job_type == JobType.HARNESS_VALIDATION
        assert job.execution_bundle_id == "eb1"


class TestRunLaneJob:
    def test_auto_job_type(self) -> None:
        job = RunLaneJob(
            campaign_id="c3",
            execution_bundle_id="eb2",
            cpu_limit=2.0,
            memory_limit_mb=512,
            timeout_seconds=300,
            resource_profile="standard",
        )
        assert job.job_type == JobType.RUN_LANE

    def test_resource_fields(self) -> None:
        job = RunLaneJob(
            campaign_id="c3",
            execution_bundle_id="eb2",
            cpu_limit=4.0,
            memory_limit_mb=1024,
            timeout_seconds=600,
            resource_profile="heavy",
        )
        assert job.cpu_limit == 4.0
        assert job.memory_limit_mb == 1024
        assert job.timeout_seconds == 600
        assert job.resource_profile == "heavy"


class TestReplayJob:
    def test_auto_job_type(self) -> None:
        job = ReplayJob(
            campaign_id="c4",
            artifact_id="a1",
            execution_bundle_id="eb3",
        )
        assert job.job_type == JobType.REPLAY
        assert job.artifact_id == "a1"


class TestMinimizationJob:
    def test_auto_job_type(self) -> None:
        job = MinimizationJob(
            campaign_id="c5",
            artifact_id="a2",
            execution_bundle_id="eb4",
            budget_seconds=120,
        )
        assert job.job_type == JobType.MINIMIZATION

    def test_budget_seconds(self) -> None:
        job = MinimizationJob(
            campaign_id="c5",
            artifact_id="a2",
            execution_bundle_id="eb4",
            budget_seconds=300,
        )
        assert job.budget_seconds == 300
