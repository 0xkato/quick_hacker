"""Tests for depth enforcement."""
import pytest
from agents.depth_enforcement import DepthEnforcementConfig, check_coverage_before_complete
from services.coverage_tracker import CoverageTracker, PathStatus


@pytest.fixture
def tracker_with_paths():
    tracker = CoverageTracker("test-agent")
    for i in range(10):
        tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=i * 10,
            entry_point_name=f"handler_{i}",
            sink_file=f"db/query{i}.py",
            sink_line=100,
            sink_type="sql",
            sink_function="execute"
        )
    return tracker


class TestDepthEnforcement:
    def test_allows_complete_when_coverage_sufficient(self, tracker_with_paths):
        # Trace 9 of 10 paths (90%)
        path_ids = list(tracker_with_paths.paths.keys())
        for path_id in path_ids[:9]:
            tracker_with_paths.update_status(path_id, PathStatus.TRACED_SAFE)

        config = DepthEnforcementConfig(min_coverage_percent=80.0)
        can_complete, challenge = check_coverage_before_complete(tracker_with_paths, config)

        assert can_complete is True
        assert challenge is None

    def test_challenges_when_coverage_insufficient(self, tracker_with_paths):
        # Trace only 5 of 10 paths (50%)
        path_ids = list(tracker_with_paths.paths.keys())
        for path_id in path_ids[:5]:
            tracker_with_paths.update_status(path_id, PathStatus.TRACED_SAFE)

        config = DepthEnforcementConfig(min_coverage_percent=80.0)
        can_complete, challenge = check_coverage_before_complete(tracker_with_paths, config)

        assert can_complete is False
        assert "50.0%" in challenge
        assert "Unexplored paths" in challenge

    def test_challenges_when_too_many_inconclusive(self, tracker_with_paths):
        path_ids = list(tracker_with_paths.paths.keys())
        # Trace 8 as safe, 2 as inconclusive
        for path_id in path_ids[:8]:
            tracker_with_paths.update_status(path_id, PathStatus.TRACED_SAFE)
        for path_id in path_ids[8:]:
            tracker_with_paths.update_status(path_id, PathStatus.INCONCLUSIVE)

        config = DepthEnforcementConfig(min_coverage_percent=80.0, max_inconclusive=1)
        can_complete, challenge = check_coverage_before_complete(tracker_with_paths, config)

        assert can_complete is False
        assert "inconclusive" in challenge.lower()
