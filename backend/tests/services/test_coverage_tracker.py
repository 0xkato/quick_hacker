"""Tests for coverage tracker service."""
import pytest
from services.coverage_tracker import PathStatus, PathRecord, CoverageStats, CoverageTracker


class TestPathStatus:
    def test_status_enum_has_all_states(self):
        assert PathStatus.UNDISCOVERED.value == "undiscovered"
        assert PathStatus.DISCOVERED.value == "discovered"
        assert PathStatus.IN_PROGRESS.value == "in_progress"
        assert PathStatus.TRACED_SAFE.value == "traced_safe"
        assert PathStatus.TRACED_VULN.value == "traced_vuln"
        assert PathStatus.BLOCKED.value == "blocked"
        assert PathStatus.INCONCLUSIVE.value == "inconclusive"


class TestPathRecord:
    def test_path_record_creation(self):
        record = PathRecord(
            id="path-1",
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute",
            status=PathStatus.DISCOVERED
        )
        assert record.id == "path-1"
        assert record.status == PathStatus.DISCOVERED
        assert record.verdict_reasoning is None


class TestCoverageStats:
    def test_coverage_stats_creation(self):
        stats = CoverageStats(
            total_paths=10,
            discovered_count=5,
            in_progress_count=1,
            traced_safe_count=2,
            traced_vuln_count=1,
            blocked_count=1,
            inconclusive_count=0
        )
        assert stats.total_paths == 10

    def test_traced_count_property(self):
        stats = CoverageStats(
            total_paths=10,
            discovered_count=5,
            in_progress_count=0,
            traced_safe_count=2,
            traced_vuln_count=1,
            blocked_count=1,
            inconclusive_count=1
        )
        assert stats.traced_count == 4  # safe + vuln + blocked

    def test_coverage_percent_property(self):
        stats = CoverageStats(
            total_paths=10,
            discovered_count=6,
            in_progress_count=0,
            traced_safe_count=2,
            traced_vuln_count=1,
            blocked_count=1,
            inconclusive_count=0
        )
        assert stats.coverage_percent == 40.0  # 4/10

    def test_coverage_percent_zero_paths(self):
        stats = CoverageStats(
            total_paths=0,
            discovered_count=0,
            in_progress_count=0,
            traced_safe_count=0,
            traced_vuln_count=0,
            blocked_count=0,
            inconclusive_count=0
        )
        assert stats.coverage_percent == 0.0


@pytest.fixture
def tracker():
    return CoverageTracker(agent_id="test-agent")


class TestCoverageTrackerRegister:
    def test_register_path_returns_id(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        assert path_id is not None
        assert len(path_id) > 0

    def test_register_path_sets_discovered_status(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        assert tracker.paths[path_id].status == PathStatus.DISCOVERED

    def test_register_path_is_idempotent(self, tracker):
        path_id_1 = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        path_id_2 = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        assert path_id_1 == path_id_2
        assert len(tracker.paths) == 1


class TestCoverageTrackerUpdateStatus:
    def test_update_status_changes_status(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(path_id, PathStatus.IN_PROGRESS)
        assert tracker.paths[path_id].status == PathStatus.IN_PROGRESS

    def test_update_status_sets_reasoning(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(
            path_id,
            PathStatus.TRACED_SAFE,
            reasoning="Uses parameterized query"
        )
        assert tracker.paths[path_id].verdict_reasoning == "Uses parameterized query"

    def test_update_status_sets_traced_at(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(path_id, PathStatus.TRACED_SAFE)
        assert tracker.paths[path_id].traced_at is not None

    def test_update_status_unknown_path_raises(self, tracker):
        with pytest.raises(ValueError, match="Unknown path"):
            tracker.update_status("nonexistent-id", PathStatus.TRACED_SAFE)

    def test_update_status_sets_finding_id(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(
            path_id,
            PathStatus.TRACED_VULN,
            finding_id="finding-123"
        )
        assert tracker.paths[path_id].finding_id == "finding-123"

    def test_update_status_sets_files_in_path(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        files = ["routes/api.py", "services/auth.py", "db/query.py"]
        tracker.update_status(
            path_id,
            PathStatus.TRACED_SAFE,
            files_in_path=files
        )
        assert tracker.paths[path_id].files_in_path == files
