"""Tests for coverage tracker service."""
import pytest
from services.coverage_tracker import PathStatus, PathRecord


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
