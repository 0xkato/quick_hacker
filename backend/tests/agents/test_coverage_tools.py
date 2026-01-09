"""Tests for coverage-related tools."""
import pytest
from agents.tools import TRACE_PATH_VERDICT_SCHEMA, handle_trace_path_verdict
from services.coverage_tracker import CoverageTracker, PathStatus


class TestTracePathVerdictSchema:
    def test_schema_has_required_fields(self):
        assert TRACE_PATH_VERDICT_SCHEMA["name"] == "trace_path_verdict"
        params = TRACE_PATH_VERDICT_SCHEMA["parameters"]["properties"]
        assert "entry_point_file" in params
        assert "entry_point_line" in params
        assert "sink_file" in params
        assert "sink_line" in params
        assert "verdict" in params
        assert "reasoning" in params
        assert "files_examined" in params

    def test_verdict_enum_values(self):
        params = TRACE_PATH_VERDICT_SCHEMA["parameters"]["properties"]
        verdict_enum = params["verdict"]["enum"]
        assert "safe" in verdict_enum
        assert "vulnerable" in verdict_enum
        assert "blocked" in verdict_enum
        assert "inconclusive" in verdict_enum


class TestHandleTracePathVerdict:
    def test_updates_existing_path(self):
        tracker = CoverageTracker("test-agent")
        tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )

        broadcasts = []
        def mock_broadcast(event_type, data):
            broadcasts.append((event_type, data))

        result = handle_trace_path_verdict(
            args={
                "entry_point_file": "routes/api.py",
                "entry_point_line": 42,
                "sink_file": "db/query.py",
                "sink_line": 100,
                "verdict": "safe",
                "reasoning": "Uses parameterized query",
                "files_examined": ["routes/api.py", "db/query.py"]
            },
            coverage_tracker=tracker,
            broadcast_fn=mock_broadcast
        )

        assert "safe" in result.lower()
        path = tracker.find_path_by_locations("routes/api.py", 42, "db/query.py", 100)
        assert path.status == PathStatus.TRACED_SAFE
        assert len(broadcasts) == 1
        assert broadcasts[0][0] == "COVERAGE_UPDATE"

    def test_auto_registers_unknown_path(self):
        tracker = CoverageTracker("test-agent")
        broadcasts = []

        result = handle_trace_path_verdict(
            args={
                "entry_point_file": "routes/new.py",
                "entry_point_line": 10,
                "sink_file": "db/new.py",
                "sink_line": 20,
                "verdict": "vulnerable",
                "reasoning": "SQL injection found",
                "files_examined": ["routes/new.py"],
                "finding_id": "finding-123"
            },
            coverage_tracker=tracker,
            broadcast_fn=lambda t, d: broadcasts.append((t, d))
        )

        assert len(tracker.paths) == 1
        path = list(tracker.paths.values())[0]
        assert path.status == PathStatus.TRACED_VULN
        assert path.finding_id == "finding-123"
