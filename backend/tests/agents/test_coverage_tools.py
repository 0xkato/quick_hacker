"""Tests for coverage-related tools."""
import pytest
from agents.tools import TRACE_PATH_VERDICT_SCHEMA


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
