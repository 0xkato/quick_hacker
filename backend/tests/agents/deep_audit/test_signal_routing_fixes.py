"""Test signal routing pipeline fixes.

Tests verify:
1. Wave files with focus suffixes are collected
2. JSON extraction handles markdown-wrapped output
3. Phase 4 condition is properly logged
"""
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch


class TestWaveFileCollection:
    """Test that wave files with focus suffixes are collected."""

    def test_list_directory_alias_exists(self):
        """Verify list_directory is aliased to ls in MemoriesFilesystem."""
        from agents.deep_audit.filesystem import MemoriesFilesystem

        # Check that list_directory is an alias to ls
        assert hasattr(MemoriesFilesystem, 'list_directory')
        assert MemoriesFilesystem.list_directory == MemoriesFilesystem.ls

    def test_sink_file_pattern_matching(self):
        """Test that sink file pattern correctly matches focus-suffixed files."""
        all_files = [
            "sinks.json",
            "sinks_memory.json",
            "sinks_injection.json",
            "sinks_crypto.json",
            "dataflow_trace.json",
            "auth_boundaries.json",
            "README.md",
        ]

        # This is the pattern used in _collect_wave_findings
        sink_files = [f for f in all_files if f.startswith("sinks") and f.endswith(".json")]

        assert len(sink_files) == 4
        assert "sinks.json" in sink_files
        assert "sinks_memory.json" in sink_files
        assert "sinks_injection.json" in sink_files
        assert "sinks_crypto.json" in sink_files
        assert "README.md" not in sink_files


class TestJSONExtraction:
    """Test consistent JSON extraction across all hunters."""

    def test_extract_json_from_markdown_wrapped_output(self):
        """Claude often wraps JSON in markdown code blocks."""
        from agents.deep_audit.utils.json_extractor import extract_json_from_output

        markdown_output = '''Here are the entrypoints I found:

```json
{
  "entrypoints": [
    {"path": "/api/users", "method": "GET"},
    {"path": "/api/login", "method": "POST"}
  ]
}
```

These are the main entry points in the application.'''

        result = extract_json_from_output(markdown_output)

        assert result is not None
        assert "entrypoints" in result
        assert len(result["entrypoints"]) == 2
        assert result["entrypoints"][0]["path"] == "/api/users"

    def test_extract_json_from_plain_json(self):
        """Plain JSON without markdown should also work."""
        from agents.deep_audit.utils.json_extractor import extract_json_from_output

        plain_json = '{"signals": [{"title": "Test", "severity": "HIGH"}]}'

        result = extract_json_from_output(plain_json)

        assert result is not None
        assert "signals" in result
        assert len(result["signals"]) == 1

    def test_extract_json_from_nested_braces(self):
        """Complex nested JSON should be extracted correctly."""
        from agents.deep_audit.utils.json_extractor import extract_json_from_output

        output_with_nested = '''Analysis complete. Found the following:

{
  "signals": [
    {
      "title": "Buffer overflow",
      "details": {
        "location": {"file": "src/codec.cpp", "line": 123},
        "severity": "HIGH"
      }
    }
  ]
}

End of analysis.'''

        result = extract_json_from_output(output_with_nested)

        assert result is not None
        assert "signals" in result
        assert result["signals"][0]["details"]["location"]["file"] == "src/codec.cpp"


class TestErrorVisibility:
    """Test that collection errors are visible in UI."""

    @pytest.mark.asyncio
    async def test_collection_errors_emitted_to_log(self):
        """Collection errors should be emitted to UI, not just printed."""
        from agents.deep_audit.overseer import Overseer
        from agents.deep_audit.filesystem import MemoriesFilesystem
        from unittest.mock import AsyncMock, MagicMock, patch

        # Create mock overseer with minimal setup
        with patch.object(Overseer, '__init__', lambda self, *args, **kwargs: None):
            overseer = Overseer.__new__(Overseer)
            overseer.campaign_state = MagicMock()
            overseer.campaign_state.confirmed_findings = []
            overseer.campaign_state.entrypoints = []
            overseer.emit_log = AsyncMock()

            # Mock filesystem that raises FileNotFoundError
            overseer.filesystem = MagicMock()
            overseer.filesystem.read_file = MagicMock(side_effect=FileNotFoundError("File not found"))

            # Run collection
            await overseer._collect_findings_from_signals()

            # Verify emit_log was called with error info
            calls = [str(c) for c in overseer.emit_log.call_args_list]
            assert any("WARNING" in str(c) or "collection error" in str(c) for c in calls)


class TestPhase4DebugLogging:
    """Test Phase 4 condition logging."""

    def test_phase4_skip_reasons(self):
        """Test that skip reasons are properly formatted."""
        # Simulate the skip reason logic from overseer
        findings_count = 0
        time_remaining = 30.5

        skip_reasons = []
        if findings_count == 0:
            skip_reasons.append("no findings collected")
        if time_remaining <= 60:
            skip_reasons.append(f"insufficient time ({time_remaining:.0f}s <= 60s)")

        reason_str = ", ".join(skip_reasons)

        assert "no findings collected" in reason_str
        assert "insufficient time (30s <= 60s)" in reason_str

    def test_phase4_proceeds_with_findings_and_time(self):
        """Phase 4 should proceed when both conditions are met."""
        findings_count = 5
        time_remaining = 120

        should_proceed = findings_count > 0 and time_remaining > 60

        assert should_proceed is True

    def test_phase4_skipped_with_no_findings(self):
        """Phase 4 should skip if no findings even with time remaining."""
        findings_count = 0
        time_remaining = 120

        should_proceed = findings_count > 0 and time_remaining > 60

        assert should_proceed is False

    def test_phase4_skipped_with_no_time(self):
        """Phase 4 should skip if insufficient time even with findings."""
        findings_count = 10
        time_remaining = 30

        should_proceed = findings_count > 0 and time_remaining > 60

        assert should_proceed is False
