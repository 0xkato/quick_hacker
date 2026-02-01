"""Tests for pre-scan path exclusions in base agent."""
import pytest
from models.validation_profile import ValidationProfile


class TestPreScanExclusions:
    def test_filter_excluded_paths(self):
        from agents.base_agent import filter_excluded_paths

        all_files = [
            "src/main.c",
            "src/parser.c",
            "tools/build.py",
            "tools/lint.py",
            "test/test_main.c",
            "test/unit/test_parser.c",
            "third_party/lib/foo.c",
        ]

        profile = ValidationProfile(
            excluded_paths=["tools/", "test/", "third_party/"]
        )

        filtered = filter_excluded_paths(all_files, profile)

        assert "src/main.c" in filtered
        assert "src/parser.c" in filtered
        assert "tools/build.py" not in filtered
        assert "test/test_main.c" not in filtered
        assert "third_party/lib/foo.c" not in filtered
        assert len(filtered) == 2

    def test_filter_no_exclusions(self):
        from agents.base_agent import filter_excluded_paths

        all_files = ["src/main.c", "tools/build.py"]
        profile = ValidationProfile(excluded_paths=[])

        filtered = filter_excluded_paths(all_files, profile)
        assert len(filtered) == 2

    def test_filter_none_profile(self):
        from agents.base_agent import filter_excluded_paths

        all_files = ["src/main.c", "tools/build.py"]
        filtered = filter_excluded_paths(all_files, None)
        assert len(filtered) == 2

    def test_filter_nested_paths(self):
        from agents.base_agent import filter_excluded_paths

        all_files = [
            "chrome/browser/main.cc",
            "chrome/test/unit/test.cc",
            "chrome/app/app.cc",
        ]

        profile = ValidationProfile(excluded_paths=["chrome/test/"])

        filtered = filter_excluded_paths(all_files, profile)
        assert "chrome/browser/main.cc" in filtered
        assert "chrome/app/app.cc" in filtered
        assert "chrome/test/unit/test.cc" not in filtered
