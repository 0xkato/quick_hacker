# backend/tests/integration/test_tool_cache_coverage.py
import pytest
import subprocess
from pathlib import Path
from services.tool_core import ToolCore
from services.tool_cache import ToolCache


class TestToolCacheCoverage:
    @pytest.mark.asyncio
    async def test_search_code_caches_results(self, tmp_path):
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True)

        # Create test files
        (tmp_path / "file1.py").write_text("password = 'secret'")
        (tmp_path / "file2.py").write_text("username = 'admin'")

        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=tmp_path, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(
            repo_path=str(tmp_path),
            project_id="test",
            cache=cache,
        )

        # First search - cache miss
        result1 = await tool_core.search_code(pattern="password")
        metrics1 = cache.get_metrics()
        assert metrics1["misses"] == 1
        assert metrics1["hits"] == 0

        # Second identical search - cache hit
        result2 = await tool_core.search_code(pattern="password")
        metrics2 = cache.get_metrics()
        assert metrics2["misses"] == 1
        assert metrics2["hits"] == 1

        assert result1 == result2

    @pytest.mark.asyncio
    async def test_list_directory_caches_results(self, tmp_path):
        # Setup git repo
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True, capture_output=True)

        # Create test structure
        (tmp_path / "dir1").mkdir()
        (tmp_path / "dir1" / "file.txt").write_text("content")

        subprocess.run(["git", "add", "."], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=tmp_path, check=True, capture_output=True)

        cache = ToolCache(max_size=100, ttl_seconds=3600)
        tool_core = ToolCore(
            repo_path=str(tmp_path),
            project_id="test",
            cache=cache,
        )

        # First listing - cache miss
        result1 = await tool_core.list_directory(path="dir1")
        metrics1 = cache.get_metrics()
        assert metrics1["misses"] == 1
        assert metrics1["hits"] == 0

        # Second listing - cache hit
        result2 = await tool_core.list_directory(path="dir1")
        metrics2 = cache.get_metrics()
        assert metrics2["misses"] == 1
        assert metrics2["hits"] == 1

        assert result1 == result2
