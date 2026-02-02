"""Tests for path classification using PathFilter."""
import pytest
from models.schemas import PathClassification, PathClassificationConfig, TriagePolicy
from services.finding_filters import PathFilter


class TestPathFilterClassification:
    """Test path classification logic via PathFilter._classify_path."""

    def _classify(self, file_path: str, config: PathClassificationConfig = None):
        """Helper to classify a path using PathFilter."""
        if config is None:
            config = PathClassificationConfig()
        policy = TriagePolicy(name="test")
        path_filter = PathFilter(config, policy)
        return path_filter._classify_path(file_path)

    def test_classify_runtime_path(self):
        """Test classification of runtime paths."""
        config = PathClassificationConfig()

        assert self._classify("src/main.py", config) == PathClassification.runtime
        assert self._classify("app/server.py", config) == PathClassification.runtime
        assert self._classify("backend/api.py", config) == PathClassification.runtime

    def test_classify_tooling_path(self):
        """Test classification of tooling paths."""
        config = PathClassificationConfig()

        assert self._classify("tools/deploy.py", config) == PathClassification.tooling
        assert self._classify("scripts/migrate.sh", config) == PathClassification.tooling
        assert self._classify("examples/demo.py", config) == PathClassification.tooling

    def test_classify_third_party_path(self):
        """Test classification of third party paths."""
        config = PathClassificationConfig()

        assert self._classify("third_party/lib.py", config) == PathClassification.third_party
        assert self._classify("vendor/package/file.py", config) == PathClassification.third_party
        assert self._classify("node_modules/pkg/index.js", config) == PathClassification.third_party

    def test_classify_test_path_as_third_party(self):
        """Test test paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert self._classify("test/test_main.py", config) == PathClassification.third_party
        assert self._classify("tests/unit/test_api.py", config) == PathClassification.third_party

    def test_classify_ci_path_as_third_party(self):
        """Test CI paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert self._classify(".github/workflows/ci.yml", config) == PathClassification.third_party
        assert self._classify(".gitlab/ci.yml", config) == PathClassification.third_party

    def test_classify_docs_path_as_third_party(self):
        """Test docs paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert self._classify("docs/readme.md", config) == PathClassification.third_party

    def test_classify_migration_path_as_third_party(self):
        """Test migration paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert self._classify("migrations/001_init.sql", config) == PathClassification.third_party

    def test_classify_unknown_path(self):
        """Test paths not matching any category return unknown."""
        config = PathClassificationConfig()

        assert self._classify("random/file.py", config) == PathClassification.unknown

    def test_classify_path_with_subdirectories(self):
        """Test path classification works with nested directories."""
        config = PathClassificationConfig()

        # Should match even in subdirectories
        assert self._classify("project/third_party/lib/file.py", config) == PathClassification.third_party
        assert self._classify("project/src/main.py", config) == PathClassification.runtime

    def test_classify_path_priority_order(self):
        """Test third_party has highest priority."""
        config = PathClassificationConfig()

        # third_party should win over runtime even if path contains both
        # (e.g., third_party might vendor src/ directories)
        assert self._classify("third_party/project/src/main.py", config) == PathClassification.third_party
