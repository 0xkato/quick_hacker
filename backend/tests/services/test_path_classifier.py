"""Tests for path classification service."""
import pytest
from models.schemas import PathClassification, PathClassificationConfig
from services.path_classifier import classify_path


class TestClassifyPath:
    def test_classify_runtime_path(self):
        """Test classification of runtime paths."""
        config = PathClassificationConfig()

        assert classify_path("src/main.py", config) == PathClassification.runtime
        assert classify_path("app/server.py", config) == PathClassification.runtime
        assert classify_path("backend/api.py", config) == PathClassification.runtime

    def test_classify_tooling_path(self):
        """Test classification of tooling paths."""
        config = PathClassificationConfig()

        assert classify_path("tools/deploy.py", config) == PathClassification.tooling
        assert classify_path("scripts/migrate.sh", config) == PathClassification.tooling
        assert classify_path("examples/demo.py", config) == PathClassification.tooling

    def test_classify_third_party_path(self):
        """Test classification of third party paths."""
        config = PathClassificationConfig()

        assert classify_path("third_party/lib.py", config) == PathClassification.third_party
        assert classify_path("vendor/package/file.py", config) == PathClassification.third_party
        assert classify_path("node_modules/pkg/index.js", config) == PathClassification.third_party

    def test_classify_test_path_as_third_party(self):
        """Test test paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert classify_path("test/test_main.py", config) == PathClassification.third_party
        assert classify_path("tests/unit/test_api.py", config) == PathClassification.third_party

    def test_classify_ci_path_as_third_party(self):
        """Test CI paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert classify_path(".github/workflows/ci.yml", config) == PathClassification.third_party
        assert classify_path(".gitlab/ci.yml", config) == PathClassification.third_party

    def test_classify_docs_path_as_third_party(self):
        """Test docs paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert classify_path("docs/readme.md", config) == PathClassification.third_party

    def test_classify_migration_path_as_third_party(self):
        """Test migration paths are classified as third_party (excluded)."""
        config = PathClassificationConfig()

        assert classify_path("migrations/001_init.sql", config) == PathClassification.third_party

    def test_classify_unknown_path(self):
        """Test paths not matching any category return unknown."""
        config = PathClassificationConfig()

        assert classify_path("random/file.py", config) == PathClassification.unknown

    def test_classify_path_with_subdirectories(self):
        """Test path classification works with nested directories."""
        config = PathClassificationConfig()

        # Should match even in subdirectories
        assert classify_path("project/third_party/lib/file.py", config) == PathClassification.third_party
        assert classify_path("project/src/main.py", config) == PathClassification.runtime

    def test_classify_path_priority_order(self):
        """Test third_party has highest priority."""
        config = PathClassificationConfig()

        # third_party should win over runtime even if path contains both
        # (e.g., third_party might vendor src/ directories)
        assert classify_path("third_party/project/src/main.py", config) == PathClassification.third_party
