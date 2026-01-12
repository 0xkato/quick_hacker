import pytest
import subprocess
from pathlib import Path
from services.git_head_tracker import GitHeadTracker


class TestGitHeadTracker:
    def test_get_head_in_git_repo(self, tmp_path):
        # Create a git repo
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_path, check=True)

        # Create initial commit
        (repo_path / "file.txt").write_text("content")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=repo_path, check=True, capture_output=True)

        # Get HEAD
        tracker = GitHeadTracker(str(repo_path))
        head = tracker.get_current_head()

        # Verify it's a valid SHA-1 hash
        assert head is not None
        assert len(head) == 40  # SHA-1 is 40 hex chars
        assert all(c in "0123456789abcdef" for c in head)

    def test_get_head_returns_none_for_non_git_directory(self, tmp_path):
        tracker = GitHeadTracker(str(tmp_path))
        head = tracker.get_current_head()
        assert head is None

    def test_head_changes_after_commit(self, tmp_path):
        # Create a git repo
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_path, check=True)

        # First commit
        (repo_path / "file.txt").write_text("content1")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "first"], cwd=repo_path, check=True, capture_output=True)

        tracker = GitHeadTracker(str(repo_path))
        head1 = tracker.get_current_head()

        # Second commit
        (repo_path / "file.txt").write_text("content2")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "second"], cwd=repo_path, check=True, capture_output=True)

        head2 = tracker.get_current_head()

        assert head1 != head2  # HEAD should change after commit
