"""Git HEAD tracking for cache invalidation."""
import subprocess
from pathlib import Path
from typing import Optional


class GitHeadTracker:
    """Track git HEAD for cache invalidation.

    When repo state changes (new commits), cache keys should change
    to prevent serving stale data.
    """

    def __init__(self, repo_path: str):
        """Initialize tracker.

        Args:
            repo_path: Path to git repository root
        """
        self.repo_path = Path(repo_path).resolve()

    def get_current_head(self) -> Optional[str]:
        """Get current git HEAD hash.

        Returns:
            40-character SHA-1 hash if in git repo, None otherwise
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, NotADirectoryError, PermissionError):
            # Not a git repo, git not installed, timeout, or permission error
            return None
