"""Git operations service for quick_hack."""

import asyncio
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from collections import Counter

from git import Repo, GitCommandError

from config import settings
from models.schemas import RepoInfo


# In-memory store for repos (replace with SQLite later)
_repos: dict[str, RepoInfo] = {}
_delete_tasks: dict[str, asyncio.Task[None]] = {}

# Timeout for git operations (clone, pull, etc.)
GIT_OPERATION_TIMEOUT = 1800  # 30 minutes for large repos


async def _delete_repo_dir_background(*, repo_id: str, repo_path: Path) -> None:
    try:
        root = settings.repos_dir.resolve()
        resolved = repo_path.resolve()

        # Safety: only delete inside the configured repos_dir.
        try:
            resolved.relative_to(root)
        except ValueError:
            print(f"[GitService] Refusing to delete path outside repos_dir: {resolved}")
            return

        if not resolved.exists():
            return

        print(f"[GitService] Background deleting repo files at {resolved}")
        await asyncio.to_thread(shutil.rmtree, resolved)
        print(f"[GitService] Background deleted repo files at {resolved}")
    except Exception as e:
        print(f"[GitService] Background deletion failed for repo {repo_id}: {e}")
    finally:
        _delete_tasks.pop(repo_id, None)


# File extension to language mapping
EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sol": "solidity",
    ".vue": "vue",
    ".svelte": "svelte",
}


def detect_languages(repo_path: Path) -> list[str]:
    """Detect programming languages in repository."""
    extensions = Counter()

    for root, _, files in os.walk(repo_path):
        # Skip hidden and common non-code directories
        if any(skip in root for skip in [".git", "node_modules", "venv", "__pycache__", ".next"]):
            continue

        for file in files:
            ext = Path(file).suffix.lower()
            if ext in EXTENSION_LANGUAGE_MAP:
                extensions[ext] += 1

    # Return top languages by file count
    top_extensions = extensions.most_common(5)
    languages = []
    for ext, _ in top_extensions:
        lang = EXTENSION_LANGUAGE_MAP.get(ext)
        if lang and lang not in languages:
            languages.append(lang)

    return languages


def count_files(repo_path: Path) -> int:
    """Count total files in repository (excluding .git)."""
    count = 0
    for root, _, files in os.walk(repo_path):
        if ".git" not in root:
            count += len(files)
    return count


async def clone_repo(url: str, branch: Optional[str] = None) -> RepoInfo:
    """Clone a git repository."""
    repo_id = str(uuid.uuid4())[:8]

    # Extract repo name from URL
    repo_name = url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    repo_path = settings.repos_dir / f"{repo_name}_{repo_id}"

    try:
        # Clone the repository
        clone_args = {"depth": 1}  # Shallow clone for speed
        if branch:
            clone_args["branch"] = branch

        try:
            repo = await asyncio.wait_for(
                asyncio.to_thread(Repo.clone_from, url, repo_path, **clone_args),
                timeout=GIT_OPERATION_TIMEOUT,
            )
        except asyncio.TimeoutError:
            # Clean up on timeout
            if repo_path.exists():
                print(f"[GitService] Cleaning up timed out clone at {repo_path}")
                await asyncio.to_thread(shutil.rmtree, repo_path)
            raise ValueError(f"Clone operation timed out after {GIT_OPERATION_TIMEOUT} seconds")

        # Get actual branch name
        actual_branch = branch or repo.active_branch.name

        # Detect languages and count files
        languages = detect_languages(repo_path)
        file_count = count_files(repo_path)

        repo_info = RepoInfo(
            id=repo_id,
            url=url,
            name=repo_name,
            branch=actual_branch,
            path=str(repo_path.absolute()),
            cloned_at=datetime.utcnow(),
            languages=languages,
            file_count=file_count,
        )

        # Store in memory
        _repos[repo_id] = repo_info

        return repo_info

    except GitCommandError as e:
        # Clean up on failure
        if repo_path.exists():
            print(f"[GitService] Cleaning up failed clone at {repo_path}")
            await asyncio.to_thread(shutil.rmtree, repo_path)
        raise ValueError(f"Failed to clone repository: {e}")


async def get_repo(repo_id: str) -> Optional[RepoInfo]:
    """Get repository info by ID."""
    return _repos.get(repo_id)


async def list_repos() -> list[RepoInfo]:
    """List all cloned repositories."""
    return list(_repos.values())


async def delete_repo(repo_id: str) -> bool:
    """Delete a cloned repository."""
    repo_info = _repos.get(repo_id)
    if not repo_info:
        return False

    # Remove from memory
    del _repos[repo_id]

    # Remove from disk asynchronously so the API returns quickly for large repos.
    repo_path = Path(repo_info.path)
    if repo_id not in _delete_tasks and repo_path.exists():
        _delete_tasks[repo_id] = asyncio.create_task(
            _delete_repo_dir_background(repo_id=repo_id, repo_path=repo_path),
        )

    return True


async def refresh_repo(repo_id: str) -> Optional[RepoInfo]:
    """Pull latest changes for a repository."""
    repo_info = _repos.get(repo_id)
    if not repo_info:
        return None

    repo_path = Path(repo_info.path)
    if not repo_path.exists():
        return None

    try:
        repo = Repo(repo_path)
        origin = repo.remotes.origin
        try:
            await asyncio.wait_for(
                asyncio.to_thread(origin.pull),
                timeout=GIT_OPERATION_TIMEOUT,
            )
        except asyncio.TimeoutError:
            raise ValueError(f"Pull operation timed out after {GIT_OPERATION_TIMEOUT} seconds")

        # Update file count
        repo_info.file_count = count_files(repo_path)

        return repo_info

    except GitCommandError as e:
        raise ValueError(f"Failed to refresh repository: {e}")
