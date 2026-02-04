"""Virtual filesystem for Deep Agents with namespaced access control.

Provides:
- /repo/* - read-only access to project repository
- /memories/* - writable access to agent memory storage

Security: Prevents path traversal attacks using resolve().relative_to() validation.
"""

import json
import os
from pathlib import Path
from typing import Tuple, Optional, Union
from datetime import datetime


# Base path for project data storage
DATA_BASE_PATH = Path("data/projects")


class MemoriesFilesystem:
    """Virtual filesystem with /repo and /memories namespaces.

    Provides a secure, namespaced filesystem for agent I/O:
    - /repo/* -> {repo_path} (read-only, the actual repository being scanned)
    - /memories/* -> {data_path}/memories (writable, agent artifacts)

    Physical storage: data/projects/{project_id}/memories/

    Standard directories in /memories/:
    - overseer/: Wave syntheses, campaign state, final report
    - foundation/: RepoProfiler, ScopeMapper, ThreatModeler outputs
    - signals/: Hunter outputs (sinks.json, entrypoints.json)
    - scopes/: Per-scope summaries and signals
    - traces/: DataflowTracer outputs
    - triage/: Triage verdicts
    - audits/: Auditor outputs
    - findings/: Confirmed findings
    - waves/: Per-wave outputs (wave_N/)

    Security features:
    - Path traversal protection using resolve().relative_to()
    - Namespace validation (must start with /repo/ or /memories/)
    - /repo/ is read-only, /memories/ is writable
    - Auto-creates memories directory structure on init

    Example:
        >>> fs = MemoriesFilesystem("project-123", "/path/to/repo")
        >>> content = fs.read_file("/repo/src/main.py")  # Read from repo
        >>> fs.write_json("/memories/signals/sinks.json", data)  # Write artifact
        >>> files = fs.ls("/memories/")  # List directories
    """

    def __init__(self, project_id: str, repo_path: Optional[str] = None):
        """Initialize filesystem for a project.

        Args:
            project_id: Unique identifier for the project
            repo_path: Path to the repository being scanned (optional, can be set later)
        """
        self.project_id = project_id
        self.data_root = DATA_BASE_PATH / project_id
        self.memory_root = self.data_root / "memories"
        self.repo_root = Path(repo_path) if repo_path else None

        # Ensure memories directory structure exists
        self._init_memories_structure()

    def _init_memories_structure(self):
        """Create the standard /memories directory structure."""
        directories = [
            self.memory_root,
            self.memory_root / "overseer",
            self.memory_root / "scopes",
            self.memory_root / "traces",
            self.memory_root / "triage",
            self.memory_root / "audits",
            self.memory_root / "findings",
        ]
        for d in directories:
            d.mkdir(parents=True, exist_ok=True)

    def set_repo_path(self, repo_path: str):
        """Set the repository path (for late binding)."""
        self.repo_root = Path(repo_path)

    def resolve_path(self, virtual_path: str) -> Tuple[Path, bool]:
        """Map virtual path to physical path with access control.

        Args:
            virtual_path: Virtual path starting with /repo/ or /memories/

        Returns:
            Tuple of (physical_path, is_writable)

        Raises:
            ValueError: If path is invalid or attempts path traversal
        """
        if virtual_path.startswith("/repo/"):
            if self.repo_root is None:
                raise ValueError("Repository path not set")
            relative = virtual_path[6:]  # Strip "/repo/"
            physical_path = self.repo_root / relative
            is_writable = False
            root_to_check = self.repo_root
        elif virtual_path.startswith("/memories/"):
            relative = virtual_path[10:]  # Strip "/memories/"
            physical_path = self.memory_root / relative
            is_writable = True
            root_to_check = self.memory_root
        else:
            raise ValueError(
                f"Path must start with /repo/ or /memories/: {virtual_path}"
            )

        # SECURITY: Prevent path traversal attacks
        try:
            physical_path.resolve().relative_to(root_to_check.resolve())
        except ValueError:
            raise ValueError(
                f"Path traversal detected - path escapes namespace: {virtual_path}"
            )

        return physical_path, is_writable

    # File Operations

    def exists(self, virtual_path: str) -> bool:
        """Check if a path exists."""
        try:
            physical_path, _ = self.resolve_path(virtual_path)
            return physical_path.exists()
        except ValueError:
            return False

    def is_file(self, virtual_path: str) -> bool:
        """Check if path is a file."""
        try:
            physical_path, _ = self.resolve_path(virtual_path)
            return physical_path.is_file()
        except ValueError:
            return False

    def is_dir(self, virtual_path: str) -> bool:
        """Check if path is a directory."""
        try:
            physical_path, _ = self.resolve_path(virtual_path)
            return physical_path.is_dir()
        except ValueError:
            return False

    def read_file(self, virtual_path: str) -> str:
        """Read file contents as string.

        Args:
            virtual_path: Path to file

        Returns:
            File contents as string

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path is invalid
        """
        physical_path, _ = self.resolve_path(virtual_path)
        if not physical_path.exists():
            raise FileNotFoundError(f"File not found: {virtual_path}")
        if not physical_path.is_file():
            raise ValueError(f"Path is not a file: {virtual_path}")
        return physical_path.read_text(encoding="utf-8")

    def write_file(self, virtual_path: str, content: str) -> str:
        """Write content to file.

        Args:
            virtual_path: Path to file (must be in /memories/)
            content: Content to write

        Returns:
            The virtual path written to

        Raises:
            PermissionError: If path is not writable
            ValueError: If path is invalid
        """
        physical_path, is_writable = self.resolve_path(virtual_path)
        if not is_writable:
            raise PermissionError(f"Path is read-only: {virtual_path}")

        # Ensure parent directory exists
        physical_path.parent.mkdir(parents=True, exist_ok=True)

        physical_path.write_text(content, encoding="utf-8")
        return virtual_path

    def read_json(self, virtual_path: str) -> Union[dict, list]:
        """Read and parse JSON file.

        Args:
            virtual_path: Path to JSON file

        Returns:
            Parsed JSON as dict or list

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file is not valid JSON
        """
        content = self.read_file(virtual_path)
        return json.loads(content)

    def write_json(self, virtual_path: str, data: Union[dict, list], indent: int = 2) -> str:
        """Write data as JSON file.

        Args:
            virtual_path: Path to file (must be in /memories/)
            data: Data to serialize as JSON
            indent: JSON indentation (default 2)

        Returns:
            The virtual path written to
        """
        content = json.dumps(data, indent=indent, default=str)
        return self.write_file(virtual_path, content)

    def append_file(self, virtual_path: str, content: str) -> str:
        """Append content to file.

        Args:
            virtual_path: Path to file (must be in /memories/)
            content: Content to append

        Returns:
            The virtual path written to
        """
        physical_path, is_writable = self.resolve_path(virtual_path)
        if not is_writable:
            raise PermissionError(f"Path is read-only: {virtual_path}")

        physical_path.parent.mkdir(parents=True, exist_ok=True)

        with open(physical_path, "a", encoding="utf-8") as f:
            f.write(content)
        return virtual_path

    def ls(self, virtual_path: str) -> list[str]:
        """List directory contents.

        Args:
            virtual_path: Path to directory

        Returns:
            List of filenames in directory

        Raises:
            FileNotFoundError: If directory doesn't exist
            ValueError: If path is not a directory
        """
        physical_path, _ = self.resolve_path(virtual_path)
        if not physical_path.exists():
            raise FileNotFoundError(f"Directory not found: {virtual_path}")
        if not physical_path.is_dir():
            raise ValueError(f"Path is not a directory: {virtual_path}")

        return sorted([p.name for p in physical_path.iterdir()])

    def ls_recursive(self, virtual_path: str, pattern: str = "*") -> list[str]:
        """List files recursively with glob pattern.

        Args:
            virtual_path: Path to directory
            pattern: Glob pattern (default "*")

        Returns:
            List of relative paths matching pattern
        """
        physical_path, _ = self.resolve_path(virtual_path)
        if not physical_path.exists():
            raise FileNotFoundError(f"Directory not found: {virtual_path}")

        results = []
        for p in physical_path.rglob(pattern):
            if p.is_file():
                rel = p.relative_to(physical_path)
                results.append(str(rel))
        return sorted(results)

    def mkdir(self, virtual_path: str) -> str:
        """Create directory (and parents if needed).

        Args:
            virtual_path: Path to directory (must be in /memories/)

        Returns:
            The virtual path created
        """
        physical_path, is_writable = self.resolve_path(virtual_path)
        if not is_writable:
            raise PermissionError(f"Path is read-only: {virtual_path}")

        physical_path.mkdir(parents=True, exist_ok=True)
        return virtual_path

    def delete(self, virtual_path: str) -> bool:
        """Delete a file (not directories).

        Args:
            virtual_path: Path to file (must be in /memories/)

        Returns:
            True if deleted, False if didn't exist
        """
        physical_path, is_writable = self.resolve_path(virtual_path)
        if not is_writable:
            raise PermissionError(f"Path is read-only: {virtual_path}")

        if physical_path.exists() and physical_path.is_file():
            physical_path.unlink()
            return True
        return False

    # Convenience methods for common paths

    def get_scope_path(self, scope_id: str) -> str:
        """Get the /memories/scopes/{scope_id}/ path."""
        return f"/memories/scopes/{scope_id}"

    def get_trace_path(self, signal_id: str) -> str:
        """Get the /memories/traces/{signal_id}/ path."""
        return f"/memories/traces/{signal_id}"

    def get_triage_path(self, signal_id: str) -> str:
        """Get the /memories/triage/{signal_id}/ path."""
        return f"/memories/triage/{signal_id}"

    def get_audit_path(self, signal_id: str) -> str:
        """Get the /memories/audits/{signal_id}/ path."""
        return f"/memories/audits/{signal_id}"

    def get_finding_path(self, finding_id: str) -> str:
        """Get the /memories/findings/{finding_id}/ path."""
        return f"/memories/findings/{finding_id}"

    def get_wave_synthesis_path(self, wave_id: int) -> str:
        """Get the wave synthesis path."""
        return f"/memories/overseer/wave_{wave_id}_synthesis.md"

    def get_wave_dispatch_path(self, wave_id: int) -> str:
        """Get the wave dispatch path."""
        return f"/memories/overseer/wave_{wave_id}_dispatch.json"

    def get_campaign_state_path(self) -> str:
        """Get the campaign state path."""
        return "/memories/overseer/campaign_state.json"

    # Artifact helpers

    def save_scope_summary(self, scope_id: str, summary: str) -> str:
        """Save a scope summary."""
        path = f"{self.get_scope_path(scope_id)}/summary.md"
        return self.write_file(path, summary)

    def save_scope_signals(self, scope_id: str, signals: list[dict]) -> str:
        """Save scope signals."""
        path = f"{self.get_scope_path(scope_id)}/signals.json"
        return self.write_json(path, {"signals": signals})

    def save_scope_entrypoints(self, scope_id: str, entrypoints: list[dict]) -> str:
        """Save scope entrypoints."""
        path = f"{self.get_scope_path(scope_id)}/entrypoints.json"
        return self.write_json(path, {"entrypoints": entrypoints})

    def save_wave_synthesis(self, wave_id: int, synthesis: str) -> str:
        """Save wave synthesis document."""
        return self.write_file(self.get_wave_synthesis_path(wave_id), synthesis)

    def save_wave_dispatch(self, wave_id: int, dispatch: dict) -> str:
        """Save wave dispatch plan."""
        return self.write_json(self.get_wave_dispatch_path(wave_id), dispatch)

    def save_campaign_state(self, state: dict) -> str:
        """Save campaign state."""
        return self.write_json(self.get_campaign_state_path(), state)

    def load_campaign_state(self) -> Optional[dict]:
        """Load campaign state if it exists."""
        path = self.get_campaign_state_path()
        if self.exists(path):
            return self.read_json(path)
        return None


# Backward compatibility alias
ProjectFilesystem = MemoriesFilesystem
