"""Virtual filesystem for Deep Agents with namespaced access control.

Provides:
- /repo/* - read-only access to project repository
- /memories/* - writable access to agent memory storage

Security: Prevents path traversal attacks using resolve().relative_to() validation.
"""

from pathlib import Path
from typing import Tuple

# Base path for project data storage
DATA_BASE_PATH = Path("data/projects")


class ProjectFilesystem:
    """Virtual filesystem with /repo and /memories namespaces.

    Maps virtual paths to physical filesystem locations with access control:
    - /repo/* -> {project_root}/repo (read-only)
    - /memories/* -> {project_root}/memories (writable)

    Security features:
    - Path traversal protection using resolve().relative_to()
    - Namespace validation
    - Auto-creates memories directory
    """

    def __init__(self, project_id: str):
        """Initialize filesystem for a project.

        Args:
            project_id: Unique identifier for the project
        """
        self.project_id = project_id
        self.project_root = DATA_BASE_PATH / project_id
        self.repo_root = self.project_root / "repo"
        self.memory_root = self.project_root / "memories"

        # Ensure memories directory exists
        self.memory_root.mkdir(parents=True, exist_ok=True)

    def resolve_path(self, virtual_path: str) -> Tuple[Path, bool]:
        """Map virtual path to physical path with access control.

        Args:
            virtual_path: Virtual path starting with /repo/ or /memories/

        Returns:
            Tuple of (physical_path, is_writable)

        Raises:
            ValueError: If path is invalid or attempts path traversal

        Security:
            Validates resolved paths stay within namespace roots to prevent
            path traversal attacks (e.g., /repo/../../../etc/passwd).
        """
        if virtual_path.startswith("/repo/"):
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
        # Resolve both paths and verify the physical path is within the namespace root
        try:
            physical_path.resolve().relative_to(root_to_check.resolve())
        except ValueError:
            raise ValueError(
                f"Path traversal detected - path escapes namespace: {virtual_path}"
            )

        return physical_path, is_writable
