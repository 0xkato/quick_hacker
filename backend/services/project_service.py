"""
Project/Workspace management service for quick_hack.

Projects organize cloned repositories into workspaces.
Each project contains a single cloned repository.
"""

import asyncio
import json
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Literal
from pydantic import BaseModel, Field

from config import settings


ThreatModel = Literal["A", "AB", "ABC"]
PROFILE_MAPPING_VERSION = 1
INPUT_CHANNEL_SEMANTICS_VERSION = 1
PROMPT_THREAT_MODEL_BLOCK_VERSION = 1


def _default_threat_model_profile(threat_model: ThreatModel):
    from models.threat_model_profile import preset_to_profile

    return preset_to_profile(threat_model)


class Project(BaseModel):
    """A project/workspace containing a cloned repository."""
    id: str
    name: str
    description: str = ""
    threat_model: ThreatModel = "AB"  # A, AB, or ABC
    threat_model_preset: Optional[ThreatModel] = None
    threat_model_profile: Optional[dict] = None
    profile_source: Optional[Literal["preset", "custom", "migrated"]] = None
    profile_review_status: Optional[Literal["unreviewed", "reviewed"]] = None
    profile_reviewed_at: Optional[datetime] = None
    profile_mapping_version: int = PROFILE_MAPPING_VERSION
    input_channel_semantics_version: int = INPUT_CHANNEL_SEMANTICS_VERSION
    prompt_threat_model_block_version: int = PROMPT_THREAT_MODEL_BLOCK_VERSION
    repo_url: Optional[str] = None
    repo_name: Optional[str] = None
    repo_branch: Optional[str] = None
    languages: list[str] = []
    file_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_accessed: datetime = Field(default_factory=datetime.utcnow)
    is_cloned: bool = False
    path: str = ""
    validation_profile: Optional[dict] = None

    def get_validation_profile(self) -> "ValidationProfile":
        """Get validation profile as a ValidationProfile object."""
        from models.validation_profile import ValidationProfile
        if self.validation_profile is None:
            return ValidationProfile()
        return ValidationProfile.model_validate(self.validation_profile)

    def ensure_threat_model_profile(self, *, source: Literal["preset", "custom", "migrated"]) -> None:
        # Hard-invariant: threat_model and threat_model_preset must match.
        self.threat_model_preset = self.threat_model

        if self.threat_model_profile is None:
            self.threat_model_profile = _default_threat_model_profile(self.threat_model).model_dump(mode="json")

        if self.profile_source is None:
            self.profile_source = source
        if self.profile_review_status is None:
            self.profile_review_status = "unreviewed"


class ProjectService:
    """Service for managing projects/workspaces."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.projects_dir = self.data_dir / "projects"
        self.projects_file = self.data_dir / "projects.json"
        self._projects: dict[str, Project] = {}
        self._current_project_id: Optional[str] = None
        # Track background deletions so we don't spawn duplicates.
        self._delete_tasks: dict[str, asyncio.Task[None]] = {}

    def _trash_project_path(self, project_id: str) -> Path:
        trash_dir = self.data_dir / ".trash" / "projects"
        suffix = uuid.uuid4().hex[:8]
        return trash_dir / f"{project_id}-{suffix}"

    async def _delete_project_dir_background(self, *, project_id: str, project_path: Path) -> None:
        try:
            projects_root = self.projects_dir.resolve()
            resolved = project_path.resolve()

            # Safety: only delete paths inside the projects directory.
            try:
                resolved.relative_to(projects_root)
            except ValueError:
                print(f"[ProjectService] Refusing to delete path outside projects_dir: {resolved}")
                return

            if not resolved.exists():
                return

            # Best-effort: move to trash first so deletion can't interfere with project management.
            delete_target = resolved
            try:
                trash_path = self._trash_project_path(project_id)
                trash_path.parent.mkdir(parents=True, exist_ok=True)
                resolved.rename(trash_path)
                delete_target = trash_path
            except Exception:
                delete_target = resolved

            print(f"[ProjectService] Background deleting project files at {delete_target}")
            await asyncio.to_thread(shutil.rmtree, delete_target)
            print(f"[ProjectService] Background deleted project files at {delete_target}")
        except Exception as e:
            print(f"[ProjectService] Background deletion failed for project {project_id}: {e}")
        finally:
            self._delete_tasks.pop(project_id, None)

    async def initialize(self):
        """Initialize the project service."""
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        await self._load_projects()

    async def _load_projects(self):
        """Load projects from disk."""
        if self.projects_file.exists():
            try:
                with open(self.projects_file, 'r') as f:
                    data = json.load(f)
                    for proj_data in data.get("projects", []):
                        proj = Project(**proj_data)
                        if proj.threat_model_preset is None or proj.threat_model_profile is None:
                            proj.ensure_threat_model_profile(source="migrated")
                        self._projects[proj.id] = proj
                    self._current_project_id = data.get("current_project_id")
            except Exception as e:
                print(f"Error loading projects: {e}")

    async def _save_projects(self):
        """Save projects to disk."""
        try:
            data = {
                "projects": [p.model_dump(mode='json') for p in self._projects.values()],
                "current_project_id": self._current_project_id,
            }
            with open(self.projects_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving projects: {e}")

    async def create_project(self, name: str, description: str = "") -> Project:
        """Create a new empty project."""
        import uuid
        project_id = str(uuid.uuid4())[:8]

        # Create project directory
        project_path = self.projects_dir / project_id
        project_path.mkdir(parents=True, exist_ok=True)

        project = Project(
            id=project_id,
            name=name,
            description=description,
            path=str(project_path.absolute()),
        )
        project.ensure_threat_model_profile(source="preset")

        self._projects[project_id] = project
        await self._save_projects()

        return project

    async def list_projects(self) -> list[Project]:
        """List all projects."""
        return list(self._projects.values())

    async def get_project(self, project_id: str) -> Optional[Project]:
        """Get a project by ID."""
        return self._projects.get(project_id)

    async def get_current_project(self) -> Optional[Project]:
        """Get the currently active project."""
        if self._current_project_id:
            return self._projects.get(self._current_project_id)
        return None

    async def enter_project(self, project_id: str) -> Optional[Project]:
        """Enter/select a project as the current workspace."""
        project = self._projects.get(project_id)
        if not project:
            return None

        self._current_project_id = project_id
        project.last_accessed = datetime.utcnow()
        await self._save_projects()

        return project

    async def exit_project(self) -> bool:
        """Exit the current project."""
        if self._current_project_id:
            self._current_project_id = None
            await self._save_projects()
            return True
        return False

    async def is_in_project(self) -> bool:
        """Check if currently inside a project."""
        return self._current_project_id is not None

    async def clone_into_project(
        self,
        project_id: str,
        url: str,
        branch: Optional[str] = None
    ) -> Project:
        """Clone a repository into a project."""
        from git import Repo, GitCommandError
        from services.git_service import detect_languages, count_files

        project = self._projects.get(project_id)
        if not project:
            raise ValueError(f"Project not found: {project_id}")

        if project.is_cloned:
            raise ValueError("Project already has a cloned repository")

        # Extract repo name from URL
        repo_name = url.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        project_path = Path(project.path)
        repo_path = project_path / repo_name

        try:
            # Clone the repository
            clone_args = {"depth": 1}
            if branch:
                clone_args["branch"] = branch

            repo = Repo.clone_from(url, repo_path, **clone_args)
            actual_branch = branch or repo.active_branch.name

            # Update project info
            project.repo_url = url
            project.repo_name = repo_name
            project.repo_branch = actual_branch
            project.languages = detect_languages(repo_path)
            project.file_count = count_files(repo_path)
            project.is_cloned = True
            project.ensure_threat_model_profile(source="preset")

            await self._save_projects()
            return project

        except GitCommandError as e:
            if repo_path.exists():
                print(f"[ProjectService] Cleaning up failed clone at {repo_path}")
                await asyncio.to_thread(shutil.rmtree, repo_path)
            raise ValueError(f"Failed to clone repository: {e}")

    async def delete_project(self, project_id: str) -> bool:
        """Delete a project and its contents."""
        project = self._projects.get(project_id)
        if not project:
            return False

        # If this is the current project, exit first
        if self._current_project_id == project_id:
            self._current_project_id = None

        # Remove from memory
        del self._projects[project_id]
        await self._save_projects()

        # Remove from disk asynchronously to avoid blocking the API for large repos.
        project_path = Path(project.path)
        if project_id not in self._delete_tasks and project_path.exists():
            self._delete_tasks[project_id] = asyncio.create_task(
                self._delete_project_dir_background(project_id=project_id, project_path=project_path),
            )

        return True

    async def update_project(
        self,
        project_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        threat_model: Optional[ThreatModel] = None,
    ) -> Optional[Project]:
        """Update project metadata."""
        project = self._projects.get(project_id)
        if not project:
            return None

        if name is not None:
            project.name = name
        if description is not None:
            project.description = description
        if threat_model is not None:
            project.threat_model = threat_model
            project.ensure_threat_model_profile(source="preset")

        await self._save_projects()
        return project

    async def refresh_project(self, project_id: str) -> Optional[Project]:
        """Pull latest changes for a project's repository."""
        from git import Repo, GitCommandError
        from services.git_service import count_files

        project = self._projects.get(project_id)
        if not project or not project.is_cloned:
            return None

        project_path = Path(project.path)
        repo_path = project_path / project.repo_name if project.repo_name else project_path

        if not repo_path.exists():
            return None

        try:
            repo = Repo(repo_path)
            origin = repo.remotes.origin
            origin.pull()

            project.file_count = count_files(repo_path)
            project.last_accessed = datetime.utcnow()
            await self._save_projects()

            return project

        except GitCommandError as e:
            raise ValueError(f"Failed to refresh repository: {e}")

    def get_project_repo_path(self, project_id: str) -> Optional[str]:
        """Get the repository path for a project."""
        project = self._projects.get(project_id)
        if not project or not project.is_cloned or not project.repo_name:
            return None

        repo_path = Path(project.path) / project.repo_name
        if repo_path.exists():
            return str(repo_path.absolute())
        return None

    def get_project_path(self, project_id: str) -> Optional[str]:
        """Get the path of a project by ID (synchronous)."""
        project = self._projects.get(project_id)
        if project:
            return project.path
        return None

    def get_current_project_path(self) -> Optional[str]:
        """Get the path of the currently active project (synchronous)."""
        if not self._current_project_id:
            return None
        project = self._projects.get(self._current_project_id)
        if project:
            return project.path
        return None

    def get_current_project_sync(self) -> Optional[Project]:
        """Get the currently active project (synchronous)."""
        if self._current_project_id:
            return self._projects.get(self._current_project_id)
        return None


# Global instance
project_service = ProjectService(os.environ.get("DATA_DIR", "data"))
