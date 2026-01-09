"""Session hibernation service for pause/resume functionality."""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from models.schemas import (
    SessionSnapshot,
    SnapshotInfo,
)


class SessionService:
    """Service for managing session snapshots."""

    SNAPSHOT_DIR = ".quickhack"
    SNAPSHOT_FILE = "session-snapshot.json"

    def get_snapshot_path(self, project_path: str) -> str:
        """Get the full path to the snapshot file."""
        return os.path.join(project_path, self.SNAPSHOT_DIR, self.SNAPSHOT_FILE)

    def save_snapshot(self, project_path: str, snapshot: SessionSnapshot) -> str:
        """Save a snapshot to disk."""
        snapshot_dir = os.path.join(project_path, self.SNAPSHOT_DIR)
        os.makedirs(snapshot_dir, exist_ok=True)

        snapshot_path = self.get_snapshot_path(project_path)

        # Serialize with datetime handling
        data = snapshot.model_dump(mode="json")

        with open(snapshot_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return snapshot_path

    def load_snapshot(self, project_path: str) -> Optional[SessionSnapshot]:
        """Load a snapshot from disk if it exists."""
        snapshot_path = self.get_snapshot_path(project_path)

        if not os.path.exists(snapshot_path):
            return None

        try:
            with open(snapshot_path) as f:
                data = json.load(f)
            return SessionSnapshot(**data)
        except (json.JSONDecodeError, Exception) as e:
            print(f"Failed to load snapshot: {e}")
            return None

    def get_snapshot_info(self, project_path: str) -> Optional[SnapshotInfo]:
        """Get metadata about an existing snapshot."""
        snapshot = self.load_snapshot(project_path)
        if not snapshot:
            return None

        pending_count = sum(len(a.pending_files) for a in snapshot.agents)

        return SnapshotInfo(
            timestamp=snapshot.timestamp,
            agent_count=len(snapshot.agents),
            findings_count=len(snapshot.findings),
            pending_files=pending_count,
        )

    def delete_snapshot(self, project_path: str) -> bool:
        """Delete a snapshot file."""
        snapshot_path = self.get_snapshot_path(project_path)

        if os.path.exists(snapshot_path):
            os.remove(snapshot_path)
            return True
        return False

    def snapshot_exists(self, project_path: str) -> bool:
        """Check if a snapshot exists."""
        return os.path.exists(self.get_snapshot_path(project_path))


# Singleton instance
session_service = SessionService()
