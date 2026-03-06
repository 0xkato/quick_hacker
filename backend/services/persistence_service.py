"""
Persistence Service - Saves and loads agent state for resumption.

Enables:
- State snapshots on pause/stop
- Resume from saved state after backend restart
- Investigation continuity
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
import uuid

from models.observability import AgentStateSnapshot
from models.schemas import WSMessage, WSMessageType


# State files directory
STATE_DIR = Path(os.environ.get("DATA_DIR", "data")) / "agent_states"


class PersistenceService:
    """Manages agent state persistence to disk."""

    def __init__(self):
        self._ensure_state_dir()
        # WebSocket broadcast callback
        self._broadcast_callback = None

    def _ensure_state_dir(self):
        """Ensure the state directory exists."""
        STATE_DIR.mkdir(parents=True, exist_ok=True)

    def set_broadcast_callback(self, callback) -> None:
        """Set the callback for broadcasting messages via WebSocket."""
        self._broadcast_callback = callback

    def _broadcast(self, message: WSMessage) -> None:
        """Broadcast message to WebSocket clients."""
        if self._broadcast_callback:
            try:
                self._broadcast_callback(message)
            except Exception as e:
                print(f"[Persistence] Broadcast error: {e}")

    def _get_state_path(self, agent_id: str) -> Path:
        """Get the path for an agent's state file."""
        return STATE_DIR / f"{agent_id}.json"

    # Valid agent IDs are UUIDs or UUID prefixes (hex + hyphens only)
    _VALID_AGENT_ID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{3}')

    def save_agent_state(self, snapshot: AgentStateSnapshot) -> str:
        """
        Save an agent state snapshot to disk.

        Returns the path to the saved file.
        """
        agent_id = str(snapshot.agent_id)
        if not self._VALID_AGENT_ID.match(agent_id):
            print(f"[Persistence] Rejecting invalid agent_id: {agent_id[:80]}")
            return ""

        self._ensure_state_dir()

        state_path = self._get_state_path(agent_id)

        # Convert to dict and serialize
        state_data = snapshot.model_dump(mode='json')

        with open(state_path, 'w') as f:
            json.dump(state_data, f, indent=2, default=str)

        print(f"[Persistence] Saved state for agent {snapshot.agent_id} to {state_path}")

        # Broadcast state sync message
        self._broadcast(WSMessage(
            type=WSMessageType.STATE_SYNC,
            agent_id=snapshot.agent_id,
            data={
                "action": "saved",
                "snapshot_id": snapshot.id,
                "path": str(state_path),
                "timestamp": datetime.utcnow().isoformat(),
            },
        ))

        return str(state_path)

    def load_agent_state(self, agent_id: str) -> Optional[AgentStateSnapshot]:
        """
        Load an agent state from disk.

        Returns None if no state file exists.
        """
        state_path = self._get_state_path(agent_id)

        if not state_path.exists():
            return None

        try:
            with open(state_path, 'r') as f:
                state_data = json.load(f)

            return AgentStateSnapshot(**state_data)
        except Exception as e:
            print(f"[Persistence] Failed to load state for {agent_id}: {e}")
            return None

    def delete_agent_state(self, agent_id: str) -> bool:
        """
        Delete an agent's saved state.

        Returns True if state was deleted, False if no state existed.
        """
        state_path = self._get_state_path(agent_id)

        if state_path.exists():
            state_path.unlink()
            print(f"[Persistence] Deleted state for agent {agent_id}")
            return True
        return False

    def list_saved_states(self) -> list[dict]:
        """
        List all saved agent states.

        Returns a list of state metadata (not full state data).
        """
        self._ensure_state_dir()

        states = []
        for state_file in STATE_DIR.glob("*.json"):
            # Skip files with invalid agent IDs (e.g. mock leakage)
            if not self._VALID_AGENT_ID.match(state_file.stem):
                continue
            try:
                with open(state_file, 'r') as f:
                    state_data = json.load(f)

                states.append({
                    "agent_id": state_data.get("agent_id"),
                    "snapshot_id": state_data.get("id"),
                    "created_at": state_data.get("created_at"),
                    "status": state_data.get("status"),
                    "agent_type": state_data.get("agent_type"),
                    "repo_id": state_data.get("repo_id"),
                    "files_analyzed": state_data.get("files_analyzed", 0),
                    "total_files": state_data.get("total_files", 0),
                    "findings_count": len(state_data.get("findings", [])),
                    "total_api_calls": state_data.get("total_api_calls", 0),
                    "file_path": str(state_file),
                })
            except Exception as e:
                print(f"[Persistence] Error reading {state_file}: {e}")

        # Sort by creation time (newest first)
        states.sort(key=lambda s: s.get("created_at", ""), reverse=True)
        return states

    def get_state_summary(self, agent_id: str) -> Optional[dict]:
        """
        Get a summary of a saved state without loading full data.

        Useful for checking if a state exists and its basic info.
        """
        state_path = self._get_state_path(agent_id)

        if not state_path.exists():
            return None

        try:
            with open(state_path, 'r') as f:
                state_data = json.load(f)

            return {
                "agent_id": state_data.get("agent_id"),
                "snapshot_id": state_data.get("id"),
                "created_at": state_data.get("created_at"),
                "status": state_data.get("status"),
                "files_analyzed": state_data.get("files_analyzed", 0),
                "total_files": state_data.get("total_files", 0),
                "findings_count": len(state_data.get("findings", [])),
                "conversation_length": len(state_data.get("conversation_history", [])),
                "total_api_calls": state_data.get("total_api_calls", 0),
            }
        except Exception as e:
            print(f"[Persistence] Error reading summary for {agent_id}: {e}")
            return None

    def has_saved_state(self, agent_id: str) -> bool:
        """Check if an agent has a saved state."""
        return self._get_state_path(agent_id).exists()


# Global instance
persistence_service = PersistenceService()
