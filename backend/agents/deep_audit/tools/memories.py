"""Memory access tools for Overseer."""

import json
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agents.deep_audit.filesystem import MemoriesFilesystem


# Will be set by Overseer
_filesystem: "MemoriesFilesystem" = None


def set_filesystem(filesystem: "MemoriesFilesystem"):
    """Set the filesystem instance for tools to use."""
    global _filesystem
    _filesystem = filesystem


def read_memories(path: str) -> str:
    """Read an artifact from /memories/.

    Args:
        path: Path to read, must start with /memories/
              Examples:
              - /memories/repo_profile.json
              - /memories/scopes/backend/signals.json
              - /memories/overseer/wave_1_synthesis.md

    Returns:
        File contents as string, or JSON error
    """
    if _filesystem is None:
        return json.dumps({"error": "Filesystem not initialized"})

    try:
        if not path.startswith("/memories/"):
            return json.dumps({"error": f"Path must start with /memories/: {path}"})

        content = _filesystem.read_file(path)

        # Try to parse as JSON for better formatting
        if path.endswith(".json"):
            try:
                data = json.loads(content)
                return json.dumps(data, indent=2)
            except json.JSONDecodeError:
                return content

        return content

    except FileNotFoundError:
        return json.dumps({"error": f"File not found: {path}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def list_memories(path: str = "/memories/") -> str:
    """List contents of a /memories/ directory.

    Args:
        path: Directory path to list, must start with /memories/
              Default is /memories/ (root)

    Returns:
        JSON list of files/directories, or error
    """
    if _filesystem is None:
        return json.dumps({"error": "Filesystem not initialized"})

    try:
        if not path.startswith("/memories/"):
            return json.dumps({"error": f"Path must start with /memories/: {path}"})

        # Ensure path ends with /
        if not path.endswith("/"):
            path = path + "/"

        items = _filesystem.ls(path.rstrip("/"))

        # Categorize items
        result = {
            "path": path,
            "directories": [],
            "files": []
        }

        for item in items:
            item_path = f"{path.rstrip('/')}/{item}"
            if _filesystem.is_dir(item_path):
                result["directories"].append(item)
            else:
                result["files"].append(item)

        return json.dumps(result, indent=2)

    except FileNotFoundError:
        return json.dumps({"error": f"Directory not found: {path}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def write_synthesis(wave_id: int, synthesis_content: str) -> str:
    """Write wave synthesis document.

    Args:
        wave_id: Wave number
        synthesis_content: Markdown content for wave synthesis

    Returns:
        Path where synthesis was written, or error
    """
    if _filesystem is None:
        return json.dumps({"error": "Filesystem not initialized"})

    try:
        path = _filesystem.save_wave_synthesis(wave_id, synthesis_content)
        return json.dumps({"success": True, "path": path})
    except Exception as e:
        return json.dumps({"error": str(e)})


def write_artifact(path: str, content: str) -> str:
    """Write an artifact to /memories/.

    Args:
        path: Path to write, must start with /memories/
        content: Content to write

    Returns:
        JSON with success status and path
    """
    if _filesystem is None:
        return json.dumps({"error": "Filesystem not initialized"})

    try:
        if not path.startswith("/memories/"):
            return json.dumps({"error": f"Path must start with /memories/: {path}"})

        written_path = _filesystem.write_file(path, content)
        return json.dumps({"success": True, "path": written_path})
    except Exception as e:
        return json.dumps({"error": str(e)})


# Tool definitions
READ_MEMORIES_TOOL = {
    "name": "read_memories",
    "description": """Read an artifact from the /memories/ filesystem.

Common paths:
- /memories/repo_profile.json - Repository profile
- /memories/threat_model.md - Threat model
- /memories/authz_map.json - Auth boundary map
- /memories/scopes/{scope_id}/summary.md - Scope summary
- /memories/scopes/{scope_id}/signals.json - Scope signals
- /memories/scopes/{scope_id}/entrypoints.json - Scope entrypoints
- /memories/traces/{signal_id}/dataflow.md - Dataflow trace
- /memories/triage/{signal_id}/verdict.json - Triage verdict
- /memories/overseer/wave_N_synthesis.md - Wave synthesis
- /memories/overseer/campaign_state.json - Campaign state""",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to read, must start with /memories/"
            }
        },
        "required": ["path"]
    }
}

LIST_MEMORIES_TOOL = {
    "name": "list_memories",
    "description": "List contents of a /memories/ directory to see what artifacts exist.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Directory path to list (default: /memories/)"
            }
        },
        "required": []
    }
}

WRITE_SYNTHESIS_TOOL = {
    "name": "write_synthesis",
    "description": """Write wave synthesis document. Called after each wave to record:
- What was learned
- Updated mental model
- New signals and hypotheses
- Confirmed findings and dismissals
- Coverage and gaps
- Next wave goals""",
    "input_schema": {
        "type": "object",
        "properties": {
            "wave_id": {
                "type": "integer",
                "description": "Wave number"
            },
            "synthesis_content": {
                "type": "string",
                "description": "Markdown content for wave synthesis"
            }
        },
        "required": ["wave_id", "synthesis_content"]
    }
}

WRITE_ARTIFACT_TOOL = {
    "name": "write_artifact",
    "description": "Write a custom artifact to /memories/. Use for threat_model.md, authz_map.json, etc.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to write, must start with /memories/"
            },
            "content": {
                "type": "string",
                "description": "Content to write"
            }
        },
        "required": ["path", "content"]
    }
}
