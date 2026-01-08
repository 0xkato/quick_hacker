"""Tests for CASS WebSocket events."""

import pytest
from unittest.mock import MagicMock, AsyncMock
from cass.events import CASSEventEmitter


@pytest.fixture
def emitter():
    callback = MagicMock()
    return CASSEventEmitter("agent-123", callback)


def test_emit_mapping_started(emitter):
    """Emits mapping started event."""
    emitter.emit_mapping_started(total_files=100)
    emitter.callback.assert_called_once()
    call_args = emitter.callback.call_args[0][0]
    assert call_args.type.value == "cass_mapping_started"


def test_emit_progress(emitter):
    """Emits progress event."""
    emitter.emit_progress(current=50, total=100, message="Scanning routes...")
    emitter.callback.assert_called_once()


def test_emit_discovery(emitter):
    """Emits discovery event."""
    emitter.emit_discovery(
        discovery_type="entry_point",
        name="/api/users",
        file_path="routes.py",
        line=10,
    )
    emitter.callback.assert_called_once()
    call_args = emitter.callback.call_args[0][0]
    assert call_args.data["discovery_type"] == "entry_point"


def test_emit_mapping_complete(emitter):
    """Emits mapping complete event."""
    emitter.emit_mapping_complete(
        nodes_count=150,
        relationships_count=300,
        duration_seconds=45.5,
    )
    emitter.callback.assert_called_once()
