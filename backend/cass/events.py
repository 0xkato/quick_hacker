"""CASS WebSocket event emitter for mapping and scanning progress."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional


class CASSMessageType(Enum):
    """Message types for CASS WebSocket events."""

    MAPPING_STARTED = "cass_mapping_started"
    MAPPING_PROGRESS = "cass_mapping_progress"
    MAPPING_DISCOVERY = "cass_mapping_discovery"
    MAPPING_COMPLETE = "cass_mapping_complete"
    SCAN_STARTED = "cass_scan_started"
    SCAN_CANDIDATE = "cass_scan_candidate"
    SCAN_COMPLETE = "cass_scan_complete"
    GRAPH_UPDATE = "cass_graph_update"


@dataclass
class WSMessage:
    """WebSocket message for CASS events."""

    type: CASSMessageType
    agent_id: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CASSEventEmitter:
    """Emits WebSocket events for CASS mapping and scanning progress."""

    agent_id: str
    callback: Callable[[WSMessage], None]

    def _emit(self, msg_type: CASSMessageType, data: dict) -> None:
        """Emit a WebSocket message."""
        msg = WSMessage(
            type=msg_type,
            agent_id=self.agent_id,
            data=data,
            timestamp=datetime.utcnow(),
        )
        self.callback(msg)

    def emit_mapping_started(
        self,
        total_files: int,
        frameworks: Optional[list[str]] = None,
    ) -> None:
        """Emit mapping started event.

        Args:
            total_files: Total number of files to map.
            frameworks: List of detected frameworks.
        """
        self._emit(
            CASSMessageType.MAPPING_STARTED,
            {
                "total_files": total_files,
                "frameworks": frameworks or [],
            },
        )

    def emit_progress(
        self,
        current: int,
        total: int,
        message: str,
        phase: Optional[str] = None,
    ) -> None:
        """Emit progress event.

        Args:
            current: Current progress count.
            total: Total count.
            message: Progress message.
            phase: Optional phase name (e.g., "scanning", "parsing", "analyzing").
        """
        self._emit(
            CASSMessageType.MAPPING_PROGRESS,
            {
                "current": current,
                "total": total,
                "message": message,
                "phase": phase,
                "percentage": round((current / total) * 100, 1) if total > 0 else 0,
            },
        )

    def emit_discovery(
        self,
        discovery_type: str,
        name: str,
        file_path: str,
        line: int,
        severity: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        """Emit discovery event for entry points, sinks, etc.

        Args:
            discovery_type: Type of discovery (e.g., "entry_point", "sink", "taint_source").
            name: Name/identifier of the discovery.
            file_path: Path to the file where discovery was made.
            line: Line number.
            severity: Optional severity level.
            details: Optional additional details.
        """
        self._emit(
            CASSMessageType.MAPPING_DISCOVERY,
            {
                "discovery_type": discovery_type,
                "name": name,
                "file_path": file_path,
                "line": line,
                "severity": severity,
                "details": details or {},
            },
        )

    def emit_mapping_complete(
        self,
        nodes_count: int,
        relationships_count: int,
        duration_seconds: float,
        summary: Optional[dict] = None,
    ) -> None:
        """Emit mapping complete event.

        Args:
            nodes_count: Total nodes in the graph.
            relationships_count: Total relationships in the graph.
            duration_seconds: Time taken for mapping.
            summary: Optional summary statistics.
        """
        self._emit(
            CASSMessageType.MAPPING_COMPLETE,
            {
                "nodes_count": nodes_count,
                "relationships_count": relationships_count,
                "duration_seconds": duration_seconds,
                "summary": summary or {},
            },
        )

    def emit_scan_started(
        self,
        candidates_count: int,
    ) -> None:
        """Emit scan started event.

        Args:
            candidates_count: Number of candidates to scan.
        """
        self._emit(
            CASSMessageType.SCAN_STARTED,
            {
                "candidates_count": candidates_count,
            },
        )

    def emit_scan_candidate(
        self,
        candidate_id: str,
        entry_point: str,
        sink: str,
        risk_score: float,
        status: str,
    ) -> None:
        """Emit scan candidate event.

        Args:
            candidate_id: Unique identifier for the candidate.
            entry_point: Entry point name/path.
            sink: Sink name/path.
            risk_score: Risk score (0.0 to 1.0).
            status: Status (e.g., "scanning", "verified", "rejected").
        """
        self._emit(
            CASSMessageType.SCAN_CANDIDATE,
            {
                "candidate_id": candidate_id,
                "entry_point": entry_point,
                "sink": sink,
                "risk_score": risk_score,
                "status": status,
            },
        )

    def emit_scan_complete(
        self,
        findings_count: int,
        verified_count: int,
        rejected_count: int,
        duration_seconds: float,
    ) -> None:
        """Emit scan complete event.

        Args:
            findings_count: Total findings discovered.
            verified_count: Number of verified findings.
            rejected_count: Number of rejected candidates.
            duration_seconds: Time taken for scan.
        """
        self._emit(
            CASSMessageType.SCAN_COMPLETE,
            {
                "findings_count": findings_count,
                "verified_count": verified_count,
                "rejected_count": rejected_count,
                "duration_seconds": duration_seconds,
            },
        )

    def emit_graph_update(
        self,
        added_nodes: int,
        added_relationships: int,
        graph_stats: Optional[dict] = None,
    ) -> None:
        """Emit graph update event.

        Args:
            added_nodes: Number of nodes added.
            added_relationships: Number of relationships added.
            graph_stats: Optional graph statistics.
        """
        self._emit(
            CASSMessageType.GRAPH_UPDATE,
            {
                "added_nodes": added_nodes,
                "added_relationships": added_relationships,
                "graph_stats": graph_stats or {},
            },
        )
