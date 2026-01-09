"""Coverage tracker for entry point to sink path analysis."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class PathStatus(Enum):
    """Status of an entry point to sink path."""
    UNDISCOVERED = "undiscovered"
    DISCOVERED = "discovered"
    IN_PROGRESS = "in_progress"
    TRACED_SAFE = "traced_safe"
    TRACED_VULN = "traced_vuln"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


@dataclass
class PathRecord:
    """Record of a single entry point to sink path."""
    id: str
    entry_point_file: str
    entry_point_line: int
    entry_point_name: str
    sink_file: str
    sink_line: int
    sink_type: str
    sink_function: str
    status: PathStatus
    verdict_reasoning: Optional[str] = None
    finding_id: Optional[str] = None
    traced_at: Optional[datetime] = None
    files_in_path: list[str] = field(default_factory=list)


@dataclass
class CoverageStats:
    """Statistics about path coverage."""
    total_paths: int
    discovered_count: int
    in_progress_count: int
    traced_safe_count: int
    traced_vuln_count: int
    blocked_count: int
    inconclusive_count: int

    @property
    def traced_count(self) -> int:
        """Count of paths with final verdict (safe, vuln, or blocked)."""
        return self.traced_safe_count + self.traced_vuln_count + self.blocked_count

    @property
    def coverage_percent(self) -> float:
        """Percentage of paths traced."""
        if self.total_paths == 0:
            return 0.0
        return (self.traced_count / self.total_paths) * 100


class CoverageTracker:
    """Tracks entry point to sink path coverage during scans."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.paths: dict[str, PathRecord] = {}
        self._location_index: dict[tuple[str, int, str, int], str] = {}

    def register_path(
        self,
        entry_point_file: str,
        entry_point_line: int,
        entry_point_name: str,
        sink_file: str,
        sink_line: int,
        sink_type: str,
        sink_function: str,
        status: PathStatus = PathStatus.DISCOVERED
    ) -> str:
        """Register a potential path. Returns path_id. Idempotent."""
        key = (entry_point_file, entry_point_line, sink_file, sink_line)

        if key in self._location_index:
            return self._location_index[key]

        path_id = str(uuid.uuid4())
        self.paths[path_id] = PathRecord(
            id=path_id,
            entry_point_file=entry_point_file,
            entry_point_line=entry_point_line,
            entry_point_name=entry_point_name,
            sink_file=sink_file,
            sink_line=sink_line,
            sink_type=sink_type,
            sink_function=sink_function,
            status=status
        )
        self._location_index[key] = path_id
        return path_id

    def update_status(
        self,
        path_id: str,
        status: PathStatus,
        reasoning: Optional[str] = None,
        finding_id: Optional[str] = None,
        files_in_path: Optional[list[str]] = None
    ) -> None:
        """Update path status after LLM verdict."""
        if path_id not in self.paths:
            raise ValueError(f"Unknown path: {path_id}")

        record = self.paths[path_id]
        record.status = status
        record.verdict_reasoning = reasoning
        record.finding_id = finding_id
        record.traced_at = datetime.now(timezone.utc)
        if files_in_path:
            record.files_in_path = files_in_path

    def get_coverage_stats(self) -> CoverageStats:
        """Calculate current coverage statistics."""
        stats = CoverageStats(
            total_paths=len(self.paths),
            discovered_count=0,
            in_progress_count=0,
            traced_safe_count=0,
            traced_vuln_count=0,
            blocked_count=0,
            inconclusive_count=0
        )

        for record in self.paths.values():
            match record.status:
                case PathStatus.DISCOVERED:
                    stats.discovered_count += 1
                case PathStatus.IN_PROGRESS:
                    stats.in_progress_count += 1
                case PathStatus.TRACED_SAFE:
                    stats.traced_safe_count += 1
                case PathStatus.TRACED_VULN:
                    stats.traced_vuln_count += 1
                case PathStatus.BLOCKED:
                    stats.blocked_count += 1
                case PathStatus.INCONCLUSIVE:
                    stats.inconclusive_count += 1

        return stats

    def find_path_by_locations(
        self,
        entry_file: str,
        entry_line: int,
        sink_file: str,
        sink_line: int
    ) -> Optional[PathRecord]:
        """Find path by file:line locations."""
        key = (entry_file, entry_line, sink_file, sink_line)
        path_id = self._location_index.get(key)
        if path_id:
            return self.paths.get(path_id)
        return None

    def get_unexplored_paths(self) -> list[PathRecord]:
        """Get paths that haven't been traced yet."""
        return [
            r for r in self.paths.values()
            if r.status in (PathStatus.DISCOVERED, PathStatus.INCONCLUSIVE)
        ]
