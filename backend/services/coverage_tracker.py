"""Coverage tracker for entry point to sink path analysis."""
from dataclasses import dataclass, field
from datetime import datetime
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
