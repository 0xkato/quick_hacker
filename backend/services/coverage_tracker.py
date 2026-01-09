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
