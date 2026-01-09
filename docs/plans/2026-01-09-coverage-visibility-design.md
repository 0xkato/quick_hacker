# Coverage Visibility Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add entry point to sink path coverage tracking so users can see what has been investigated vs. what remains unexplored during security scans.

**Architecture:** Lightweight path tracker service + LLM verdict tool + tree view UI + depth enforcement

**Tech Stack:** Python 3.11+, React/TypeScript, WebSocket, pytest

---

## Overview

Current scans lack visibility into coverage. The LLM says "AUDIT_COMPLETE" but users have no way to verify that all paths were actually investigated. This design adds:

1. **CoverageTracker** - Service tracking (entry_point, sink) path status
2. **trace_path_verdict** - LLM tool to report path conclusions
3. **Tree view UI** - Hierarchical visualization of coverage
4. **Depth enforcement** - Challenge premature completion claims

---

## Data Model

### Path Status

```python
class PathStatus(Enum):
    UNDISCOVERED = "undiscovered"    # Not yet found by triage
    DISCOVERED = "discovered"         # Found, not yet investigated
    IN_PROGRESS = "in_progress"       # LLM currently tracing
    TRACED_SAFE = "traced_safe"       # LLM concluded: no vulnerability
    TRACED_VULN = "traced_vuln"       # LLM concluded: vulnerability found
    BLOCKED = "blocked"               # Path blocked by defenses
    INCONCLUSIVE = "inconclusive"     # LLM couldn't determine
```

### Path Record

```python
@dataclass
class PathRecord:
    id: str                          # Unique path identifier
    entry_point: EntryPoint          # From existing schema
    sink: Sink                       # From existing schema
    status: PathStatus
    verdict_reasoning: str | None    # Why safe/vuln/blocked
    finding_id: str | None           # Link to Finding if vuln
    traced_at: datetime | None
    files_in_path: list[str]         # Files read during trace
```

### Coverage Stats

```python
@dataclass
class CoverageStats:
    total_paths: int
    discovered_count: int
    in_progress_count: int
    traced_safe_count: int
    traced_vuln_count: int
    blocked_count: int
    inconclusive_count: int

    @property
    def traced_count(self) -> int:
        return self.traced_safe_count + self.traced_vuln_count + self.blocked_count

    @property
    def coverage_percent(self) -> float:
        if self.total_paths == 0:
            return 0.0
        return (self.traced_count / self.total_paths) * 100
```

---

## CoverageTracker Service

```python
# backend/services/coverage_tracker.py

from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import uuid


class CoverageTracker:
    """Tracks entry point to sink path coverage during scans."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.paths: dict[str, PathRecord] = {}
        self._entry_sink_index: dict[tuple[str, str], str] = {}  # (ep_id, sink_id) -> path_id

    def register_path(
        self,
        entry_point: EntryPoint,
        sink: Sink,
        status: PathStatus = PathStatus.DISCOVERED
    ) -> str:
        """Register a potential path. Returns path_id."""
        key = (entry_point.id, sink.id)

        # Idempotent - return existing if already registered
        if key in self._entry_sink_index:
            return self._entry_sink_index[key]

        path_id = str(uuid.uuid4())
        self.paths[path_id] = PathRecord(
            id=path_id,
            entry_point=entry_point,
            sink=sink,
            status=status,
            verdict_reasoning=None,
            finding_id=None,
            traced_at=None,
            files_in_path=[]
        )
        self._entry_sink_index[key] = path_id
        return path_id

    def update_status(
        self,
        path_id: str,
        status: PathStatus,
        reasoning: str | None = None,
        finding_id: str | None = None,
        files_in_path: list[str] | None = None
    ) -> None:
        """Update path status after LLM verdict."""
        if path_id not in self.paths:
            raise ValueError(f"Unknown path: {path_id}")

        record = self.paths[path_id]
        record.status = status
        record.verdict_reasoning = reasoning
        record.finding_id = finding_id
        record.traced_at = datetime.utcnow()
        if files_in_path:
            record.files_in_path = files_in_path

    def find_path_by_locations(
        self,
        entry_file: str,
        entry_line: int,
        sink_file: str,
        sink_line: int
    ) -> PathRecord | None:
        """Find path by file:line locations. Used by trace_path_verdict tool."""
        for record in self.paths.values():
            ep_match = (
                record.entry_point.file_path == entry_file and
                record.entry_point.line_number == entry_line
            )
            sink_match = (
                record.sink.file_path == sink_file and
                record.sink.line_number == sink_line
            )
            if ep_match and sink_match:
                return record
        return None

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

    def get_unexplored_paths(self) -> list[PathRecord]:
        """Get paths that haven't been traced yet."""
        return [
            r for r in self.paths.values()
            if r.status in (PathStatus.DISCOVERED, PathStatus.INCONCLUSIVE)
        ]

    def get_paths_by_entry_point(self, entry_point_id: str) -> list[PathRecord]:
        """Get all paths from a specific entry point."""
        return [
            r for r in self.paths.values()
            if r.entry_point.id == entry_point_id
        ]
```

---

## LLM Tool: trace_path_verdict

```python
# Add to backend/agents/tools.py

TRACE_PATH_VERDICT_SCHEMA = {
    "name": "trace_path_verdict",
    "description": "Report the conclusion of tracing a data flow path from entry point to sink. Call this after investigating each potential vulnerability path.",
    "parameters": {
        "type": "object",
        "properties": {
            "entry_point_file": {
                "type": "string",
                "description": "File path of the entry point"
            },
            "entry_point_line": {
                "type": "integer",
                "description": "Line number of the entry point"
            },
            "sink_file": {
                "type": "string",
                "description": "File path of the dangerous sink"
            },
            "sink_line": {
                "type": "integer",
                "description": "Line number of the dangerous sink"
            },
            "verdict": {
                "type": "string",
                "enum": ["safe", "vulnerable", "blocked", "inconclusive"],
                "description": "Conclusion: safe (no vuln), vulnerable (finding reported), blocked (defenses prevent exploitation), inconclusive (need more context)"
            },
            "reasoning": {
                "type": "string",
                "description": "1-2 sentence explanation of why this verdict"
            },
            "files_examined": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of files read while tracing this path"
            },
            "finding_id": {
                "type": "string",
                "description": "If verdict is 'vulnerable', the ID of the reported finding"
            }
        },
        "required": ["entry_point_file", "entry_point_line", "sink_file", "sink_line", "verdict", "reasoning", "files_examined"]
    }
}


def handle_trace_path_verdict(
    args: dict,
    coverage_tracker: CoverageTracker,
    broadcast_fn: Callable
) -> str:
    """Handle trace_path_verdict tool call."""

    # Find or create the path record
    record = coverage_tracker.find_path_by_locations(
        args["entry_point_file"],
        args["entry_point_line"],
        args["sink_file"],
        args["sink_line"]
    )

    if record is None:
        # Auto-register if not found (LLM discovered path during analysis)
        entry_point = EntryPoint(
            id=str(uuid.uuid4()),
            name="discovered",
            file_path=args["entry_point_file"],
            line_number=args["entry_point_line"],
            method=None,
            route=None,
            code_snippet=None
        )
        sink = Sink(
            id=str(uuid.uuid4()),
            sink_type="unknown",
            function_name="unknown",
            file_path=args["sink_file"],
            line_number=args["sink_line"],
            code_snippet=None,
            context=None
        )
        path_id = coverage_tracker.register_path(entry_point, sink)
        record = coverage_tracker.paths[path_id]

    # Map verdict string to status
    status_map = {
        "safe": PathStatus.TRACED_SAFE,
        "vulnerable": PathStatus.TRACED_VULN,
        "blocked": PathStatus.BLOCKED,
        "inconclusive": PathStatus.INCONCLUSIVE
    }

    # Update the record
    coverage_tracker.update_status(
        record.id,
        status_map[args["verdict"]],
        reasoning=args["reasoning"],
        finding_id=args.get("finding_id"),
        files_in_path=args["files_examined"]
    )

    # Broadcast coverage update
    stats = coverage_tracker.get_coverage_stats()
    broadcast_fn("COVERAGE_UPDATE", {
        "path_id": record.id,
        "entry_point": f"{args['entry_point_file']}:{args['entry_point_line']}",
        "sink": f"{args['sink_file']}:{args['sink_line']}",
        "status": args["verdict"],
        "stats": {
            "total": stats.total_paths,
            "traced": stats.traced_count,
            "remaining": stats.discovered_count + stats.inconclusive_count,
            "coverage_percent": stats.coverage_percent
        }
    })

    return f"Recorded verdict '{args['verdict']}' for path {args['entry_point_file']}:{args['entry_point_line']} -> {args['sink_file']}:{args['sink_line']}"
```

---

## Prompt Modifications

Add to each analysis prompt in `backend/prompts/v2/analysis/*.py`:

```python
VERDICT_REPORTING_INSTRUCTION = """
<path_verdict_reporting>
AFTER TRACING EACH PATH:

When you finish investigating a path from entry point to sink, call trace_path_verdict with:
- entry_point_file, entry_point_line: Location of the entry point
- sink_file, sink_line: Location of the dangerous sink
- verdict: One of:
  - "safe" - No vulnerability, data is properly handled
  - "vulnerable" - Exploitable vulnerability (also call report_finding)
  - "blocked" - Path exists but defenses prevent exploitation
  - "inconclusive" - Cannot determine, need more context
- reasoning: 1-2 sentence explanation
- files_examined: Files you read while tracing

This enables coverage tracking. Do NOT skip this step.
</path_verdict_reporting>
"""
```

---

## Depth Enforcement

Add to `backend/agents/react_agent.py`:

```python
@dataclass
class DepthEnforcementConfig:
    min_coverage_percent: float = 80.0
    max_inconclusive: int = 3
    require_explicit_skip_reason: bool = True


def check_coverage_before_complete(
    coverage_tracker: CoverageTracker,
    config: DepthEnforcementConfig
) -> tuple[bool, str | None]:
    """Check if coverage is sufficient to accept AUDIT_COMPLETE.

    Returns:
        (can_complete, challenge_message)
    """
    stats = coverage_tracker.get_coverage_stats()

    # Check coverage percentage
    if stats.coverage_percent < config.min_coverage_percent:
        remaining = coverage_tracker.get_unexplored_paths()
        paths_summary = "\n".join([
            f"  - {r.entry_point.file_path}:{r.entry_point.line_number} -> {r.sink.file_path}:{r.sink.line_number}"
            for r in remaining[:10]
        ])
        if len(remaining) > 10:
            paths_summary += f"\n  ... and {len(remaining) - 10} more"

        return False, f"""You said AUDIT_COMPLETE but coverage is only {stats.coverage_percent:.1f}%.

Unexplored paths:
{paths_summary}

Either:
1. Trace these remaining paths and call trace_path_verdict for each
2. Explain why these paths are not worth investigating
3. Say AUDIT_COMPLETE again to confirm you're done despite low coverage
"""

    # Check inconclusive count
    if stats.inconclusive_count > config.max_inconclusive:
        return False, f"""You said AUDIT_COMPLETE but {stats.inconclusive_count} paths are marked inconclusive.

Review these paths and either:
1. Gather more context to make a determination
2. Mark them as safe/blocked with reasoning
3. Say AUDIT_COMPLETE again to confirm
"""

    return True, None


# In the agent loop, modify AUDIT_COMPLETE handling:

if "AUDIT_COMPLETE" in response:
    can_complete, challenge = check_coverage_before_complete(
        self.coverage_tracker,
        self.depth_config
    )

    if not can_complete and challenge:
        self.messages.append({"role": "user", "content": challenge})
        continue  # Force another iteration

    audit_complete_count += 1
    if audit_complete_count >= required_confirmations:
        break
```

---

## Frontend: Coverage Tree Component

```typescript
// frontend/components/CoveragePanel/CoverageTree.tsx

interface PathRecord {
  id: string;
  entryPoint: {
    filePath: string;
    lineNumber: number;
    name: string;
    route?: string;
  };
  sink: {
    filePath: string;
    lineNumber: number;
    functionName: string;
    sinkType: string;
  };
  status: 'discovered' | 'in_progress' | 'traced_safe' | 'traced_vuln' | 'blocked' | 'inconclusive';
  verdictReasoning?: string;
  findingId?: string;
}

interface CoverageStats {
  total: number;
  traced: number;
  remaining: number;
  coveragePercent: number;
}

interface CoverageTreeProps {
  paths: PathRecord[];
  stats: CoverageStats;
  onPathClick: (path: PathRecord) => void;
}

const STATUS_ICONS: Record<string, string> = {
  discovered: '[ ]',
  in_progress: '[~]',
  traced_safe: '[ok]',
  traced_vuln: '[!!]',
  blocked: '[x]',
  inconclusive: '[?]',
};

const STATUS_COLORS: Record<string, string> = {
  discovered: 'text-gray-400',
  in_progress: 'text-blue-500',
  traced_safe: 'text-green-500',
  traced_vuln: 'text-red-500',
  blocked: 'text-gray-500',
  inconclusive: 'text-yellow-500',
};

export function CoverageTree({ paths, stats, onPathClick }: CoverageTreeProps) {
  // Group paths by entry point
  const grouped = useMemo(() => {
    const map = new Map<string, PathRecord[]>();
    for (const path of paths) {
      const key = `${path.entryPoint.filePath}:${path.entryPoint.lineNumber}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(path);
    }
    return map;
  }, [paths]);

  return (
    <div className="coverage-tree">
      {/* Summary bar */}
      <div className="coverage-summary p-2 border-b">
        <span>Coverage: {stats.traced}/{stats.total} paths ({stats.coveragePercent.toFixed(1)}%)</span>
        <span className="ml-4 text-red-500">{stats.vulnCount} vulns</span>
        <span className="ml-4 text-gray-400">{stats.remaining} remaining</span>
      </div>

      {/* Tree */}
      <div className="tree-content p-2 font-mono text-sm">
        {Array.from(grouped.entries()).map(([epKey, epPaths]) => (
          <EntryPointNode key={epKey} paths={epPaths} onPathClick={onPathClick} />
        ))}
      </div>
    </div>
  );
}

function EntryPointNode({ paths, onPathClick }: { paths: PathRecord[], onPathClick: (p: PathRecord) => void }) {
  const [expanded, setExpanded] = useState(true);
  const ep = paths[0].entryPoint;
  const tracedCount = paths.filter(p =>
    ['traced_safe', 'traced_vuln', 'blocked'].includes(p.status)
  ).length;

  return (
    <div className="entry-point-node">
      <div
        className="cursor-pointer hover:bg-gray-100 p-1"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? 'v' : '>'} {ep.route || ep.name} ({ep.filePath}:{ep.lineNumber})
        <span className="ml-2 text-gray-500">{tracedCount}/{paths.length}</span>
      </div>

      {expanded && (
        <div className="ml-4">
          {paths.map(path => (
            <div
              key={path.id}
              className={`p-1 cursor-pointer hover:bg-gray-50 ${STATUS_COLORS[path.status]}`}
              onClick={() => onPathClick(path)}
            >
              {STATUS_ICONS[path.status]} -{'>'} {path.sink.functionName} ({path.sink.filePath}:{path.sink.lineNumber})
              {path.verdictReasoning && (
                <span className="ml-2 text-gray-400 text-xs">- {path.verdictReasoning}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
```

---

## WebSocket Events

Add to existing WebSocket message types:

```python
# backend/models/schemas.py

class WebSocketMessageType(str, Enum):
    # ... existing types ...
    COVERAGE_UPDATE = "COVERAGE_UPDATE"
    COVERAGE_INIT = "COVERAGE_INIT"  # Full coverage state on connect


# Message payloads
@dataclass
class CoverageUpdateMessage:
    type: Literal["COVERAGE_UPDATE"]
    path_id: str
    entry_point: str  # file:line
    sink: str         # file:line
    status: str
    stats: dict       # CoverageStats as dict


@dataclass
class CoverageInitMessage:
    type: Literal["COVERAGE_INIT"]
    paths: list[dict]  # All PathRecords as dicts
    stats: dict
```

---

## Testing

### Unit Tests

```python
# backend/tests/services/test_coverage_tracker.py

import pytest
from services.coverage_tracker import CoverageTracker, PathStatus, PathRecord
from models.schemas import EntryPoint, Sink


@pytest.fixture
def tracker():
    return CoverageTracker(agent_id="test-agent")


@pytest.fixture
def sample_entry_point():
    return EntryPoint(
        id="ep-1",
        name="login",
        file_path="routes/auth.py",
        line_number=42,
        method="POST",
        route="/api/login",
        code_snippet=None
    )


@pytest.fixture
def sample_sink():
    return Sink(
        id="sink-1",
        sink_type="sql",
        function_name="cursor.execute",
        file_path="services/user.py",
        line_number=89,
        code_snippet=None,
        context=None
    )


class TestCoverageTracker:
    def test_register_path_sets_discovered_status(self, tracker, sample_entry_point, sample_sink):
        path_id = tracker.register_path(sample_entry_point, sample_sink)

        assert path_id in tracker.paths
        assert tracker.paths[path_id].status == PathStatus.DISCOVERED

    def test_register_path_is_idempotent(self, tracker, sample_entry_point, sample_sink):
        path_id_1 = tracker.register_path(sample_entry_point, sample_sink)
        path_id_2 = tracker.register_path(sample_entry_point, sample_sink)

        assert path_id_1 == path_id_2
        assert len(tracker.paths) == 1

    def test_update_status_transitions_correctly(self, tracker, sample_entry_point, sample_sink):
        path_id = tracker.register_path(sample_entry_point, sample_sink)

        tracker.update_status(path_id, PathStatus.IN_PROGRESS)
        assert tracker.paths[path_id].status == PathStatus.IN_PROGRESS

        tracker.update_status(path_id, PathStatus.TRACED_SAFE, reasoning="Parameterized query used")
        assert tracker.paths[path_id].status == PathStatus.TRACED_SAFE
        assert tracker.paths[path_id].verdict_reasoning == "Parameterized query used"

    def test_get_coverage_stats_calculates_correctly(self, tracker, sample_entry_point, sample_sink):
        # Register 3 paths
        for i in range(3):
            sink = Sink(id=f"sink-{i}", sink_type="sql", function_name="execute",
                       file_path=f"file{i}.py", line_number=i*10, code_snippet=None, context=None)
            tracker.register_path(sample_entry_point, sink)

        # Update one to traced
        path_ids = list(tracker.paths.keys())
        tracker.update_status(path_ids[0], PathStatus.TRACED_SAFE)

        stats = tracker.get_coverage_stats()
        assert stats.total_paths == 3
        assert stats.traced_safe_count == 1
        assert stats.discovered_count == 2
        assert stats.coverage_percent == pytest.approx(33.33, rel=0.1)

    def test_get_unexplored_paths_returns_discovered_only(self, tracker, sample_entry_point, sample_sink):
        path_id = tracker.register_path(sample_entry_point, sample_sink)

        unexplored = tracker.get_unexplored_paths()
        assert len(unexplored) == 1

        tracker.update_status(path_id, PathStatus.TRACED_SAFE)
        unexplored = tracker.get_unexplored_paths()
        assert len(unexplored) == 0

    def test_find_path_by_locations(self, tracker, sample_entry_point, sample_sink):
        tracker.register_path(sample_entry_point, sample_sink)

        found = tracker.find_path_by_locations(
            "routes/auth.py", 42,
            "services/user.py", 89
        )
        assert found is not None
        assert found.entry_point.id == "ep-1"

        not_found = tracker.find_path_by_locations(
            "nonexistent.py", 1,
            "also_nonexistent.py", 1
        )
        assert not_found is None
```

### Integration Tests

```python
# backend/tests/agents/test_coverage_integration.py

import pytest
from agents.react_agent import ReActSecurityAgent
from services.coverage_tracker import CoverageTracker, PathStatus


class TestCoverageIntegration:
    def test_trace_path_verdict_updates_tracker(self, mock_agent):
        tracker = CoverageTracker("test")
        mock_agent.coverage_tracker = tracker

        # Simulate tool call
        result = mock_agent.handle_tool_call("trace_path_verdict", {
            "entry_point_file": "routes/api.py",
            "entry_point_line": 10,
            "sink_file": "db/query.py",
            "sink_line": 50,
            "verdict": "safe",
            "reasoning": "Uses parameterized query",
            "files_examined": ["routes/api.py", "db/query.py"]
        })

        assert len(tracker.paths) == 1
        path = list(tracker.paths.values())[0]
        assert path.status == PathStatus.TRACED_SAFE

    def test_audit_complete_challenged_when_paths_remain(self, mock_agent):
        tracker = CoverageTracker("test")
        # Register path but don't trace it
        tracker.register_path(mock_entry_point(), mock_sink())
        mock_agent.coverage_tracker = tracker

        # Simulate AUDIT_COMPLETE in response
        response = "Based on my analysis, AUDIT_COMPLETE"

        can_complete, challenge = mock_agent.check_coverage_before_complete()

        assert can_complete is False
        assert "coverage" in challenge.lower()
        assert "0.0%" in challenge or "0%" in challenge
```

---

## Error Handling

| Scenario | Handling |
|----------|----------|
| LLM reports verdict for unknown path | Auto-register path with status from verdict |
| LLM reports same path twice | Keep most recent verdict, log warning |
| Path references non-existent file | Accept verdict, file validation is separate |
| Coverage tracker initialization fails | Scan continues without coverage tracking |
| WebSocket disconnect during update | Full coverage state sent on reconnect via COVERAGE_INIT |

---

## Files Summary

**Create:**
- `backend/services/coverage_tracker.py`
- `backend/tests/services/test_coverage_tracker.py`
- `backend/tests/agents/test_coverage_integration.py`
- `frontend/components/CoveragePanel/CoverageTree.tsx`
- `frontend/components/CoveragePanel/index.ts`

**Modify:**
- `backend/agents/react_agent.py` - Add coverage tracker, depth enforcement
- `backend/agents/tools.py` - Add trace_path_verdict tool and handler
- `backend/prompts/v2/analysis/base_analysis.py` - Add verdict reporting instruction
- `backend/routers/agents.py` - Initialize coverage tracker on scan start
- `backend/models/schemas.py` - Add WebSocket message types
- `frontend/app/page.tsx` - Add CoverageTree to UI layout
