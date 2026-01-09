# Coverage Visibility Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add entry point to sink path coverage tracking so users can see what has been investigated vs. what remains unexplored during security scans.

**Architecture:** CoverageTracker service tracks (entry_point, sink) paths with status. LLM reports verdicts via trace_path_verdict tool. Frontend displays tree view. Depth enforcement challenges premature AUDIT_COMPLETE.

**Tech Stack:** Python 3.11+, pytest, React/TypeScript, WebSocket

---

## Task 1: Create PathStatus Enum and PathRecord Model

**Files:**
- Create: `backend/services/coverage_tracker.py`
- Test: `backend/tests/services/test_coverage_tracker.py`

**Step 1: Write the failing test**

```python
# backend/tests/services/test_coverage_tracker.py
"""Tests for coverage tracker service."""
import pytest
from services.coverage_tracker import PathStatus, PathRecord


class TestPathStatus:
    def test_status_enum_has_all_states(self):
        assert PathStatus.UNDISCOVERED.value == "undiscovered"
        assert PathStatus.DISCOVERED.value == "discovered"
        assert PathStatus.IN_PROGRESS.value == "in_progress"
        assert PathStatus.TRACED_SAFE.value == "traced_safe"
        assert PathStatus.TRACED_VULN.value == "traced_vuln"
        assert PathStatus.BLOCKED.value == "blocked"
        assert PathStatus.INCONCLUSIVE.value == "inconclusive"


class TestPathRecord:
    def test_path_record_creation(self):
        record = PathRecord(
            id="path-1",
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute",
            status=PathStatus.DISCOVERED
        )
        assert record.id == "path-1"
        assert record.status == PathStatus.DISCOVERED
        assert record.verdict_reasoning is None
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'services.coverage_tracker'"

**Step 3: Write minimal implementation**

```python
# backend/services/coverage_tracker.py
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
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/services/coverage_tracker.py backend/tests/services/test_coverage_tracker.py
git commit -m "feat(coverage): add PathStatus enum and PathRecord model"
```

---

## Task 2: Create CoverageStats Model

**Files:**
- Modify: `backend/services/coverage_tracker.py`
- Test: `backend/tests/services/test_coverage_tracker.py`

**Step 1: Write the failing test**

```python
# Add to backend/tests/services/test_coverage_tracker.py
from services.coverage_tracker import PathStatus, PathRecord, CoverageStats


class TestCoverageStats:
    def test_coverage_stats_creation(self):
        stats = CoverageStats(
            total_paths=10,
            discovered_count=5,
            in_progress_count=1,
            traced_safe_count=2,
            traced_vuln_count=1,
            blocked_count=1,
            inconclusive_count=0
        )
        assert stats.total_paths == 10

    def test_traced_count_property(self):
        stats = CoverageStats(
            total_paths=10,
            discovered_count=5,
            in_progress_count=0,
            traced_safe_count=2,
            traced_vuln_count=1,
            blocked_count=1,
            inconclusive_count=1
        )
        assert stats.traced_count == 4  # safe + vuln + blocked

    def test_coverage_percent_property(self):
        stats = CoverageStats(
            total_paths=10,
            discovered_count=6,
            in_progress_count=0,
            traced_safe_count=2,
            traced_vuln_count=1,
            blocked_count=1,
            inconclusive_count=0
        )
        assert stats.coverage_percent == 40.0  # 4/10

    def test_coverage_percent_zero_paths(self):
        stats = CoverageStats(
            total_paths=0,
            discovered_count=0,
            in_progress_count=0,
            traced_safe_count=0,
            traced_vuln_count=0,
            blocked_count=0,
            inconclusive_count=0
        )
        assert stats.coverage_percent == 0.0
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageStats -v`
Expected: FAIL with "cannot import name 'CoverageStats'"

**Step 3: Write minimal implementation**

```python
# Add to backend/services/coverage_tracker.py

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
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageStats -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/services/coverage_tracker.py backend/tests/services/test_coverage_tracker.py
git commit -m "feat(coverage): add CoverageStats model with traced_count and coverage_percent"
```

---

## Task 3: Create CoverageTracker Class - register_path

**Files:**
- Modify: `backend/services/coverage_tracker.py`
- Test: `backend/tests/services/test_coverage_tracker.py`

**Step 1: Write the failing test**

```python
# Add to backend/tests/services/test_coverage_tracker.py
from services.coverage_tracker import CoverageTracker


@pytest.fixture
def tracker():
    return CoverageTracker(agent_id="test-agent")


class TestCoverageTrackerRegister:
    def test_register_path_returns_id(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        assert path_id is not None
        assert len(path_id) > 0

    def test_register_path_sets_discovered_status(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        assert tracker.paths[path_id].status == PathStatus.DISCOVERED

    def test_register_path_is_idempotent(self, tracker):
        path_id_1 = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        path_id_2 = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        assert path_id_1 == path_id_2
        assert len(tracker.paths) == 1
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerRegister -v`
Expected: FAIL with "cannot import name 'CoverageTracker'"

**Step 3: Write minimal implementation**

```python
# Add to backend/services/coverage_tracker.py
import uuid


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
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerRegister -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/services/coverage_tracker.py backend/tests/services/test_coverage_tracker.py
git commit -m "feat(coverage): add CoverageTracker.register_path with idempotency"
```

---

## Task 4: Add CoverageTracker.update_status

**Files:**
- Modify: `backend/services/coverage_tracker.py`
- Test: `backend/tests/services/test_coverage_tracker.py`

**Step 1: Write the failing test**

```python
# Add to backend/tests/services/test_coverage_tracker.py

class TestCoverageTrackerUpdateStatus:
    def test_update_status_changes_status(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(path_id, PathStatus.IN_PROGRESS)
        assert tracker.paths[path_id].status == PathStatus.IN_PROGRESS

    def test_update_status_sets_reasoning(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(
            path_id,
            PathStatus.TRACED_SAFE,
            reasoning="Uses parameterized query"
        )
        assert tracker.paths[path_id].verdict_reasoning == "Uses parameterized query"

    def test_update_status_sets_traced_at(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(path_id, PathStatus.TRACED_SAFE)
        assert tracker.paths[path_id].traced_at is not None

    def test_update_status_unknown_path_raises(self, tracker):
        with pytest.raises(ValueError, match="Unknown path"):
            tracker.update_status("nonexistent-id", PathStatus.TRACED_SAFE)
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerUpdateStatus -v`
Expected: FAIL with "AttributeError: 'CoverageTracker' object has no attribute 'update_status'"

**Step 3: Write minimal implementation**

```python
# Add to CoverageTracker class in backend/services/coverage_tracker.py

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
        record.traced_at = datetime.utcnow()
        if files_in_path:
            record.files_in_path = files_in_path
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerUpdateStatus -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/services/coverage_tracker.py backend/tests/services/test_coverage_tracker.py
git commit -m "feat(coverage): add CoverageTracker.update_status"
```

---

## Task 5: Add CoverageTracker.get_coverage_stats

**Files:**
- Modify: `backend/services/coverage_tracker.py`
- Test: `backend/tests/services/test_coverage_tracker.py`

**Step 1: Write the failing test**

```python
# Add to backend/tests/services/test_coverage_tracker.py

class TestCoverageTrackerStats:
    def test_get_coverage_stats_empty(self, tracker):
        stats = tracker.get_coverage_stats()
        assert stats.total_paths == 0
        assert stats.coverage_percent == 0.0

    def test_get_coverage_stats_counts_correctly(self, tracker):
        # Register 3 paths
        for i in range(3):
            tracker.register_path(
                entry_point_file="routes/api.py",
                entry_point_line=i * 10,
                entry_point_name=f"handler_{i}",
                sink_file=f"db/query{i}.py",
                sink_line=100,
                sink_type="sql",
                sink_function="execute"
            )

        # Update one to traced_safe
        path_ids = list(tracker.paths.keys())
        tracker.update_status(path_ids[0], PathStatus.TRACED_SAFE)

        stats = tracker.get_coverage_stats()
        assert stats.total_paths == 3
        assert stats.traced_safe_count == 1
        assert stats.discovered_count == 2
        assert stats.coverage_percent == pytest.approx(33.33, rel=0.1)
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerStats -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# Add to CoverageTracker class in backend/services/coverage_tracker.py

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
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerStats -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/services/coverage_tracker.py backend/tests/services/test_coverage_tracker.py
git commit -m "feat(coverage): add CoverageTracker.get_coverage_stats"
```

---

## Task 6: Add CoverageTracker.find_path_by_locations and get_unexplored_paths

**Files:**
- Modify: `backend/services/coverage_tracker.py`
- Test: `backend/tests/services/test_coverage_tracker.py`

**Step 1: Write the failing test**

```python
# Add to backend/tests/services/test_coverage_tracker.py

class TestCoverageTrackerQueries:
    def test_find_path_by_locations_found(self, tracker):
        tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        found = tracker.find_path_by_locations(
            "routes/api.py", 42,
            "db/query.py", 100
        )
        assert found is not None
        assert found.entry_point_name == "login"

    def test_find_path_by_locations_not_found(self, tracker):
        found = tracker.find_path_by_locations(
            "nonexistent.py", 1,
            "also_nonexistent.py", 1
        )
        assert found is None

    def test_get_unexplored_paths_returns_discovered(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        unexplored = tracker.get_unexplored_paths()
        assert len(unexplored) == 1

        tracker.update_status(path_id, PathStatus.TRACED_SAFE)
        unexplored = tracker.get_unexplored_paths()
        assert len(unexplored) == 0

    def test_get_unexplored_paths_includes_inconclusive(self, tracker):
        path_id = tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )
        tracker.update_status(path_id, PathStatus.INCONCLUSIVE)
        unexplored = tracker.get_unexplored_paths()
        assert len(unexplored) == 1
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerQueries -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# Add to CoverageTracker class in backend/services/coverage_tracker.py

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
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/services/test_coverage_tracker.py::TestCoverageTrackerQueries -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/services/coverage_tracker.py backend/tests/services/test_coverage_tracker.py
git commit -m "feat(coverage): add find_path_by_locations and get_unexplored_paths"
```

---

## Task 7: Create trace_path_verdict Tool Schema

**Files:**
- Modify: `backend/agents/tools.py`
- Test: `backend/tests/agents/test_tools.py`

**Step 1: Write the failing test**

```python
# backend/tests/agents/test_coverage_tools.py
"""Tests for coverage-related tools."""
import pytest
from agents.tools import TRACE_PATH_VERDICT_SCHEMA


class TestTracePathVerdictSchema:
    def test_schema_has_required_fields(self):
        assert TRACE_PATH_VERDICT_SCHEMA["name"] == "trace_path_verdict"
        params = TRACE_PATH_VERDICT_SCHEMA["parameters"]["properties"]
        assert "entry_point_file" in params
        assert "entry_point_line" in params
        assert "sink_file" in params
        assert "sink_line" in params
        assert "verdict" in params
        assert "reasoning" in params
        assert "files_examined" in params

    def test_verdict_enum_values(self):
        params = TRACE_PATH_VERDICT_SCHEMA["parameters"]["properties"]
        verdict_enum = params["verdict"]["enum"]
        assert "safe" in verdict_enum
        assert "vulnerable" in verdict_enum
        assert "blocked" in verdict_enum
        assert "inconclusive" in verdict_enum
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/agents/test_coverage_tools.py -v`
Expected: FAIL with "cannot import name 'TRACE_PATH_VERDICT_SCHEMA'"

**Step 3: Write minimal implementation**

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
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/agents/test_coverage_tools.py -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/agents/tools.py backend/tests/agents/test_coverage_tools.py
git commit -m "feat(coverage): add trace_path_verdict tool schema"
```

---

## Task 8: Implement trace_path_verdict Handler

**Files:**
- Modify: `backend/agents/tools.py`
- Test: `backend/tests/agents/test_coverage_tools.py`

**Step 1: Write the failing test**

```python
# Add to backend/tests/agents/test_coverage_tools.py
from services.coverage_tracker import CoverageTracker, PathStatus
from agents.tools import handle_trace_path_verdict


class TestHandleTracePathVerdict:
    def test_updates_existing_path(self):
        tracker = CoverageTracker("test-agent")
        tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=42,
            entry_point_name="login",
            sink_file="db/query.py",
            sink_line=100,
            sink_type="sql",
            sink_function="cursor.execute"
        )

        broadcasts = []
        def mock_broadcast(event_type, data):
            broadcasts.append((event_type, data))

        result = handle_trace_path_verdict(
            args={
                "entry_point_file": "routes/api.py",
                "entry_point_line": 42,
                "sink_file": "db/query.py",
                "sink_line": 100,
                "verdict": "safe",
                "reasoning": "Uses parameterized query",
                "files_examined": ["routes/api.py", "db/query.py"]
            },
            coverage_tracker=tracker,
            broadcast_fn=mock_broadcast
        )

        assert "safe" in result.lower()
        path = tracker.find_path_by_locations("routes/api.py", 42, "db/query.py", 100)
        assert path.status == PathStatus.TRACED_SAFE
        assert len(broadcasts) == 1
        assert broadcasts[0][0] == "COVERAGE_UPDATE"

    def test_auto_registers_unknown_path(self):
        tracker = CoverageTracker("test-agent")
        broadcasts = []

        result = handle_trace_path_verdict(
            args={
                "entry_point_file": "routes/new.py",
                "entry_point_line": 10,
                "sink_file": "db/new.py",
                "sink_line": 20,
                "verdict": "vulnerable",
                "reasoning": "SQL injection found",
                "files_examined": ["routes/new.py"],
                "finding_id": "finding-123"
            },
            coverage_tracker=tracker,
            broadcast_fn=lambda t, d: broadcasts.append((t, d))
        )

        assert len(tracker.paths) == 1
        path = list(tracker.paths.values())[0]
        assert path.status == PathStatus.TRACED_VULN
        assert path.finding_id == "finding-123"
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/agents/test_coverage_tools.py::TestHandleTracePathVerdict -v`
Expected: FAIL with "cannot import name 'handle_trace_path_verdict'"

**Step 3: Write minimal implementation**

```python
# Add to backend/agents/tools.py
from typing import Callable
from services.coverage_tracker import CoverageTracker, PathStatus


def handle_trace_path_verdict(
    args: dict,
    coverage_tracker: CoverageTracker,
    broadcast_fn: Callable[[str, dict], None]
) -> str:
    """Handle trace_path_verdict tool call."""
    status_map = {
        "safe": PathStatus.TRACED_SAFE,
        "vulnerable": PathStatus.TRACED_VULN,
        "blocked": PathStatus.BLOCKED,
        "inconclusive": PathStatus.INCONCLUSIVE
    }

    # Find or auto-register the path
    record = coverage_tracker.find_path_by_locations(
        args["entry_point_file"],
        args["entry_point_line"],
        args["sink_file"],
        args["sink_line"]
    )

    if record is None:
        # Auto-register discovered path
        path_id = coverage_tracker.register_path(
            entry_point_file=args["entry_point_file"],
            entry_point_line=args["entry_point_line"],
            entry_point_name="discovered",
            sink_file=args["sink_file"],
            sink_line=args["sink_line"],
            sink_type="unknown",
            sink_function="unknown"
        )
        record = coverage_tracker.paths[path_id]

    # Update status
    coverage_tracker.update_status(
        record.id,
        status_map[args["verdict"]],
        reasoning=args["reasoning"],
        finding_id=args.get("finding_id"),
        files_in_path=args["files_examined"]
    )

    # Broadcast update
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

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/agents/test_coverage_tools.py::TestHandleTracePathVerdict -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/agents/tools.py backend/tests/agents/test_coverage_tools.py
git commit -m "feat(coverage): add handle_trace_path_verdict with auto-registration"
```

---

## Task 9: Add Depth Enforcement Config and Check

**Files:**
- Create: `backend/agents/depth_enforcement.py`
- Test: `backend/tests/agents/test_depth_enforcement.py`

**Step 1: Write the failing test**

```python
# backend/tests/agents/test_depth_enforcement.py
"""Tests for depth enforcement."""
import pytest
from agents.depth_enforcement import DepthEnforcementConfig, check_coverage_before_complete
from services.coverage_tracker import CoverageTracker, PathStatus


@pytest.fixture
def tracker_with_paths():
    tracker = CoverageTracker("test-agent")
    for i in range(10):
        tracker.register_path(
            entry_point_file="routes/api.py",
            entry_point_line=i * 10,
            entry_point_name=f"handler_{i}",
            sink_file=f"db/query{i}.py",
            sink_line=100,
            sink_type="sql",
            sink_function="execute"
        )
    return tracker


class TestDepthEnforcement:
    def test_allows_complete_when_coverage_sufficient(self, tracker_with_paths):
        # Trace 9 of 10 paths (90%)
        path_ids = list(tracker_with_paths.paths.keys())
        for path_id in path_ids[:9]:
            tracker_with_paths.update_status(path_id, PathStatus.TRACED_SAFE)

        config = DepthEnforcementConfig(min_coverage_percent=80.0)
        can_complete, challenge = check_coverage_before_complete(tracker_with_paths, config)

        assert can_complete is True
        assert challenge is None

    def test_challenges_when_coverage_insufficient(self, tracker_with_paths):
        # Trace only 5 of 10 paths (50%)
        path_ids = list(tracker_with_paths.paths.keys())
        for path_id in path_ids[:5]:
            tracker_with_paths.update_status(path_id, PathStatus.TRACED_SAFE)

        config = DepthEnforcementConfig(min_coverage_percent=80.0)
        can_complete, challenge = check_coverage_before_complete(tracker_with_paths, config)

        assert can_complete is False
        assert "50.0%" in challenge
        assert "Unexplored paths" in challenge

    def test_challenges_when_too_many_inconclusive(self, tracker_with_paths):
        path_ids = list(tracker_with_paths.paths.keys())
        # Trace 8 as safe, 2 as inconclusive
        for path_id in path_ids[:8]:
            tracker_with_paths.update_status(path_id, PathStatus.TRACED_SAFE)
        for path_id in path_ids[8:]:
            tracker_with_paths.update_status(path_id, PathStatus.INCONCLUSIVE)

        config = DepthEnforcementConfig(min_coverage_percent=80.0, max_inconclusive=1)
        can_complete, challenge = check_coverage_before_complete(tracker_with_paths, config)

        assert can_complete is False
        assert "inconclusive" in challenge.lower()
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/agents/test_depth_enforcement.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'agents.depth_enforcement'"

**Step 3: Write minimal implementation**

```python
# backend/agents/depth_enforcement.py
"""Depth enforcement for coverage-based scan completion."""
from dataclasses import dataclass
from typing import Optional
from services.coverage_tracker import CoverageTracker


@dataclass
class DepthEnforcementConfig:
    """Configuration for depth enforcement."""
    min_coverage_percent: float = 80.0
    max_inconclusive: int = 3
    require_explicit_skip_reason: bool = True


def check_coverage_before_complete(
    coverage_tracker: CoverageTracker,
    config: DepthEnforcementConfig
) -> tuple[bool, Optional[str]]:
    """Check if coverage is sufficient to accept AUDIT_COMPLETE.

    Returns:
        (can_complete, challenge_message)
    """
    stats = coverage_tracker.get_coverage_stats()

    # Check coverage percentage
    if stats.coverage_percent < config.min_coverage_percent:
        remaining = coverage_tracker.get_unexplored_paths()
        paths_summary = "\n".join([
            f"  - {r.entry_point_file}:{r.entry_point_line} -> {r.sink_file}:{r.sink_line}"
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
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/agents/test_depth_enforcement.py -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/agents/depth_enforcement.py backend/tests/agents/test_depth_enforcement.py
git commit -m "feat(coverage): add depth enforcement config and check"
```

---

## Task 10: Add Verdict Reporting Instruction to Base Analysis Prompt

**Files:**
- Modify: `backend/prompts/v2/analysis/base_analysis.py`
- Test: `backend/tests/prompts/test_v2_base_analysis.py`

**Step 1: Write the failing test**

```python
# Add to backend/tests/prompts/test_v2_base_analysis.py

    def test_includes_verdict_reporting_instruction(self):
        prompt = BaseAnalysisPrompt.get_verdict_reporting_instruction()
        assert "trace_path_verdict" in prompt
        assert "safe" in prompt.lower()
        assert "vulnerable" in prompt.lower()
        assert "reasoning" in prompt.lower()
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/prompts/test_v2_base_analysis.py::TestBaseAnalysisPrompt::test_includes_verdict_reporting_instruction -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# Add to BaseAnalysisPrompt class in backend/prompts/v2/analysis/base_analysis.py

    @staticmethod
    def get_verdict_reporting_instruction() -> str:
        """Return instruction for reporting path verdicts."""
        return """
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

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility && python -m pytest backend/tests/prompts/test_v2_base_analysis.py::TestBaseAnalysisPrompt::test_includes_verdict_reporting_instruction -v`
Expected: PASS

**Step 5: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add backend/prompts/v2/analysis/base_analysis.py backend/tests/prompts/test_v2_base_analysis.py
git commit -m "feat(coverage): add verdict reporting instruction to base analysis prompt"
```

---

## Task 11: Create Frontend CoverageTree Component

**Files:**
- Create: `frontend/components/CoveragePanel/CoverageTree.tsx`
- Create: `frontend/components/CoveragePanel/index.ts`

**Step 1: Create the component**

```typescript
// frontend/components/CoveragePanel/CoverageTree.tsx
import React, { useState, useMemo } from 'react';

export interface PathRecord {
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

export interface CoverageStats {
  total: number;
  traced: number;
  remaining: number;
  coveragePercent: number;
  vulnCount?: number;
}

interface CoverageTreeProps {
  paths: PathRecord[];
  stats: CoverageStats;
  onPathClick?: (path: PathRecord) => void;
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
  traced_safe: 'text-green-600',
  traced_vuln: 'text-red-600',
  blocked: 'text-gray-500',
  inconclusive: 'text-yellow-600',
};

interface EntryPointNodeProps {
  paths: PathRecord[];
  onPathClick?: (path: PathRecord) => void;
}

function EntryPointNode({ paths, onPathClick }: EntryPointNodeProps) {
  const [expanded, setExpanded] = useState(true);
  const ep = paths[0].entryPoint;
  const tracedCount = paths.filter(p =>
    ['traced_safe', 'traced_vuln', 'blocked'].includes(p.status)
  ).length;

  return (
    <div className="entry-point-node mb-1">
      <div
        className="cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 p-1 rounded flex items-center"
        onClick={() => setExpanded(!expanded)}
      >
        <span className="mr-1 text-gray-500">{expanded ? 'v' : '>'}</span>
        <span className="font-medium">{ep.route || ep.name}</span>
        <span className="ml-2 text-gray-500 text-sm">
          ({ep.filePath}:{ep.lineNumber})
        </span>
        <span className="ml-auto text-sm text-gray-400">
          {tracedCount}/{paths.length}
        </span>
      </div>

      {expanded && (
        <div className="ml-4 border-l border-gray-200 dark:border-gray-700 pl-2">
          {paths.map(path => (
            <div
              key={path.id}
              className={`p-1 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 rounded text-sm ${STATUS_COLORS[path.status]}`}
              onClick={() => onPathClick?.(path)}
            >
              <span className="font-mono">{STATUS_ICONS[path.status]}</span>
              <span className="ml-1">-{'>'}</span>
              <span className="ml-1">{path.sink.functionName}</span>
              <span className="ml-1 text-gray-500">
                ({path.sink.filePath}:{path.sink.lineNumber})
              </span>
              {path.verdictReasoning && (
                <span className="ml-2 text-gray-400 text-xs italic">
                  - {path.verdictReasoning}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function CoverageTree({ paths, stats, onPathClick }: CoverageTreeProps) {
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
    <div className="coverage-tree h-full flex flex-col">
      {/* Summary bar */}
      <div className="coverage-summary p-2 border-b border-gray-200 dark:border-gray-700 flex items-center gap-4 text-sm">
        <span>
          Coverage: {stats.traced}/{stats.total} ({stats.coveragePercent.toFixed(1)}%)
        </span>
        {stats.vulnCount !== undefined && stats.vulnCount > 0 && (
          <span className="text-red-600">{stats.vulnCount} vulns</span>
        )}
        <span className="text-gray-400">{stats.remaining} remaining</span>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-gray-200 dark:bg-gray-700">
        <div
          className="h-full bg-green-500 transition-all duration-300"
          style={{ width: `${stats.coveragePercent}%` }}
        />
      </div>

      {/* Tree */}
      <div className="tree-content flex-1 overflow-y-auto p-2 font-mono text-sm">
        {paths.length === 0 ? (
          <div className="text-gray-400 text-center py-4">
            No paths discovered yet
          </div>
        ) : (
          Array.from(grouped.entries()).map(([epKey, epPaths]) => (
            <EntryPointNode
              key={epKey}
              paths={epPaths}
              onPathClick={onPathClick}
            />
          ))
        )}
      </div>

      {/* Legend */}
      <div className="legend p-2 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-500 flex gap-3">
        <span>[ ] discovered</span>
        <span className="text-blue-500">[~] in progress</span>
        <span className="text-green-600">[ok] safe</span>
        <span className="text-red-600">[!!] vuln</span>
        <span>[x] blocked</span>
        <span className="text-yellow-600">[?] inconclusive</span>
      </div>
    </div>
  );
}
```

```typescript
// frontend/components/CoveragePanel/index.ts
export { CoverageTree } from './CoverageTree';
export type { PathRecord, CoverageStats } from './CoverageTree';
```

**Step 2: Run TypeScript check**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility/frontend && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hack/.worktrees/coverage-visibility
git add frontend/components/CoveragePanel/
git commit -m "feat(coverage): add CoverageTree frontend component"
```

---

## Summary

| Task | Component | Tests |
|------|-----------|-------|
| 1 | PathStatus enum, PathRecord model | 2 |
| 2 | CoverageStats model | 4 |
| 3 | CoverageTracker.register_path | 3 |
| 4 | CoverageTracker.update_status | 4 |
| 5 | CoverageTracker.get_coverage_stats | 2 |
| 6 | find_path_by_locations, get_unexplored_paths | 4 |
| 7 | trace_path_verdict schema | 2 |
| 8 | handle_trace_path_verdict | 2 |
| 9 | DepthEnforcementConfig, check_coverage_before_complete | 3 |
| 10 | Verdict reporting instruction | 1 |
| 11 | CoverageTree React component | TypeScript check |

**Total: 11 tasks, ~27 tests**
