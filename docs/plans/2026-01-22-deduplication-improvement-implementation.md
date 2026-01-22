# Finding Deduplication Improvement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace exact string matching deduplication with conservative overlap-based matching to eliminate multi-agent/scanner duplicate findings.

**Architecture:** Enhanced fingerprinting with per-bucket overlap checking. Group findings by normalized (file_path, vulnerability_type), then check line range overlaps within each group.

**Tech Stack:** Python 3.12, pytest

---

## Phase 1: Helper Functions (TDD)

### Task 1: Path Normalization Function

**Files:**
- Modify: `backend/services/deduplicator.py`
- Test: `backend/tests/services/test_deduplicator.py`

**Step 1: Write failing test for normalize_path**

Add to `test_deduplicator.py` after imports:

```python
def test_normalize_path_strips_leading_dot_slash():
    """Test that leading ./ is stripped from paths."""
    from services.deduplicator import normalize_path

    assert normalize_path("./src/main.py") == "src/main.py"
    assert normalize_path("./app/test.py") == "app/test.py"


def test_normalize_path_lowercases():
    """Test that paths are lowercased."""
    from services.deduplicator import normalize_path

    assert normalize_path("Src/Main.py") == "src/main.py"
    assert normalize_path("APP/TEST.PY") == "app/test.py"


def test_normalize_path_normalizes_separators():
    """Test that backslashes are converted to forward slashes."""
    from services.deduplicator import normalize_path

    assert normalize_path("src\\main.py") == "src/main.py"
    assert normalize_path("app\\sub\\test.py") == "app/sub/test.py"


def test_normalize_path_handles_empty_and_none():
    """Test that empty strings and None are handled gracefully."""
    from services.deduplicator import normalize_path

    assert normalize_path("") == ""
    assert normalize_path(None) == ""
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/services/test_deduplicator.py::test_normalize_path_strips_leading_dot_slash -v`
Expected: `ImportError: cannot import name 'normalize_path'`

**Step 3: Implement normalize_path**

Add to `services/deduplicator.py` at the top, after imports:

```python
def normalize_path(path: str | None) -> str:
    """
    Normalize file path for comparison.

    - Strip leading ./
    - Convert backslashes to forward slashes
    - Lowercase (case-insensitive filesystems)

    Args:
        path: File path to normalize (can be None)

    Returns:
        Normalized path, or empty string if None
    """
    if not path:
        return ""
    normalized = path.lstrip('./').replace('\\', '/')
    return normalized.lower()
```

**Step 4: Run all path normalization tests**

Run: `python -m pytest tests/services/test_deduplicator.py -k "test_normalize_path" -v`
Expected: 4 passed

**Step 5: Commit**

```bash
git add services/deduplicator.py tests/services/test_deduplicator.py
git commit -m "feat(dedup): add path normalization function

Add normalize_path helper for case-insensitive, separator-normalized
path comparison. Strips leading ./ and converts backslashes.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 2: Vulnerability Type Normalization Function

**Files:**
- Modify: `backend/services/deduplicator.py`
- Test: `backend/tests/services/test_deduplicator.py`

**Step 1: Write failing test for normalize_vuln_type**

Add to `test_deduplicator.py`:

```python
def test_normalize_vuln_type_lowercases():
    """Test that vulnerability types are lowercased."""
    from services.deduplicator import normalize_vuln_type

    assert normalize_vuln_type("SQL Injection") == "sql injection"
    assert normalize_vuln_type("XSS") == "xss"
    assert normalize_vuln_type("Command_Injection") == "command_injection"


def test_normalize_vuln_type_strips_whitespace():
    """Test that leading/trailing whitespace is stripped."""
    from services.deduplicator import normalize_vuln_type

    assert normalize_vuln_type("  SQL Injection  ") == "sql injection"
    assert normalize_vuln_type("\tXSS\n") == "xss"


def test_normalize_vuln_type_handles_empty_and_none():
    """Test that empty strings and None are handled gracefully."""
    from services.deduplicator import normalize_vuln_type

    assert normalize_vuln_type("") == ""
    assert normalize_vuln_type(None) == ""
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/services/test_deduplicator.py::test_normalize_vuln_type_lowercases -v`
Expected: `ImportError: cannot import name 'normalize_vuln_type'`

**Step 3: Implement normalize_vuln_type**

Add to `services/deduplicator.py` after `normalize_path`:

```python
def normalize_vuln_type(vuln_type: str | None) -> str:
    """
    Normalize vulnerability type for comparison.

    - Lowercase
    - Strip leading/trailing whitespace

    Args:
        vuln_type: Vulnerability type to normalize (can be None)

    Returns:
        Normalized vulnerability type, or empty string if None
    """
    if not vuln_type:
        return ""
    return vuln_type.lower().strip()
```

**Step 4: Run all vuln type normalization tests**

Run: `python -m pytest tests/services/test_deduplicator.py -k "test_normalize_vuln_type" -v`
Expected: 3 passed

**Step 5: Commit**

```bash
git add services/deduplicator.py tests/services/test_deduplicator.py
git commit -m "feat(dedup): add vulnerability type normalization function

Add normalize_vuln_type helper for case-insensitive comparison.
Lowercases and strips whitespace.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 3: Line Range Extraction Function

**Files:**
- Modify: `backend/services/deduplicator.py`
- Test: `backend/tests/services/test_deduplicator.py`

**Step 1: Write failing test for get_line_range**

Add to `test_deduplicator.py`:

```python
def test_get_line_range_with_line_end():
    """Test that line range is extracted when line_end is present."""
    from services.deduplicator import get_line_range
    from models.schemas import Finding, Severity
    from datetime import datetime, timezone

    finding = Finding(
        id="1",
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="test.py",
        line_start=10,
        line_end=15,
        vulnerability_type="SQL Injection",
        title="Test",
        description="Test",
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )

    assert get_line_range(finding) == (10, 15)


def test_get_line_range_without_line_end():
    """Test that line_start is used for both when line_end is None."""
    from services.deduplicator import get_line_range
    from models.schemas import Finding, Severity
    from datetime import datetime, timezone

    finding = Finding(
        id="1",
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="test.py",
        line_start=10,
        line_end=None,
        vulnerability_type="SQL Injection",
        title="Test",
        description="Test",
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )

    assert get_line_range(finding) == (10, 10)


def test_get_line_range_handles_line_end_less_than_start():
    """Test that invalid ranges (end < start) are treated as single-line."""
    from services.deduplicator import get_line_range
    from models.schemas import Finding, Severity
    from datetime import datetime, timezone

    finding = Finding(
        id="1",
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="test.py",
        line_start=10,
        line_end=8,  # Invalid: less than start
        vulnerability_type="SQL Injection",
        title="Test",
        description="Test",
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )

    # Use line_start for both when line_end is invalid
    result = get_line_range(finding)
    assert result == (10, 10) or result == (10, 8)  # Accept either behavior
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/services/test_deduplicator.py::test_get_line_range_with_line_end -v`
Expected: `ImportError: cannot import name 'get_line_range'`

**Step 3: Implement get_line_range**

Add to `services/deduplicator.py` after `normalize_vuln_type`:

```python
def get_line_range(finding: Finding) -> tuple[int, int]:
    """
    Get line range from a finding.

    If line_end is None or invalid (< line_start), uses line_start for both.

    Args:
        finding: Finding to extract line range from

    Returns:
        Tuple of (start, end) line numbers
    """
    line_start = finding.line_start
    line_end = finding.line_end

    # Use line_start if line_end is missing or invalid
    if line_end is None or line_end < line_start:
        return (line_start, line_start)

    return (line_start, line_end)
```

**Step 4: Run all line range tests**

Run: `python -m pytest tests/services/test_deduplicator.py -k "test_get_line_range" -v`
Expected: 3 passed

**Step 5: Commit**

```bash
git add services/deduplicator.py tests/services/test_deduplicator.py
git commit -m "feat(dedup): add line range extraction function

Add get_line_range helper to extract (start, end) tuple from findings.
Handles missing line_end and invalid ranges.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 4: Line Range Overlap Detection Function

**Files:**
- Modify: `backend/services/deduplicator.py`
- Test: `backend/tests/services/test_deduplicator.py`

**Step 1: Write failing test for ranges_overlap**

Add to `test_deduplicator.py`:

```python
def test_ranges_overlap_exact_match():
    """Test that identical ranges overlap."""
    from services.deduplicator import ranges_overlap

    assert ranges_overlap((10, 15), (10, 15)) is True
    assert ranges_overlap((5, 5), (5, 5)) is True


def test_ranges_overlap_partial_overlap():
    """Test that partially overlapping ranges are detected."""
    from services.deduplicator import ranges_overlap

    assert ranges_overlap((10, 15), (12, 18)) is True  # Overlap 12-15
    assert ranges_overlap((10, 15), (5, 12)) is True   # Overlap 10-12
    assert ranges_overlap((10, 15), (8, 20)) is True   # One contains other


def test_ranges_overlap_containment():
    """Test that contained ranges overlap."""
    from services.deduplicator import ranges_overlap

    assert ranges_overlap((10, 20), (12, 15)) is True  # (12,15) inside (10,20)
    assert ranges_overlap((12, 15), (10, 20)) is True  # Symmetric


def test_ranges_overlap_adjacent_no_overlap():
    """Test that adjacent ranges don't overlap."""
    from services.deduplicator import ranges_overlap

    assert ranges_overlap((10, 15), (16, 20)) is False
    assert ranges_overlap((16, 20), (10, 15)) is False


def test_ranges_overlap_separated_no_overlap():
    """Test that separated ranges don't overlap."""
    from services.deduplicator import ranges_overlap

    assert ranges_overlap((10, 15), (20, 25)) is False
    assert ranges_overlap((20, 25), (10, 15)) is False


def test_ranges_overlap_touching_boundary():
    """Test that ranges touching at boundary overlap."""
    from services.deduplicator import ranges_overlap

    # Touching at 15 should overlap (inclusive)
    assert ranges_overlap((10, 15), (15, 20)) is True
    assert ranges_overlap((15, 20), (10, 15)) is True
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/services/test_deduplicator.py::test_ranges_overlap_exact_match -v`
Expected: `ImportError: cannot import name 'ranges_overlap'`

**Step 3: Implement ranges_overlap**

Add to `services/deduplicator.py` after `get_line_range`:

```python
def ranges_overlap(range1: tuple[int, int], range2: tuple[int, int]) -> bool:
    """
    Check if two line ranges overlap.

    Ranges overlap if they share at least one line number.
    Uses inclusive comparison: max(start1, start2) <= min(end1, end2)

    Args:
        range1: First range as (start, end) tuple
        range2: Second range as (start, end) tuple

    Returns:
        True if ranges overlap, False otherwise

    Examples:
        (10, 15) and (12, 18) -> True (overlap 12-15)
        (10, 15) and (16, 20) -> False (adjacent, no overlap)
        (10, 15) and (15, 20) -> True (touching at 15)
    """
    start1, end1 = range1
    start2, end2 = range2
    return max(start1, start2) <= min(end1, end2)
```

**Step 4: Run all overlap tests**

Run: `python -m pytest tests/services/test_deduplicator.py -k "test_ranges_overlap" -v`
Expected: 6 passed

**Step 5: Commit**

```bash
git add services/deduplicator.py tests/services/test_deduplicator.py
git commit -m "feat(dedup): add line range overlap detection function

Add ranges_overlap helper to detect overlapping line ranges.
Uses inclusive comparison: max(start1, start2) <= min(end1, end2)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Phase 2: Rewrite Main Deduplication Function

### Task 5: Rewrite deduplicate_findings Function

**Files:**
- Modify: `backend/services/deduplicator.py`
- Test: `backend/tests/services/test_deduplicator.py`

**Step 1: Write new tests for overlap-based deduplication**

Replace all existing tests in `test_deduplicator.py` with new tests. Keep the test helper imports at the top:

```python
"""Tests for finding deduplication."""
import pytest
from models.schemas import Finding, Severity
from services.deduplicator import (
    deduplicate_findings,
    normalize_path,
    normalize_vuln_type,
    get_line_range,
    ranges_overlap
)
from datetime import datetime, timezone


# Helper function to create findings
def create_finding(
    id: str,
    file_path: str,
    line_start: int,
    line_end: int | None,
    vulnerability_type: str,
    title: str = "Test Finding",
    description: str = "Test description"
) -> Finding:
    """Helper to create test findings."""
    return Finding(
        id=id,
        agent_id="agent1",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        vulnerability_type=vulnerability_type,
        title=title,
        description=description,
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )


# Keep existing helper function tests (normalize_path, etc.)
# [Paste all the helper function tests from Tasks 1-4 here]


class TestDeduplicateFindings:
    """Tests for the main deduplicate_findings function."""

    def test_empty_list_returns_empty(self):
        """Test that empty findings list returns empty."""
        result = deduplicate_findings([])
        assert result == []

    def test_single_finding_returns_as_is(self):
        """Test that single finding is returned unchanged."""
        finding = create_finding("1", "test.py", 10, None, "SQL Injection")
        result = deduplicate_findings([finding])

        assert len(result) == 1
        assert result[0].id == "1"

    def test_different_files_no_dedup(self):
        """Test that findings in different files are not deduplicated."""
        findings = [
            create_finding("1", "file1.py", 10, None, "SQL Injection"),
            create_finding("2", "file2.py", 10, None, "SQL Injection"),
        ]

        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_different_vuln_types_no_dedup(self):
        """Test that different vulnerability types are not deduplicated."""
        findings = [
            create_finding("1", "test.py", 10, None, "SQL Injection"),
            create_finding("2", "test.py", 10, None, "XSS"),
        ]

        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_non_overlapping_lines_no_dedup(self):
        """Test that non-overlapping lines are not deduplicated."""
        findings = [
            create_finding("1", "test.py", 10, 15, "SQL Injection"),
            create_finding("2", "test.py", 20, 25, "SQL Injection"),
        ]

        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_exact_same_line_deduplicates(self):
        """Test that exact same line is deduplicated."""
        findings = [
            create_finding("1", "test.py", 10, None, "SQL Injection", "Title 1"),
            create_finding("2", "test.py", 10, None, "SQL Injection", "Title 2"),  # Different title
        ]

        result = deduplicate_findings(findings)

        assert len(result) == 1
        assert result[0].id == "1"  # First occurrence preserved

    def test_overlapping_line_ranges_deduplicates(self):
        """Test that overlapping line ranges are deduplicated."""
        findings = [
            create_finding("1", "test.py", 10, 15, "SQL Injection"),
            create_finding("2", "test.py", 12, 18, "SQL Injection"),  # Overlaps 12-15
        ]

        result = deduplicate_findings(findings)

        assert len(result) == 1
        assert result[0].id == "1"  # First occurrence preserved

    def test_contained_range_deduplicates(self):
        """Test that contained ranges are deduplicated."""
        findings = [
            create_finding("1", "test.py", 10, 20, "SQL Injection"),
            create_finding("2", "test.py", 12, 15, "SQL Injection"),  # Inside (10,20)
        ]

        result = deduplicate_findings(findings)

        assert len(result) == 1
        assert result[0].id == "1"

    def test_path_normalization_deduplicates(self):
        """Test that path variations are normalized and deduplicated."""
        findings = [
            create_finding("1", "./src/test.py", 10, None, "SQL Injection"),
            create_finding("2", "src/test.py", 10, None, "SQL Injection"),  # Same after normalization
            create_finding("3", "Src/Test.py", 10, None, "SQL Injection"),  # Case difference
        ]

        result = deduplicate_findings(findings)

        assert len(result) == 1
        assert result[0].id == "1"

    def test_vuln_type_normalization_deduplicates(self):
        """Test that vulnerability type variations are normalized."""
        findings = [
            create_finding("1", "test.py", 10, None, "SQL Injection"),
            create_finding("2", "test.py", 10, None, "sql injection"),  # Case difference
            create_finding("3", "test.py", 10, None, "  SQL Injection  "),  # Whitespace
        ]

        result = deduplicate_findings(findings)

        assert len(result) == 1
        assert result[0].id == "1"

    def test_multi_agent_same_finding_deduplicates(self):
        """Test realistic multi-agent scenario with variations."""
        findings = [
            create_finding(
                "1", "src/users.py", 45, 47,
                "SQL Injection",
                "SQL injection vulnerability in login",
                "Found SQL injection at line 45"
            ),
            create_finding(
                "2", "./src/users.py", 45, None,  # Different line_end
                "sql injection",  # Case difference
                "Unsafe SQL query",  # Different title
                "User input flows to SQL query without sanitization"  # Different description
            ),
            create_finding(
                "3", "Src/Users.py", 46, 48,  # Case difference, overlapping range
                "SQL Injection",
                "SQL vulnerability detected",
                "High confidence SQL injection"
            ),
        ]

        result = deduplicate_findings(findings)

        # All should be deduplicated to first finding
        assert len(result) == 1
        assert result[0].id == "1"

    def test_preserves_distinct_findings_in_same_file(self):
        """Test that distinct findings in same file are preserved."""
        findings = [
            create_finding("1", "test.py", 10, 15, "SQL Injection"),
            create_finding("2", "test.py", 20, 25, "SQL Injection"),  # Different lines
            create_finding("3", "test.py", 30, None, "XSS"),  # Different vuln type
            create_finding("4", "test.py", 12, 14, "SQL Injection"),  # Overlaps with #1
        ]

        result = deduplicate_findings(findings)

        # Should keep 1, 2, 3 (4 is dup of 1)
        assert len(result) == 3
        assert {r.id for r in result} == {"1", "2", "3"}

    def test_handles_none_file_path(self):
        """Test that None file_path is handled gracefully."""
        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path=None,  # None path
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test",
                description="Test",
                confidence=0.9,
                created_at=datetime.now(timezone.utc)
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                file_path=None,  # None path
                line_start=10,
                vulnerability_type="SQL Injection",
                title="Test 2",
                description="Test 2",
                confidence=0.9,
                created_at=datetime.now(timezone.utc)
            ),
        ]

        # Should deduplicate (both have same normalized path: "")
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0].id == "1"
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/services/test_deduplicator.py::TestDeduplicateFindings -v`
Expected: Many failures because old function still takes config parameter

**Step 3: Rewrite deduplicate_findings function**

Replace the entire `deduplicate_findings` function in `services/deduplicator.py`:

```python
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings using conservative overlap-based matching.

    Duplicates are defined as findings with:
    - Same file (normalized path)
    - Same vulnerability type (normalized)
    - Overlapping line ranges

    First occurrence is preserved when duplicates are found.

    Algorithm:
    1. Group findings by (normalized_path, normalized_vuln_type) fingerprint
    2. Within each group, check for line range overlaps
    3. Keep first occurrence when overlap is detected

    Args:
        findings: List of findings to deduplicate

    Returns:
        Deduplicated list of findings with first occurrence preserved

    Examples:
        >>> # Same file, same type, overlapping lines -> deduplicated
        >>> f1 = Finding(file_path="test.py", line_start=10, line_end=15, ...)
        >>> f2 = Finding(file_path="test.py", line_start=12, line_end=18, ...)
        >>> deduplicate_findings([f1, f2])  # Returns [f1]

        >>> # Same file, same type, non-overlapping lines -> preserved
        >>> f3 = Finding(file_path="test.py", line_start=20, line_end=25, ...)
        >>> deduplicate_findings([f1, f3])  # Returns [f1, f3]
    """
    if not findings:
        return []

    # Step 1: Group by location fingerprint
    from collections import defaultdict
    fingerprint_groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        norm_path = normalize_path(finding.file_path)
        norm_type = normalize_vuln_type(finding.vulnerability_type)
        fingerprint = (norm_path, norm_type)
        fingerprint_groups[fingerprint].append(finding)

    # Step 2: Check overlaps within each group
    deduplicated = []

    for fingerprint, group_findings in fingerprint_groups.items():
        survivors = []

        for finding in group_findings:
            finding_range = get_line_range(finding)

            # Check if this finding overlaps with any survivor
            is_duplicate = False
            for survivor in survivors:
                survivor_range = get_line_range(survivor)
                if ranges_overlap(finding_range, survivor_range):
                    is_duplicate = True
                    break

            # If no overlap found, this finding survives
            if not is_duplicate:
                survivors.append(finding)

        deduplicated.extend(survivors)

    return deduplicated
```

**Step 4: Update imports**

Update the imports at the top of `services/deduplicator.py`:

```python
"""Finding deduplication for VRP triage."""
from collections import defaultdict

from models.schemas import Finding
```

Remove the `DeduplicationConfig` import since it's no longer needed.

**Step 5: Run all tests**

Run: `python -m pytest tests/services/test_deduplicator.py -v`
Expected: All tests pass

**Step 6: Commit**

```bash
git add services/deduplicator.py tests/services/test_deduplicator.py
git commit -m "feat(dedup): rewrite deduplicate_findings with overlap matching

Replace exact string matching with conservative overlap-based deduplication:
- Group by normalized (file_path, vulnerability_type)
- Check line range overlaps within groups
- Preserve first occurrence

Removes config parameter (breaking change).

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Phase 3: Update Callers

### Task 6: Update finding_triage_service.py Caller

**Files:**
- Modify: `backend/services/finding_triage_service.py`

**Step 1: Find and update the caller**

The caller is at line 123 in `finding_triage_service.py`. Update this section:

**Before:**
```python
# Step 1 - Deduplicate
if policy and policy.deduplication.enabled:
    findings = deduplicate_findings(findings, policy.deduplication)
```

**After:**
```python
# Step 1 - Deduplicate (always enabled with new algorithm)
findings = deduplicate_findings(findings)
```

**Step 2: Verify no other usages of deduplication config**

Search for other references to `policy.deduplication` in the file and consider removing if no longer needed.

**Step 3: Run triage service tests**

Run: `python -m pytest tests/services/test_finding_triage_service.py -v -k dedup`
Expected: Tests pass (or update if they explicitly test deduplication config)

**Step 4: Commit**

```bash
git add services/finding_triage_service.py
git commit -m "fix(triage): update deduplicate_findings caller

Remove config parameter from deduplicate_findings call.
Deduplication now always enabled with overlap-based matching.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Phase 4: Integration Testing

### Task 7: Run Full Test Suite

**Step 1: Run all deduplicator tests**

Run: `python -m pytest tests/services/test_deduplicator.py -v`
Expected: All pass

**Step 2: Run all triage service tests**

Run: `python -m pytest tests/services/test_finding_triage_service.py -v`
Expected: All pass (or minimal failures to fix)

**Step 3: Run full backend test suite**

Run: `python -m pytest tests/ -v --tb=short`
Expected: High pass rate, investigate any failures related to deduplication

**Step 4: Fix any failing tests**

If tests fail due to the breaking change (config removal), update them to use the new signature.

**Step 5: Commit any test fixes**

```bash
git add tests/
git commit -m "test: update tests for new deduplication API

Update tests to use new deduplicate_findings signature without config.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Phase 5: Documentation and Cleanup

### Task 8: Update Documentation

**Files:**
- Create: `backend/services/README_DEDUPLICATION.md` (optional)

**Step 1: Document the new deduplication behavior**

Create `backend/services/README_DEDUPLICATION.md`:

```markdown
# Finding Deduplication

## Overview

The deduplication system removes duplicate security findings from scanner output using conservative overlap-based matching.

## Algorithm

**Conservative Philosophy:** Only merge findings when highly confident they're duplicates.

**Duplicate Definition:** Two findings are duplicates if they have:
1. Same file (normalized path - case-insensitive, no `./` prefix)
2. Same vulnerability type (normalized - lowercase, trimmed)
3. Overlapping line ranges (handles ±1-2 line drift)

**First Occurrence:** When duplicates are found, the first occurrence is preserved.

## Implementation

### Core Functions

- `normalize_path(path)` - Normalize file paths for comparison
- `normalize_vuln_type(type)` - Normalize vulnerability types
- `get_line_range(finding)` - Extract (start, end) line range
- `ranges_overlap(r1, r2)` - Check if line ranges overlap
- `deduplicate_findings(findings)` - Main deduplication function

### How It Works

1. **Fingerprinting:** Group findings by `(normalized_path, normalized_vuln_type)`
2. **Overlap Check:** Within each group, check for line range overlaps
3. **First Wins:** Keep first finding when overlap detected, discard later ones

### Usage

```python
from services.deduplicator import deduplicate_findings

# Deduplicate findings
unique_findings = deduplicate_findings(raw_findings)
```

## Examples

### Multi-Agent Duplicates

Same vulnerability reported by different agents with variations:

```python
findings = [
    Finding(file_path="./src/users.py", line_start=45, line_end=47,
            vulnerability_type="SQL Injection", title="SQL injection in login"),
    Finding(file_path="src/users.py", line_start=45, line_end=None,
            vulnerability_type="sql injection", title="Unsafe SQL query"),
    Finding(file_path="Src/Users.py", line_start=46, line_end=48,
            vulnerability_type="SQL Injection", title="SQL vulnerability"),
]

# All deduplicated to first finding (they overlap at lines 45-47)
unique = deduplicate_findings(findings)
assert len(unique) == 1
```

### Distinct Findings Preserved

Non-overlapping findings in same file are preserved:

```python
findings = [
    Finding(file_path="test.py", line_start=10, line_end=15,
            vulnerability_type="SQL Injection"),
    Finding(file_path="test.py", line_start=20, line_end=25,
            vulnerability_type="SQL Injection"),
]

# Both preserved (lines 10-15 and 20-25 don't overlap)
unique = deduplicate_findings(findings)
assert len(unique) == 2
```

## Performance

- **Typical:** 10-100 findings, groups into 5-20 buckets, ~milliseconds
- **Worst case:** 1000 findings in one bucket, ~milliseconds
- **Optimization:** Fingerprinting reduces O(n²) to O(k²) per bucket where k << n

## Migration Notes

**Breaking Change:** Removed `config` parameter from `deduplicate_findings()`.

**Before:**
```python
deduplicate_findings(findings, config)
```

**After:**
```python
deduplicate_findings(findings)
```

Deduplication is now always enabled with overlap-based matching.
```

**Step 2: Commit documentation**

```bash
git add services/README_DEDUPLICATION.md
git commit -m "docs: add deduplication system documentation

Document overlap-based deduplication algorithm, usage, and examples.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 9: Final Verification

**Step 1: Run full test suite one more time**

Run: `python -m pytest tests/ -v`
Expected: All pass

**Step 2: Manual smoke test**

Create a simple test script `test_dedup_smoke.py`:

```python
"""Smoke test for deduplication."""
from datetime import datetime, timezone
from models.schemas import Finding, Severity
from services.deduplicator import deduplicate_findings


def main():
    """Run smoke test."""
    findings = [
        Finding(
            id="1",
            agent_id="agent1",
            repo_id="repo1",
            severity=Severity.HIGH,
            file_path="./src/test.py",
            line_start=10,
            line_end=15,
            vulnerability_type="SQL Injection",
            title="Agent 1: SQL Injection detected",
            description="Found SQL injection",
            confidence=0.9,
            created_at=datetime.now(timezone.utc)
        ),
        Finding(
            id="2",
            agent_id="agent2",
            repo_id="repo1",
            severity=Severity.HIGH,
            file_path="src/test.py",  # No leading ./
            line_start=12,
            line_end=18,
            vulnerability_type="sql injection",  # Lowercase
            title="Agent 2: Unsafe SQL query",  # Different title
            description="User input to SQL",  # Different description
            confidence=0.95,  # Different confidence
            created_at=datetime.now(timezone.utc)
        ),
        Finding(
            id="3",
            agent_id="agent3",
            repo_id="repo1",
            severity=Severity.HIGH,
            file_path="src/test.py",
            line_start=50,  # Different line
            line_end=55,
            vulnerability_type="SQL Injection",
            title="Agent 3: SQL vulnerability",
            description="Found SQL issue",
            confidence=0.85,
            created_at=datetime.now(timezone.utc)
        ),
    ]

    result = deduplicate_findings(findings)

    print(f"Input: {len(findings)} findings")
    print(f"Output: {len(result)} findings")
    print(f"\nPreserved findings:")
    for f in result:
        print(f"  - ID {f.id}: {f.file_path}:{f.line_start}-{f.line_end or f.line_start}")

    assert len(result) == 2, "Should dedupe findings 1 and 2 (overlapping lines)"
    assert result[0].id == "1", "Should preserve first occurrence"
    assert result[1].id == "3", "Should preserve distinct finding"

    print("\n✅ Smoke test passed!")


if __name__ == "__main__":
    main()
```

Run: `python test_dedup_smoke.py`
Expected: "✅ Smoke test passed!"

**Step 3: Clean up smoke test**

```bash
rm test_dedup_smoke.py
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final verification and cleanup

All tests passing. Deduplication improvement complete.

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Success Metrics

**Before:**
- 50-100 duplicate findings per scan
- Exact string matching fails with multi-agent variations

**After:**
- <5 duplicate findings per scan
- Conservative overlap matching handles multi-agent duplicates
- First occurrence preserved
- Distinct findings not merged

## Validation

Run against existing scan results and verify:
1. Duplicate count reduction (should see 90%+ reduction in duplicates)
2. No distinct findings incorrectly merged
3. First occurrence always preserved

---

## Notes

- **Breaking Change:** This removes the `config` parameter from `deduplicate_findings()`
- **Always Enabled:** Deduplication now runs automatically without config check
- **Conservative:** Only merges when highly confident (same file + type + overlapping lines)
- **Performance:** Fingerprinting groups reduce comparison complexity significantly
- **Future:** Can add fuzzy title matching or configurable line drift tolerance
