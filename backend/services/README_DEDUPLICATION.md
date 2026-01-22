# Deduplication System Documentation

## Overview

The deduplication system prevents duplicate security findings from being stored in the database. It uses an **overlap-based algorithm** that considers two findings as duplicates if their source code ranges overlap, even partially.

## Algorithm

### Key Principle
Two findings are considered duplicates if:
1. They are from the **same file** (normalized path)
2. They have the **same vulnerability type** (normalized)
3. Their **line ranges overlap** (even by a single line)

### Why Overlap-Based?
- **Robustness**: Different agents may report slightly different line ranges for the same issue
- **Accuracy**: Prevents near-duplicates that would be missed by exact matching
- **Simplicity**: Clear, deterministic behavior

## Implementation

### Core Functions

#### `normalize_path(path)`
Normalizes file paths for comparison:
- Strips leading `./`
- Converts backslashes to forward slashes
- Lowercases (case-insensitive filesystems)

#### `normalize_vuln_type(vuln_type)`
Normalizes vulnerability types for comparison:
- Lowercases
- Strips leading/trailing whitespace

#### `get_line_range(finding)`
Extracts line range from a finding:
- Returns `(line_start, line_end)` tuple
- If `line_end` is None or invalid, uses `line_start` for both

#### `ranges_overlap(range1, range2)`
Checks if two line ranges overlap:

**Overlap Logic:**
```
Range 1: [start1, end1]
Range 2: [start2, end2]

Overlap if: max(start1, start2) <= min(end1, end2)
```

This handles:
- Exact matches
- Partial overlaps
- Containment (one range inside another)
- Touching boundaries (inclusive)

#### `deduplicate_findings(findings)`
Main deduplication function:

```python
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings using conservative overlap-based matching.

    Strategy: "First wins"
    - Group findings by (normalized_path, normalized_vuln_type)
    - Within each group, check for line range overlaps
    - Keep first occurrence, discard subsequent overlapping findings
    """
```

## How It Works

### 1. Grouping by Fingerprint
Findings are grouped by a tuple of `(normalized_path, normalized_vuln_type)`:
- This reduces comparison space from O(n²) to O(k²) per group where k << n
- Only findings in the same file with the same vulnerability type are compared

### 2. Overlap Check Within Groups
For each group:
1. Start with empty "survivors" list
2. For each finding in order:
   - Check if its line range overlaps with any survivor's line range
   - If overlap found → skip (it's a duplicate)
   - If no overlap → add to survivors

### 3. First Wins
The **first** finding to be processed is kept. Later overlapping findings are discarded.

## Usage Examples

### Example 1: Multi-Agent Duplicates

Three agents scan the same file and report the same SQL injection:

```python
from models.schemas import Finding, Severity
from services.deduplicator import deduplicate_findings

findings = [
    Finding(
        id="1",
        agent_id="codex",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="api/database.py",
        line_start=45,
        line_end=48,
        vulnerability_type="SQL Injection",
        title="SQL Injection in query builder",
        description="...",
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    ),
    Finding(
        id="2",
        agent_id="sdk",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="api/database.py",
        line_start=45,
        line_end=49,  # Slightly different end
        vulnerability_type="sql injection",  # Different case
        title="Unsanitized SQL query",
        description="...",
        confidence=0.85,
        created_at=datetime.now(timezone.utc)
    ),
    Finding(
        id="3",
        agent_id="custom",
        repo_id="repo1",
        severity=Severity.HIGH,
        file_path="./api/database.py",  # Leading ./
        line_start=44,  # Slightly different start
        line_end=48,
        vulnerability_type="SQL INJECTION",  # Different case
        title="SQL injection vulnerability",
        description="...",
        confidence=0.8,
        created_at=datetime.now(timezone.utc)
    )
]

deduplicated = deduplicate_findings(findings)
# Result: Only the first finding is kept
# len(deduplicated) == 1
```

**Result**: Only 1 finding stored (from Codex agent, as it was first)
**Why**: All three have same normalized path + vuln type + overlapping lines

### Example 2: Distinct Findings Preserved

Two findings in the same file but different locations:

```python
findings = [
    Finding(
        id="1",
        file_path="app/auth.py",
        line_start=10,
        line_end=15,
        vulnerability_type="Hardcoded Credential",
        title="Hardcoded password",
        # ... other fields
    ),
    Finding(
        id="2",
        file_path="app/auth.py",
        line_start=50,
        line_end=55,
        vulnerability_type="Weak Cryptography",
        title="Weak hash algorithm",
        # ... other fields
    )
]

deduplicated = deduplicate_findings(findings)
# Result: Both findings kept (no overlap)
# len(deduplicated) == 2
```

**Result**: Both findings stored (different line ranges, different vuln types)

### Example 3: Edge Case - Single Line Overlap

```python
findings = [
    Finding(
        id="1",
        file_path="utils/crypto.py",
        line_start=20,
        line_end=30,
        vulnerability_type="Weak Cryptography",
        # ... other fields
    ),
    Finding(
        id="2",
        file_path="utils/crypto.py",
        line_start=30,  # Overlaps by 1 line (line 30)
        line_end=40,
        vulnerability_type="Weak Cryptography",
        # ... other fields
    )
]

deduplicated = deduplicate_findings(findings)
# Result: Only first finding kept (they overlap on line 30)
# len(deduplicated) == 1
```

**Result**: Only 1 finding stored (same file + vuln type + touching at line 30)

## Performance Characteristics

- **Time Complexity**: O(n + Σk²) where:
  - n = total number of findings
  - k = number of findings per (file, vuln_type) group
  - Grouping step: O(n)
  - Per-group overlap checks: O(k²) where k << n
  - Typical case: 10-100 findings with 5-20 groups → ~25-100 comparisons per group
  - Worst case: All findings in same (file, vuln_type) → O(n²)

- **Space Complexity**: O(n)
  - Stores groups and survivors list

- **Why This Works**:
  - Grouping by (path, vuln_type) drastically reduces comparison space
  - Most scans have findings spread across multiple files and types
  - Even large scans (1000+ findings) complete in milliseconds

## Migration Notes

### Breaking Changes

**1. Function Signature**

`deduplicate_findings()` no longer takes a `config` parameter:

```python
# Before:
deduplicate_findings(findings, config)

# After:
deduplicate_findings(findings)
```

**2. Configuration Model Deprecated**

`DeduplicationConfig` is **deprecated and no longer used**:
- `enabled` flag: Deduplication is now always enabled
- `strategy` field: Only overlap-based matching is used
- `exact_match_fields`: No longer configurable

The `DeduplicationConfig` model still exists in `models/schemas.py` for backward compatibility with `TriagePolicy`, but is not used by the deduplication algorithm.

**3. Deduplication Behavior**

**Before**: Exact fingerprint matching
- Findings with slightly different line ranges were stored as separate findings
- Could result in duplicate issues reported to users
- Configurable via `DeduplicationConfig`

**After**: Overlap-based matching
- Findings with overlapping line ranges are deduplicated
- Uses normalized paths and vulnerability types
- Handles ±1-2 line drift automatically
- More aggressive deduplication, fewer duplicates

### Impact
- **Fewer findings stored**: Overlapping findings from multiple agents are now deduplicated
- **More accurate**: Users see distinct issues, not the same issue reported multiple times
- **Better UX**: Cleaner scan results, easier to review
- **Simpler**: No configuration needed, works consistently

### Testing
The deduplication logic is tested in:
- `tests/services/test_deduplicator.py` (29 tests)

Test coverage includes:
- Path normalization (4 tests)
- Vulnerability type normalization (3 tests)
- Line range extraction (3 tests)
- Overlap detection (6 tests)
- Full deduplication scenarios (13 tests)

Run tests with:
```bash
pytest backend/tests/services/test_deduplicator.py -v
```

## Integration Points

The deduplication system is integrated at:

1. **Finding triage service** (`services/finding_triage_service.py`)
   - `deduplicate_findings()` called as first step in triage workflow
   - Always enabled (not conditional)
   - Reduces database writes and prevents duplicate reports

## Future Enhancements

Potential improvements:
1. **Configurable overlap threshold**: Allow tuning how much overlap triggers deduplication
2. **Severity-aware deduplication**: Keep higher-severity findings when deduplicating
3. **Agent priority**: Allow certain agents to take precedence
4. **Cross-file deduplication**: Detect duplicates across different file paths (e.g., moved code)
