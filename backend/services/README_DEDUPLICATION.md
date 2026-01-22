# Deduplication System Documentation

## Overview

The deduplication system prevents duplicate security findings from being stored in the database. It uses an **overlap-based algorithm** that considers two findings as duplicates if their source code ranges overlap, even partially.

## Algorithm

### Key Principle
Two findings are considered duplicates if:
1. They are from the **same file**
2. Their **line ranges overlap** (even by a single line)

### Why Overlap-Based?
- **Robustness**: Different agents may report slightly different line ranges for the same issue
- **Accuracy**: Prevents near-duplicates that would be missed by exact matching
- **Simplicity**: Clear, deterministic behavior

## Implementation

### Core Functions

#### `create_finding_fingerprint(finding)`
Creates a unique identifier for a finding based on:
- File path
- Start line
- End line

```python
def create_finding_fingerprint(finding: Dict[str, Any]) -> str:
    """
    Create a fingerprint for a finding.

    Args:
        finding: Dict with 'file_path', 'start_line', 'end_line'

    Returns:
        Fingerprint string in format: "filepath:start-end"
    """
```

#### `findings_overlap(f1, f2)`
Checks if two findings overlap:

```python
def findings_overlap(f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
    """
    Check if two findings overlap.

    Two findings overlap if:
    1. They are in the same file
    2. Their line ranges overlap (even by a single line)

    Args:
        f1, f2: Findings with 'file_path', 'start_line', 'end_line'

    Returns:
        True if findings overlap, False otherwise
    """
```

**Overlap Logic:**
```
Range 1: [start1, end1]
Range 2: [start2, end2]

Overlap if: start1 <= end2 AND start2 <= end1
```

#### `deduplicate_findings(findings)`
Removes duplicates from a list of findings:

```python
def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings using overlap detection.

    Strategy: "First wins"
    - Findings are processed in order
    - First occurrence of overlapping findings is kept
    - Later duplicates are discarded

    Args:
        findings: List of finding dicts

    Returns:
        Deduplicated list of findings
    """
```

## How It Works

### 1. Fingerprinting
Each finding gets a fingerprint based on its location:
```
"src/auth.py:10-15"
"src/auth.py:20-25"
```

### 2. Overlap Check
When a new finding arrives, it's compared against all existing findings:
- Same file? Check line range overlap
- Different file? Not a duplicate

### 3. First Wins
The **first** finding to be processed is kept. Later overlapping findings are discarded.

## Usage Examples

### Example 1: Multi-Agent Duplicates

Three agents scan the same file and report the same SQL injection:

```python
findings = [
    {
        "agent": "codex",
        "file_path": "api/database.py",
        "start_line": 45,
        "end_line": 48,
        "title": "SQL Injection in query builder"
    },
    {
        "agent": "sdk",
        "file_path": "api/database.py",
        "start_line": 45,
        "end_line": 49,  # Slightly different end
        "title": "Unsanitized SQL query"
    },
    {
        "agent": "custom",
        "file_path": "api/database.py",
        "start_line": 44,  # Slightly different start
        "end_line": 48,
        "title": "SQL injection vulnerability"
    }
]

deduplicated = deduplicate_findings(findings)
# Result: Only the first finding is kept
# len(deduplicated) == 1
```

**Result**: Only 1 finding stored (from Codex agent, as it was first)

### Example 2: Distinct Findings Preserved

Two findings in the same file but different locations:

```python
findings = [
    {
        "file_path": "app/auth.py",
        "start_line": 10,
        "end_line": 15,
        "title": "Hardcoded password"
    },
    {
        "file_path": "app/auth.py",
        "start_line": 50,
        "end_line": 55,
        "title": "Weak hash algorithm"
    }
]

deduplicated = deduplicate_findings(findings)
# Result: Both findings kept (no overlap)
# len(deduplicated) == 2
```

**Result**: Both findings stored (different line ranges)

### Example 3: Edge Case - Single Line Overlap

```python
findings = [
    {
        "file_path": "utils/crypto.py",
        "start_line": 20,
        "end_line": 30
    },
    {
        "file_path": "utils/crypto.py",
        "start_line": 30,  # Overlaps by 1 line (line 30)
        "end_line": 40
    }
]

deduplicated = deduplicate_findings(findings)
# Result: Only first finding kept (they overlap on line 30)
# len(deduplicated) == 1
```

## Performance Characteristics

- **Time Complexity**: O(n²) where n is the number of findings
  - For each finding, we check against all previously seen findings
  - Acceptable for typical scan sizes (10-1000 findings)

- **Space Complexity**: O(n)
  - Stores fingerprints for all unique findings

- **Optimization Opportunities**:
  - For very large scans (>10,000 findings), consider spatial indexing
  - Group findings by file first to reduce comparisons

## Migration Notes

### Breaking Change
This implementation changes deduplication behavior:

**Before**: Exact fingerprint matching
- Findings with slightly different line ranges were stored as separate findings
- Could result in duplicate issues reported to users

**After**: Overlap-based matching
- Findings with overlapping line ranges are deduplicated
- More aggressive deduplication, fewer duplicates

### Impact
- **Fewer findings stored**: Overlapping findings from multiple agents are now deduplicated
- **More accurate**: Users see distinct issues, not the same issue reported multiple times
- **Better UX**: Cleaner scan results, easier to review

### Testing
The deduplication logic is tested in:
- `tests/test_services_deduplication.py`

Run tests with:
```bash
pytest tests/test_services_deduplication.py -v
```

## Integration Points

The deduplication system is integrated at:

1. **Security service** (`services/security_service.py`)
   - `deduplicate_findings()` called before storing findings
   - Reduces database writes and prevents duplicate reports

2. **Report generation** (`services/report_service.py`)
   - Deduplicated findings ensure clean reports
   - No duplicate issues shown to users

## Future Enhancements

Potential improvements:
1. **Configurable overlap threshold**: Allow tuning how much overlap triggers deduplication
2. **Severity-aware deduplication**: Keep higher-severity findings when deduplicating
3. **Agent priority**: Allow certain agents to take precedence
4. **Cross-file deduplication**: Detect duplicates across different file paths (e.g., moved code)
