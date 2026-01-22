# Finding Deduplication Improvement Design

**Date:** 2026-01-22
**Status:** Approved
**Goal:** Replace exact string matching deduplication with conservative overlap-based matching to eliminate multi-agent/scanner duplicate findings.

## Problem Statement

The current deduplication system uses exact string matching on configured fields (file_path, line_start, vulnerability_type, title). This fails to catch duplicates when:

- Same vulnerability reported by different agents with different titles/descriptions
- Code snippets captured with different formatting or context amounts
- Different confidence scores for the same finding
- Different metadata added by different scanners
- Line numbers off by 1-2 lines due to tool calculation differences

Result: Multiple reports of the same vulnerability at the same location.

## Requirements

**Conservative Deduplication Philosophy:**
- Only merge findings when highly confident they're duplicates
- Better to keep some duplicates than risk merging distinct issues
- First occurrence preserved (discard subsequent duplicates)

**Duplicate Definition:**
Two findings are duplicates if:
- Same file (normalized path)
- Same vulnerability type (normalized)
- Overlapping line ranges (handles ±1-2 line drift and span differences)

**Normalization:**
- File paths: case-insensitive, strip leading `./`, normalize separators
- Vulnerability types: lowercase, strip whitespace
- Ignore variations in: title, description, code_snippet, confidence, metadata

## Design

### Core Algorithm: Enhanced Fingerprinting

**Step 1: Normalize & Group**
- Compute location fingerprint for each finding: `(normalized_path, normalized_vuln_type)`
- Group findings by fingerprint into buckets: `fingerprint -> list[Finding]`
- This reduces comparison space from O(n²) to O(k²) per bucket where k << n

**Step 2: Per-Bucket Overlap Check**
For each fingerprint bucket:
1. Initialize empty "survivors" list
2. For each finding in bucket (in order):
   - Check if its line range overlaps with any survivor's line range
   - If overlap found → skip (it's a duplicate)
   - If no overlap → add to survivors
3. Add all survivors to final deduplicated list

**Step 3: Line Overlap Logic**
- Extract range: `(line_start, line_end or line_start)`
- Two ranges overlap if: `max(start1, start2) <= min(end1, end2)`
- Handles: exact matches, partial overlaps, containment, single-line findings

**First Occurrence Preservation:**
Processing in order + only adding to survivors if no overlap = first finding kept.

### Implementation Components

**Path Normalization:**
```python
def normalize_path(path: str) -> str:
    """Normalize file path for comparison."""
    if not path:
        return ""
    normalized = path.lstrip('./').replace('\\', '/')
    return normalized.lower()
```

**Vulnerability Type Normalization:**
```python
def normalize_vuln_type(vuln_type: str) -> str:
    """Normalize vulnerability type for comparison."""
    if not vuln_type:
        return ""
    return vuln_type.lower().strip()
```

**Line Range Extraction:**
```python
def get_line_range(finding: Finding) -> tuple[int, int]:
    """Get (start, end) line range."""
    return (finding.line_start, finding.line_end or finding.line_start)
```

**Overlap Detection:**
```python
def ranges_overlap(range1: tuple[int, int], range2: tuple[int, int]) -> bool:
    """Check if two line ranges overlap."""
    start1, end1 = range1
    start2, end2 = range2
    return max(start1, start2) <= min(end1, end2)
```

**Main Function:**
```python
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings using conservative overlap-based matching.

    Duplicates are defined as findings with:
    - Same file (normalized path)
    - Same vulnerability type (normalized)
    - Overlapping line ranges

    First occurrence is preserved.
    """
    # Implementation here
```

### Function Signature Changes

**Before:**
```python
def deduplicate_findings(
    findings: list[Finding],
    config: DeduplicationConfig
) -> list[Finding]:
```

**After:**
```python
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
```

**Breaking Change:** Remove `config` parameter and `DeduplicationConfig` dependency. Update all callers.

## Edge Cases

| Case | Behavior |
|------|----------|
| Empty findings list | Return empty list |
| Single finding | Return as-is |
| None file_path | Treat as empty string, group together |
| None vulnerability_type | Treat as empty string, group together |
| None line_end | Use line_start as both start and end |
| line_end < line_start | Treat as single-line at line_start |
| Invalid line_start (≤ 0) | Accept as-is (no validation) |
| All findings identical | Keep only first |
| No overlaps found | Return all findings |

## Performance

**Typical Case:**
- 10-100 findings per scan
- 5-20 unique location buckets
- ~5-10 findings per bucket
- Comparisons per bucket: ~25-100 (very fast)

**Worst Case:**
- 1000 findings in same (file, vuln_type)
- 1000² = 1,000,000 comparisons
- Still manageable, takes ~milliseconds

**Optimization:** Grouping by fingerprint is sufficient. No need for interval trees or complex data structures.

## Testing Strategy

**Unit Tests:**
- `test_normalize_path()` - various path formats
- `test_normalize_vuln_type()` - case variations, whitespace
- `test_get_line_range()` - with/without line_end
- `test_ranges_overlap()` - exact, partial, no overlap, containment
- `test_deduplicate_findings_empty()` - edge cases
- `test_deduplicate_findings_no_duplicates()` - returns all
- `test_deduplicate_findings_exact_duplicates()` - same line
- `test_deduplicate_findings_overlap()` - line drift cases
- `test_deduplicate_findings_multi_agent()` - realistic scenario with varied titles/descriptions

**Integration Tests:**
- Run against real scan results with known duplicates
- Verify first occurrence preserved
- Verify distinct findings not merged

## Migration

**Files to Update:**
1. `backend/services/deduplicator.py` - rewrite function
2. `backend/tests/services/test_deduplicator.py` - update tests
3. All callers of `deduplicate_findings()` - remove config argument

**Backward Compatibility:**
- Breaking change: removes config parameter
- `DeduplicationConfig` model can remain in schemas for future use
- Update callers: `deduplicate_findings(findings, config)` → `deduplicate_findings(findings)`

## Success Metrics

**Before:** 50-100 duplicate findings per scan (same file + line + vuln_type)
**After:** <5 duplicates per scan (only distinct line ranges preserved)

**Validation:** Run on existing scan results and verify duplicate count reduction without losing distinct findings.

## Future Enhancements (Out of Scope)

- Fuzzy title matching for additional confidence
- Merge metadata from duplicates instead of discarding
- Configurable line drift tolerance
- Symbol-based deduplication (same function, different line numbers)

## References

- Current implementation: `backend/services/deduplicator.py`
- Finding model: `backend/models/schemas.py:Finding`
- Triage service (caller): `backend/services/finding_triage_service.py`
