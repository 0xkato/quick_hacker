"""Finding deduplication for VRP triage."""
from collections import defaultdict

from models.schemas import Finding


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


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings using overlap-based matching.

    Deduplication strategy:
    1. Normalize file paths and vulnerability types for comparison
    2. Group findings by (normalized_path, normalized_vuln_type)
    3. Within each group, check for line range overlaps
    4. Keep first occurrence, discard subsequent overlapping findings

    Args:
        findings: List of findings to deduplicate

    Returns:
        Deduplicated list of findings (preserves first occurrence)

    Examples:
        Same file, same type, overlapping lines -> deduplicated
        Same file, different type -> kept separate
        Different files -> kept separate
        Non-overlapping lines -> kept separate
    """
    if not findings:
        return []

    # Group findings by (normalized_path, normalized_vuln_type)
    groups: defaultdict[tuple[str, str], list[Finding]] = defaultdict(list)

    for finding in findings:
        norm_path = normalize_path(finding.file_path)
        norm_type = normalize_vuln_type(finding.vulnerability_type)
        fingerprint = (norm_path, norm_type)
        groups[fingerprint].append(finding)

    # Within each group, remove overlapping findings
    deduplicated = []

    for group_findings in groups.values():
        kept_findings = []

        for finding in group_findings:
            range_current = get_line_range(finding)

            # Check if this finding overlaps with any already kept finding
            overlaps = False
            for kept in kept_findings:
                range_kept = get_line_range(kept)
                if ranges_overlap(range_current, range_kept):
                    overlaps = True
                    break

            if not overlaps:
                kept_findings.append(finding)

        deduplicated.extend(kept_findings)

    return deduplicated
