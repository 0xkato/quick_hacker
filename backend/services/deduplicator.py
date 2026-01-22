"""Finding deduplication for VRP triage."""
from models.schemas import Finding, DeduplicationConfig


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


def deduplicate_findings(
    findings: list[Finding],
    config: DeduplicationConfig
) -> list[Finding]:
    """
    Remove duplicate findings based on configured strategy.

    Args:
        findings: List of findings to deduplicate
        config: Deduplication configuration

    Returns:
        Deduplicated list of findings (first occurrence preserved)

    Strategy:
        - "exact": Match on configured fields (default: file_path + line_start + type + title)
        - Others: Not implemented yet
    """
    if not config.enabled:
        return findings

    if config.strategy != "exact":
        raise NotImplementedError(f"Dedup strategy {config.strategy} not implemented")

    seen = set()
    deduplicated = []

    for finding in findings:
        # Build fingerprint from configured fields
        fingerprint_parts = []
        for field in config.exact_match_fields:
            value = getattr(finding, field, None)
            if value is not None:
                fingerprint_parts.append(str(value))

        fingerprint = "|".join(fingerprint_parts)

        if fingerprint not in seen:
            seen.add(fingerprint)
            deduplicated.append(finding)

    return deduplicated
