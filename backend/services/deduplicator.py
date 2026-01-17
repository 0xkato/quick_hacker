"""Finding deduplication for VRP triage."""
from models.schemas import Finding, DeduplicationConfig


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
