"""Pre-triage filtering for VRP policies."""
import warnings
from models.schemas import Finding, TriagePolicy, PathClassification
from services.path_classifier import classify_path

# Deprecation warning
warnings.warn(
    "pre_triage_filter is deprecated. Use services.finding_filters.PathFilter instead.",
    DeprecationWarning,
    stacklevel=2
)


def pre_filter_findings(
    findings: list[Finding],
    policy: TriagePolicy
) -> list[Finding]:
    """
    Filter findings based on path classification before triage.

    Args:
        findings: List of findings to filter
        policy: Triage policy with filter settings

    Returns:
        Filtered list of findings with path_classification attached

    Filtering logic:
        - Classify each finding's path
        - Apply policy filters (filter_third_party, filter_tests, etc.)
        - Attach path_classification to surviving findings
    """
    filtered = []

    for finding in findings:
        # Classify path
        path_class = classify_path(finding.file_path, policy.path_classification)

        # Apply filters based on classification
        # Note: classify_path returns third_party for test/ci/docs/migration paths
        # We need to check specific roots to apply granular filtering
        if path_class == PathClassification.third_party:
            # Check each specific type of third_party path
            should_filter = False

            # Check third_party roots
            if policy.filter_third_party:
                for root in policy.path_classification.third_party_roots:
                    root_norm = root.rstrip("/")
                    if finding.file_path.startswith(root_norm + "/") or f"/{root_norm}/" in finding.file_path:
                        should_filter = True
                        break

            # Check test roots
            if not should_filter and policy.filter_tests:
                for root in policy.path_classification.test_roots:
                    root_norm = root.rstrip("/")
                    if finding.file_path.startswith(root_norm + "/") or f"/{root_norm}/" in finding.file_path:
                        should_filter = True
                        break

            # Check CI roots
            if not should_filter and policy.filter_ci:
                for root in policy.path_classification.ci_roots:
                    root_norm = root.rstrip("/")
                    if finding.file_path.startswith(root_norm + "/") or f"/{root_norm}/" in finding.file_path:
                        should_filter = True
                        break

            # Check docs roots
            if not should_filter and policy.filter_docs:
                for root in policy.path_classification.docs_roots:
                    root_norm = root.rstrip("/")
                    if finding.file_path.startswith(root_norm + "/") or f"/{root_norm}/" in finding.file_path:
                        should_filter = True
                        break

            # Check migration roots
            if not should_filter and policy.filter_migrations:
                for root in policy.path_classification.migration_roots:
                    root_norm = root.rstrip("/")
                    if finding.file_path.startswith(root_norm + "/") or f"/{root_norm}/" in finding.file_path:
                        should_filter = True
                        break

            if should_filter:
                continue  # Skip this finding

        # Attach classification for later use
        finding.path_classification = path_class
        filtered.append(finding)

    return filtered
