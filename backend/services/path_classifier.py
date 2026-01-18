"""Path classification for VRP filtering."""
import warnings
from models.schemas import PathClassification, PathClassificationConfig

# Deprecation warning
warnings.warn(
    "path_classifier is deprecated. Use services.finding_filters.PathFilter instead.",
    DeprecationWarning,
    stacklevel=2
)


def classify_path(file_path: str, config: PathClassificationConfig) -> PathClassification:
    """
    Classify file path into runtime/tooling/third_party/unknown.

    Args:
        file_path: File path to classify (can be repo-relative or absolute)
        config: Path classification configuration

    Returns:
        PathClassification enum value

    Priority order (highest to lowest):
        1. third_party_roots (includes test/ci/docs/migration for VRP)
        2. tooling_roots
        3. runtime_roots
        4. unknown
    """
    # Normalize path (handle both relative and absolute paths)
    # For now, work with path as-is; repo-relative normalization can be added if needed
    path = file_path.replace("\\", "/")  # Normalize Windows paths

    # Check in priority order (most specific first)

    # Third party (highest priority)
    for root in config.third_party_roots:
        root_norm = root.rstrip("/")
        if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
            return PathClassification.third_party

    # Test roots (treated as excluded/third_party for VRP)
    for root in config.test_roots:
        root_norm = root.rstrip("/")
        if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
            return PathClassification.third_party

    # CI roots (treated as excluded/third_party for VRP)
    for root in config.ci_roots:
        root_norm = root.rstrip("/")
        if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
            return PathClassification.third_party

    # Docs roots (treated as excluded/third_party for VRP)
    for root in config.docs_roots:
        root_norm = root.rstrip("/")
        if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
            return PathClassification.third_party

    # Migration roots (treated as excluded/third_party for VRP)
    for root in config.migration_roots:
        root_norm = root.rstrip("/")
        if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
            return PathClassification.third_party

    # Tooling
    for root in config.tooling_roots:
        root_norm = root.rstrip("/")
        if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
            return PathClassification.tooling

    # Runtime
    for root in config.runtime_roots:
        root_norm = root.rstrip("/")
        if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
            return PathClassification.runtime

    return PathClassification.unknown
