"""
File origin classification for First-Party Focus.

Classifies files as first-party, third-party, test, generated, or external
based on path patterns and project scope configuration.
"""

from enum import Enum
from pathlib import Path
from models.schemas import ProjectScope


class FileOrigin(str, Enum):
    """File origin classification."""
    first_party = "first_party"
    third_party = "third_party"
    test = "test"
    generated = "generated"
    external = "external"
    unknown = "unknown"


def to_repo_relative(repo_root: str, path: str) -> str:
    """
    Convert path to repo-relative path.

    Args:
        repo_root: Repository root directory
        path: File path (absolute or relative)

    Returns:
        Repo-relative path with forward slashes
    """
    rr = Path(repo_root).resolve()
    p = Path(path).resolve() if Path(path).is_absolute() else (rr / path).resolve()

    try:
        rel = p.relative_to(rr)
        return str(rel).replace("\\", "/")
    except ValueError:
        # Path is outside repo
        return str(p).replace("\\", "/")


def classify_file_origin(
    *,
    repo_root: str,
    file_path: str,
    scope: ProjectScope
) -> FileOrigin:
    """
    Classify file origin based on path and scope.

    Classification order:
    1. External (outside repo)
    2. Third-party (excluded roots)
    3. Test (test markers/suffixes)
    4. Generated (generated markers)
    5. First-party (primary code roots)
    6. Unknown (doesn't match any pattern)

    Args:
        repo_root: Repository root directory
        file_path: File path to classify
        scope: Project scope configuration

    Returns:
        FileOrigin enum
    """
    rel = to_repo_relative(repo_root, file_path)

    # Outside repo => external
    if rel.startswith("/") or (":" in rel[:4]):
        return FileOrigin.external

    # Excluded roots (match anywhere in path)
    for excluded in scope.excluded_roots:
        excluded_norm = excluded.rstrip("/")
        if (
            rel == excluded_norm
            or rel.startswith(f"{excluded_norm}/")
            or f"/{excluded_norm}/" in f"/{rel}"
        ):
            return FileOrigin.third_party

    # Test files
    test_markers = ["test/", "tests/", "__tests__/", "spec/"]
    test_suffixes = [".spec.", ".test."]
    if any(m in rel for m in test_markers) or any(s in rel for s in test_suffixes):
        return FileOrigin.test

    # Generated code
    if "generated/" in rel or ".generated." in rel or "__generated__" in rel:
        return FileOrigin.generated

    # Primary code roots
    if any(rel.startswith(pr) for pr in scope.primary_code_roots):
        return FileOrigin.first_party

    return FileOrigin.unknown
