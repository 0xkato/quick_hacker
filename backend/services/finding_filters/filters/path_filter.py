"""Path-based filtering for findings."""
from models.schemas import Finding, PathClassification, PathClassificationConfig, TriagePolicy


class PathFilter:
    """
    Filter findings based on path classification.

    Consolidates path classification logic and pre-triage filtering.
    Classifies file paths into runtime/tooling/third_party/unknown
    and filters based on policy settings.
    """

    def __init__(self, config: PathClassificationConfig, policy: TriagePolicy):
        """
        Initialize path filter.

        Args:
            config: Path classification configuration
            policy: Triage policy with filter settings
        """
        self.config = config
        self.policy = policy

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """
        Apply path-based filtering to findings.

        Args:
            findings: List of findings to filter

        Returns:
            Filtered list of findings with path_classification attached
        """
        filtered = []

        for finding in findings:
            # Classify path
            path_class = self._classify_path(finding.file_path)

            # Apply filters based on classification
            # Note: _classify_path returns third_party for test/ci/docs/migration paths
            # We need to check specific roots to apply granular filtering
            if path_class == PathClassification.third_party:
                # Check each specific type of third_party path
                should_filter = False

                # Check third_party roots
                if self.policy.filter_third_party:
                    if self._matches_any_root(finding.file_path, self.config.third_party_roots):
                        should_filter = True

                # Check test roots
                if not should_filter and self.policy.filter_tests:
                    if self._matches_any_root(finding.file_path, self.config.test_roots):
                        should_filter = True

                # Check CI roots
                if not should_filter and self.policy.filter_ci:
                    if self._matches_any_root(finding.file_path, self.config.ci_roots):
                        should_filter = True

                # Check docs roots
                if not should_filter and self.policy.filter_docs:
                    if self._matches_any_root(finding.file_path, self.config.docs_roots):
                        should_filter = True

                # Check migration roots
                if not should_filter and self.policy.filter_migrations:
                    if self._matches_any_root(finding.file_path, self.config.migration_roots):
                        should_filter = True

                if should_filter:
                    continue  # Skip this finding

            # Attach classification for later use
            finding.path_classification = path_class
            filtered.append(finding)

        return filtered

    def _classify_path(self, file_path: str) -> PathClassification:
        """
        Classify file path into runtime/tooling/third_party/unknown.

        Args:
            file_path: File path to classify (can be repo-relative or absolute)

        Returns:
            PathClassification enum value

        Priority order (highest to lowest):
            1. third_party_roots (includes test/ci/docs/migration for VRP)
            2. tooling_roots
            3. runtime_roots
            4. unknown
        """
        # Normalize path (handle both relative and absolute paths)
        path = file_path.replace("\\", "/")  # Normalize Windows paths

        # Check in priority order (most specific first)

        # Third party (highest priority)
        if self._matches_any_root(path, self.config.third_party_roots):
            return PathClassification.third_party

        # Test roots (treated as excluded/third_party for VRP)
        if self._matches_any_root(path, self.config.test_roots):
            return PathClassification.third_party

        # CI roots (treated as excluded/third_party for VRP)
        if self._matches_any_root(path, self.config.ci_roots):
            return PathClassification.third_party

        # Docs roots (treated as excluded/third_party for VRP)
        if self._matches_any_root(path, self.config.docs_roots):
            return PathClassification.third_party

        # Migration roots (treated as excluded/third_party for VRP)
        if self._matches_any_root(path, self.config.migration_roots):
            return PathClassification.third_party

        # Tooling
        if self._matches_any_root(path, self.config.tooling_roots):
            return PathClassification.tooling

        # Runtime
        if self._matches_any_root(path, self.config.runtime_roots):
            return PathClassification.runtime

        return PathClassification.unknown

    def _matches_any_root(self, path: str, roots: list[str]) -> bool:
        """
        Check if path matches any of the given roots.

        Args:
            path: File path to check
            roots: List of root paths

        Returns:
            True if path matches any root
        """
        for root in roots:
            root_norm = root.rstrip("/")
            if path.startswith(root_norm + "/") or f"/{root_norm}/" in path:
                return True
        return False
