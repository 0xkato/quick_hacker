"""Tool core utilities for vulnerability analysis.

This package provides the core implementation of security research tools,
organized into focused modules:

- file_operations: File reading, directory listing, code search
- ast_analysis: AST parsing and dataflow tracing
- security_scanning: Secret scanning, dependency auditing, semantic grep
- sink_signals: Sink signal management
- finding_management: Finding reporting and triaging
- flow_tracking: Investigation flow tracking
- validity: Validity checklists and finding finalization
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from services.security_scanners.base import WorkspacePolicy, ScanLimits
from services.tool_cache import ToolCache
from services.git_head_tracker import GitHeadTracker
from services.artifact_service import artifact_service

# Import all mixins
from .file_operations import FileOperationsMixin
from .ast_analysis import ASTAnalysisMixin
from .security_scanning import SecurityScanningMixin
from .sink_signals import SinkSignalsMixin
from .finding_management import FindingManagementMixin
from .flow_tracking import FlowTrackingMixin
from .validity import ValidityMixin


class ToolCore(
    FileOperationsMixin,
    ASTAnalysisMixin,
    SecurityScanningMixin,
    SinkSignalsMixin,
    FindingManagementMixin,
    FlowTrackingMixin,
    ValidityMixin,
):
    """Shared tool implementations for security research agents.

    This class combines all tool functionality using mixins, which are
    called by both:
    - MCP tool handlers (for Claude SDK provider)
    - ToolExecutor methods (for legacy ReAct providers)

    Attributes:
        repo_path: Resolved path to the repository root
        project_id: Project identifier for persistence
        workspace_policy: Policy enforcing security boundaries
    """

    # Valid severity values for report_finding
    VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

    # Default excluded directories
    DEFAULT_EXCLUDED_DIRS = frozenset({
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", ".nuxt", "coverage", "target",
        ".idea", ".vscode", ".cache", ".nyc_output",
    })

    # Maximum file size for reads (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(
        self,
        repo_path: str,
        project_id: str,
        agent_id: str | None = None,
        get_scan_limits: Callable[[], ScanLimits] | None = None,
        cache: ToolCache | None = None,
    ):
        """Initialize ToolCore.

        Args:
            repo_path: Path to the repository root
            project_id: Project identifier for persistence services
            agent_id: Optional agent identifier for flow tracking
            get_scan_limits: Factory function that returns fresh ScanLimits
                            with current remaining budget
            cache: Optional ToolCache instance for caching tool outputs
        """
        self.repo_path = Path(repo_path).resolve()
        self.project_id = project_id
        self.agent_id = agent_id
        self._get_scan_limits = get_scan_limits or (lambda: ScanLimits())
        self.cache = cache

        # Initialize git HEAD tracker if cache is enabled
        if self.cache is not None:
            self.git_head_tracker = GitHeadTracker(str(self.repo_path))
        else:
            self.git_head_tracker = None

        # Create workspace policy
        self.workspace_policy = WorkspacePolicy(
            workspace_root=str(self.repo_path),
            max_file_size=self.MAX_FILE_SIZE,
            excluded_dirs=set(self.DEFAULT_EXCLUDED_DIRS),
        )

        # Span context tracking
        self._current_span_id: str | None = None
        self._current_hypothesis_id: str | None = None

    def set_span_context(
        self,
        span_id: str,
        hypothesis_id: str | None = None
    ) -> None:
        """
        Set current span context for artifact provenance tracking.

        Args:
            span_id: Current span being executed
            hypothesis_id: Optional hypothesis ID
        """
        self._current_span_id = span_id
        self._current_hypothesis_id = hypothesis_id

    def clear_span_context(self) -> None:
        """Clear current span context."""
        self._current_span_id = None
        self._current_hypothesis_id = None

    def _track_artifact_provenance(self, artifact_id: str) -> None:
        """
        Track artifact provenance in current span.

        Args:
            artifact_id: Artifact ID to track
        """
        if not self._current_span_id or not self.agent_id:
            return

        # Import here to avoid circular dependency
        from services.span_service import span_service

        # Add artifact to span
        span_service.attach_artifact(
            agent_id=self.agent_id,
            span_id=self._current_span_id,
            artifact_id=artifact_id
        )

        # Track producer provenance
        artifact_service.add_producer(
            span_id=self._current_span_id,
            artifact_id=artifact_id
        )


__all__ = [
    "ToolCore",
]
