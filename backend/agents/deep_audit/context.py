"""Scan context for Deep Audit - isolated state per scan.

This module provides a ScanContext class that encapsulates all per-scan state,
replacing the global variables that prevented concurrent scans.

Usage:
    ctx = ScanContext.create(project_id="proj-123", repo_path="/path/to/repo")

    # Pass context to functions instead of using globals
    result = await dispatch_wave(ctx, wave_plan)
    content = read_memories(ctx, "/memories/signals/sinks.json")
"""

import uuid
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from agents.deep_audit.filesystem import MemoriesFilesystem
    from agents.deep_audit.dispatcher import WaveDispatcher
    from agents.deep_audit.state import CampaignState
    from agents.deep_audit.foundation import FoundationContext
    from agents.deep_audit.calibration import CalibrationStore, ConfidenceCalibrator


@dataclass
class ScanContext:
    """Isolated context for a single scan.

    Encapsulates all per-scan state that was previously in global variables.
    Each concurrent scan gets its own context instance, enabling safe
    parallel execution.

    Attributes:
        scan_id: Unique identifier for this scan
        project_id: Project being scanned
        repo_path: Path to repository
        filesystem: MemoriesFilesystem instance for this scan
        dispatcher: WaveDispatcher instance for this scan
        state: CampaignState tracking scan progress
        foundation_context: Foundation Context from Foundation Phase
        calibration_store: CalibrationStore for specialist tracking
        calibrator: ConfidenceCalibrator for verdict weighting
    """
    scan_id: str
    project_id: str
    repo_path: str
    filesystem: "MemoriesFilesystem"
    dispatcher: Optional["WaveDispatcher"] = None
    state: Optional["CampaignState"] = None
    foundation_context: Optional["FoundationContext"] = None
    calibration_store: Optional["CalibrationStore"] = None
    calibrator: Optional["ConfidenceCalibrator"] = None
    current_wave_id: int = 0

    @classmethod
    def create(
        cls,
        project_id: str,
        repo_path: str,
        scan_tier: str = "quick",
        provider_config: Optional[dict] = None,
        on_message=None,
        parent_agent_id: Optional[str] = None,
    ) -> "ScanContext":
        """Create a new scan context with all components initialized.

        Args:
            project_id: Unique project identifier
            repo_path: Path to the repository to scan
            scan_tier: Scan tier (quick, medium, pro, etc.)
            provider_config: LLM provider configuration
            on_message: WebSocket message callback
            parent_agent_id: Parent agent ID for logging

        Returns:
            Fully initialized ScanContext
        """
        from agents.deep_audit.filesystem import MemoriesFilesystem
        from agents.deep_audit.dispatcher import WaveDispatcher
        from agents.deep_audit.state import CampaignState
        from agents.deep_audit.calibration import CalibrationStore, ConfidenceCalibrator
        import time

        # Create filesystem
        filesystem = MemoriesFilesystem(project_id, repo_path)

        # Create dispatcher
        dispatcher = WaveDispatcher(
            repo_path=repo_path,
            filesystem=filesystem,
            provider_config=provider_config or {},
            on_message=on_message,
            parent_agent_id=parent_agent_id,
        )

        # Create campaign state
        # Time budgets by tier
        budgets = {
            "quick": 300,
            "medium": 900,
            "standard": 900,
            "advanced": 1800,
            "deep": 1800,
            "pro": 3600,
            "exhaustive": 3600,
            "ultra": 14400,
            "evil": 86400,
        }
        time_budget = budgets.get(scan_tier, 300)

        state = CampaignState(
            project_id=project_id,
            scan_tier=scan_tier,
            deadline=time.time() + time_budget,
        )

        # Create calibration
        calibration_path = str(filesystem.memory_root / "calibration")
        calibration_store = CalibrationStore(calibration_path)
        calibrator = ConfidenceCalibrator(calibration_store)

        return cls(
            scan_id=str(uuid.uuid4())[:8],
            project_id=project_id,
            repo_path=repo_path,
            filesystem=filesystem,
            dispatcher=dispatcher,
            state=state,
            calibration_store=calibration_store,
            calibrator=calibrator,
        )

    def set_foundation_context(self, context: "FoundationContext"):
        """Set the Foundation Context after Foundation Phase completes."""
        self.foundation_context = context

    def set_wave_id(self, wave_id: int):
        """Set the current wave ID."""
        self.current_wave_id = wave_id


# Thread-local storage for backward compatibility during migration
# New code should pass context explicitly
import threading
_context_local = threading.local()


def get_current_context() -> Optional[ScanContext]:
    """Get the current scan context (for backward compatibility).

    During migration, this allows old code to access the context
    without explicit passing. New code should use explicit context passing.
    """
    return getattr(_context_local, 'context', None)


def set_current_context(ctx: Optional[ScanContext]):
    """Set the current scan context (for backward compatibility).

    During migration, this allows old code to access the context.
    Call this at the start of a scan and clear it at the end.
    """
    _context_local.context = ctx


class ScanContextManager:
    """Context manager for scan execution.

    Automatically sets and clears the thread-local context.

    Usage:
        ctx = ScanContext.create(...)
        with ScanContextManager(ctx):
            # Old code can use get_current_context()
            # New code should use ctx directly
            await run_scan(ctx)
    """

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self._previous_ctx = None

    def __enter__(self) -> ScanContext:
        self._previous_ctx = get_current_context()
        set_current_context(self.ctx)
        return self.ctx

    def __exit__(self, exc_type, exc_val, exc_tb):
        set_current_context(self._previous_ctx)
        return False
