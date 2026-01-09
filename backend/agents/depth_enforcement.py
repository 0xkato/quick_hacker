"""Depth enforcement for coverage-based scan completion."""
from dataclasses import dataclass
from typing import Optional
from services.coverage_tracker import CoverageTracker


@dataclass
class DepthEnforcementConfig:
    """Configuration for depth enforcement."""
    min_coverage_percent: float = 80.0
    max_inconclusive: int = 3
    require_explicit_skip_reason: bool = True


def check_coverage_before_complete(
    coverage_tracker: CoverageTracker,
    config: DepthEnforcementConfig
) -> tuple[bool, Optional[str]]:
    """Check if coverage is sufficient to accept AUDIT_COMPLETE.

    Returns:
        (can_complete, challenge_message)
    """
    stats = coverage_tracker.get_coverage_stats()

    # Check coverage percentage
    if stats.coverage_percent < config.min_coverage_percent:
        remaining = coverage_tracker.get_unexplored_paths()
        paths_summary = "\n".join([
            f"  - {r.entry_point_file}:{r.entry_point_line} -> {r.sink_file}:{r.sink_line}"
            for r in remaining[:10]
        ])
        if len(remaining) > 10:
            paths_summary += f"\n  ... and {len(remaining) - 10} more"

        return False, f"""You said AUDIT_COMPLETE but coverage is only {stats.coverage_percent:.1f}%.

Unexplored paths:
{paths_summary}

Either:
1. Trace these remaining paths and call trace_path_verdict for each
2. Explain why these paths are not worth investigating
3. Say AUDIT_COMPLETE again to confirm you're done despite low coverage
"""

    # Check inconclusive count
    if stats.inconclusive_count > config.max_inconclusive:
        return False, f"""You said AUDIT_COMPLETE but {stats.inconclusive_count} paths are marked inconclusive.

Review these paths and either:
1. Gather more context to make a determination
2. Mark them as safe/blocked with reasoning
3. Say AUDIT_COMPLETE again to confirm
"""

    return True, None
