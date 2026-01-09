"""Depth enforcement for coverage-based scan completion."""
from dataclasses import dataclass
from typing import Optional
from services.coverage_tracker import CoverageTracker


@dataclass
class CompletionValidationResult:
    """Result of completion validation."""
    can_complete: bool
    rejection_reason: Optional[str] = None
    coverage_stats: Optional[dict] = None
    guidance: Optional[str] = None


@dataclass
class DepthEnforcementConfig:
    """Configuration for depth enforcement."""
    min_coverage_percent: float = 80.0
    max_inconclusive: int = 3
    require_explicit_skip_reason: bool = True
    min_files_examined: int = 5
    min_iterations: int = 10


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


def validate_completion_request(
    coverage_tracker: CoverageTracker,
    config: DepthEnforcementConfig,
    files_examined: set[str],
    iteration_count: int,
    pending_investigations: int
) -> CompletionValidationResult:
    """Validate if audit completion can be accepted.

    Checks:
    1. Minimum files examined
    2. Minimum iterations
    3. Investigation queue empty
    4. Coverage threshold met

    Returns CompletionValidationResult with can_complete and reason if rejected.
    """
    # Check 1: Minimum files examined
    if len(files_examined) < config.min_files_examined:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"Must examine at least {config.min_files_examined} files. Currently: {len(files_examined)}",
            guidance="Use read_file and search_code to examine more of the codebase before completing."
        )

    # Check 2: Minimum iterations
    if iteration_count < config.min_iterations:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"Must run at least {config.min_iterations} iterations. Currently: {iteration_count}",
            guidance="Continue investigating. The audit needs more depth before completion."
        )

    # Check 3: Investigation queue empty
    if pending_investigations > 0:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"{pending_investigations} items in investigation queue must be processed or explicitly deferred",
            guidance="Process pending investigation items or defer them with explicit reasoning."
        )

    # Check 4: Coverage threshold
    stats = coverage_tracker.get_coverage_stats()

    # Special case: if no paths registered, that's suspicious
    if stats.total_paths == 0:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason="No entry point to sink paths have been registered. Cannot verify coverage.",
            guidance="Use get_entry_points to discover entry points, then trace_data_flow to find paths to dangerous sinks, then trace_path_verdict to record verdicts."
        )

    if stats.coverage_percent < config.min_coverage_percent:
        unexplored = coverage_tracker.get_unexplored_paths()
        paths_summary = ", ".join([
            f"{r.entry_point_file}:{r.entry_point_line}"
            for r in unexplored[:5]
        ])
        if len(unexplored) > 5:
            paths_summary += f" ... and {len(unexplored) - 5} more"

        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"Coverage is {stats.coverage_percent:.1f}%, minimum required is {config.min_coverage_percent}%",
            coverage_stats={
                "total_paths": stats.total_paths,
                "traced_count": stats.traced_count,
                "coverage_percent": stats.coverage_percent
            },
            guidance=f"Trace remaining paths and call trace_path_verdict for each. Unexplored: {paths_summary}"
        )

    # Check 5: Too many inconclusive
    if stats.inconclusive_count > config.max_inconclusive:
        return CompletionValidationResult(
            can_complete=False,
            rejection_reason=f"{stats.inconclusive_count} paths marked inconclusive, maximum allowed is {config.max_inconclusive}",
            guidance="Review inconclusive paths and either gather more context or make a determination."
        )

    # All checks passed
    return CompletionValidationResult(
        can_complete=True,
        coverage_stats={
            "total_paths": stats.total_paths,
            "traced_count": stats.traced_count,
            "coverage_percent": stats.coverage_percent,
            "vuln_count": stats.traced_vuln_count
        }
    )
