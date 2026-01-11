"""Semantic grep scanner - regex search with context.

This module provides regex-based code search with context lines,
pattern validation to prevent ReDoS, and optional timeout support.

Key features:
- Pattern validation to reject catastrophic backtracking patterns
- Context line support for better finding understanding
- Optional timeout support via the 'regex' module
- Cancellation support via ScanLimits
- Binary file skipping
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Optional

try:
    import regex as regex_module
    HAS_REGEX = True
except ImportError:
    regex_module = None
    HAS_REGEX = False

from .base import (
    ScanFinding,
    ScanLimits,
    ScanResult,
    ScannerTool,
    Severity,
    WorkspacePolicy,
    read_file_safe,
)


# Pattern to detect potentially catastrophic regex patterns
# Matches nested quantifiers like (a+)+, (a*)*, (a?)+, etc.
# Also catches patterns like (?:a+)+ and groups containing quantifiers that are themselves quantified
UNSAFE_PATTERN_RE = re.compile(
    r"(\+|\*|\?)\1"  # Consecutive quantifiers like ++, **, ??
    r"|"
    r"\([^)]*[\+\*][^)]*\)[\+\*]"  # Group with + or * followed by + or *
    r"|"
    r"\(\?[^)]*\+"  # Non-capturing group patterns with possessive quantifier
)


def validate_pattern(pattern: str) -> tuple[bool, Optional[str]]:
    """Validate a regex pattern for safety and correctness.

    Rejects patterns that:
    - Are too long (>500 chars)
    - Contain nested quantifiers (backtracking risk)
    - Are not valid regex syntax

    Args:
        pattern: The regex pattern to validate

    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message is None
    """
    if len(pattern) > 500:
        return False, "Pattern too long (max 500 chars)"

    if UNSAFE_PATTERN_RE.search(pattern):
        return False, "Pattern contains nested quantifiers (backtracking risk)"

    try:
        if HAS_REGEX:
            regex_module.compile(pattern)
        else:
            re.compile(pattern)
    except (re.error, Exception) as e:
        return False, f"Invalid regex: {e}"

    return True, None


def _get_line_number_from_position(line_starts: list[int], pos: int, total_lines: int) -> int:
    """Get line number (1-indexed) from character position.

    Args:
        line_starts: List of character positions where each line starts
        pos: Character position in the content
        total_lines: Total number of lines in the content

    Returns:
        Line number (1-indexed)
    """
    line_no = 1
    for i, start_pos in enumerate(line_starts):
        if start_pos > pos:
            line_no = i
            break
    else:
        line_no = total_lines
    return line_no


def _build_context_snippet(
    lines: list[str],
    line_no: int,
    context_lines: int,
) -> str:
    """Build a snippet with context lines around the match.

    Args:
        lines: All lines in the file
        line_no: Line number of the match (1-indexed)
        context_lines: Number of context lines before and after

    Returns:
        Snippet string with context
    """
    start_idx = max(0, line_no - 1 - context_lines)
    end_idx = min(len(lines), line_no + context_lines)
    snippet_lines = lines[start_idx:end_idx]
    return "\n".join(snippet_lines)


def _semantic_grep_sync(
    policy: WorkspacePolicy,
    pattern: str,
    limits: ScanLimits,
    context_lines: int,
    file_glob: str,
    max_files: Optional[int],
    max_matches: Optional[int],
    max_matches_per_file: Optional[int],
    regex_timeout_ms: int,
) -> ScanResult:
    """Synchronous implementation of semantic grep.

    Args:
        policy: WorkspacePolicy defining file boundaries
        limits: ScanLimits for cancellation and deadline
        pattern: Regex pattern to search for
        context_lines: Number of context lines to include
        file_glob: Glob pattern for filtering files
        max_files: Maximum number of files to scan
        max_matches: Maximum total matches to return
        max_matches_per_file: Maximum matches per file
        regex_timeout_ms: Timeout in milliseconds for regex operations

    Returns:
        ScanResult with findings and metrics
    """
    # Validate pattern first
    valid, err = validate_pattern(pattern)
    if not valid:
        return ScanResult(
            success=False,
            error=err,
            findings=[],
            files_scanned=0,
            files_skipped=0,
            bytes_scanned=0,
            duration_ms=0,
        )

    # Compile the pattern
    if HAS_REGEX:
        compiled = regex_module.compile(pattern)
    else:
        compiled = re.compile(pattern)

    findings: list[ScanFinding] = []
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0
    start = time.monotonic()

    for path in policy.iter_files(file_glob):
        # Check cancellation
        if limits.is_cancelled():
            return ScanResult(
                success=True,
                cancelled=True,
                findings=findings,
                files_scanned=files_scanned,
                files_skipped=files_skipped,
                bytes_scanned=bytes_scanned,
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        # Check max files limit
        if max_files is not None and files_scanned >= max_files:
            break

        # Check max matches limit
        if max_matches is not None and len(findings) >= max_matches:
            break

        # Read file content (will skip binary files)
        content, _ = read_file_safe(path)
        if content is None:
            files_skipped += 1
            continue

        files_scanned += 1
        bytes_scanned += len(content.encode())
        lines = content.splitlines()
        file_matches = 0

        # Find all matches with optional timeout
        try:
            if HAS_REGEX:
                timeout_s = regex_timeout_ms / 1000
                matches = list(compiled.finditer(content, timeout=timeout_s))
            else:
                matches = list(compiled.finditer(content))
        except Exception:
            # Timeout or other error during matching
            files_skipped += 1
            continue

        # Build line start positions for mapping match positions to line numbers
        line_starts = [0]
        for line in lines:
            line_starts.append(line_starts[-1] + len(line) + 1)

        for match in matches:
            # Check per-file limit
            if max_matches_per_file is not None and file_matches >= max_matches_per_file:
                break

            # Check total limit
            if max_matches is not None and len(findings) >= max_matches:
                break

            # Find line number from match position
            line_no = _get_line_number_from_position(line_starts, match.start(), len(lines))

            # Build context snippet
            snippet = _build_context_snippet(lines, line_no, context_lines)

            # Calculate line_end based on context
            line_end = min(line_no + context_lines, len(lines)) if context_lines > 0 else None

            # Create finding
            finding = ScanFinding(
                tool=ScannerTool.GREP,
                severity=Severity.INFO,
                title=f"Pattern match: {pattern[:50]}{'...' if len(pattern) > 50 else ''}",
                file_path=str(path),
                line_start=line_no,
                line_end=line_end,
                snippet=snippet[:500] if snippet else match.group(0)[:100],
                confidence=1.0,  # High confidence for exact pattern matches
                details={
                    "pattern": pattern,
                    "match": match.group(0)[:100],
                    "context_lines": context_lines,
                    "description": f"Found pattern match in source code at line {line_no}",
                },
            )
            findings.append(finding)
            file_matches += 1

        # Check total limit after processing file
        if max_matches is not None and len(findings) >= max_matches:
            break

    return ScanResult(
        success=True,
        findings=findings,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        bytes_scanned=bytes_scanned,
        duration_ms=int((time.monotonic() - start) * 1000),
    )


async def semantic_grep(
    policy: WorkspacePolicy,
    pattern: str,
    limits: Optional[ScanLimits] = None,
    context_lines: int = 3,
    file_glob: str = "**/*",
    max_files: Optional[int] = None,
    max_matches: Optional[int] = None,
    max_matches_per_file: Optional[int] = None,
    regex_timeout_ms: int = 5000,
) -> ScanResult:
    """Search code for patterns with context.

    Uses the 'regex' module with timeout if available, falls back to 're'.
    Rejects patterns with catastrophic backtracking risk.

    Args:
        policy: WorkspacePolicy defining file boundaries
        pattern: Regex pattern to search for
        limits: Optional ScanLimits for cancellation and deadline
        context_lines: Number of context lines to include (default: 3)
        file_glob: Glob pattern for filtering files (default: all files)
        max_files: Maximum number of files to scan (optional)
        max_matches: Maximum total matches to return (optional)
        max_matches_per_file: Maximum matches per file (optional)
        regex_timeout_ms: Timeout in milliseconds for regex operations (default: 5000)

    Returns:
        ScanResult with findings and metrics
    """
    limits = limits or ScanLimits()
    return await asyncio.to_thread(
        _semantic_grep_sync,
        policy,
        pattern,
        limits,
        context_lines,
        file_glob,
        max_files,
        max_matches,
        max_matches_per_file,
        regex_timeout_ms,
    )
