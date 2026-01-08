"""Relevance scoring for code graph nodes."""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class RelevanceScore:
    """Breakdown of how a node's relevance was calculated."""
    total: int
    level: str  # "high", "medium", "low", "skip"
    content_score: int
    position_score: int
    matched_patterns: list[str]


# Content patterns and their scores
CONTENT_PATTERNS = [
    # Security-critical (+40)
    (40, ["auth", "authentication", "login", "session", "token", "jwt", "oauth"]),
    (40, ["crypto", "encrypt", "decrypt", "hash", "password", "secret"]),
    (40, ["sql", "query", "execute", "cursor", "database"]),
    (40, ["exec", "eval", "subprocess", "shell", "command", "system"]),
    (40, ["input", "request", "body", "params", "user_input", "form"]),
    # Important (+30)
    (30, ["file", "read", "write", "open", "path", "upload"]),
    # Moderate (+20)
    (20, ["http", "api", "endpoint", "route", "handler"]),
    # Low (+10)
    (10, ["config", "settings", "env"]),
    # Negative (tests, logging)
    (-20, ["test", "spec", "mock", "fixture"]),
    (-10, ["log", "print", "debug", "trace"]),
]

# Position scores by depth
POSITION_SCORES = {
    0: 60,  # Entry point
    1: 40,  # Depth 1
    2: 25,  # Depth 2
    3: 15,  # Depth 3
}
DEFAULT_POSITION_SCORE = 5  # Depth 4+


def score_content(text: str) -> tuple[int, list[str]]:
    """Score content based on pattern matching.

    Args:
        text: Combined text of function name, file path, and code content

    Returns:
        Tuple of (score, list of matched pattern groups)
    """
    text_lower = text.lower()
    score = 0
    matched = []

    for points, patterns in CONTENT_PATTERNS:
        for pattern in patterns:
            if pattern in text_lower:
                score += points
                matched.append(pattern)
                break  # Only count each pattern group once

    return score, matched


def score_position(depth: int) -> int:
    """Score based on position in call graph.

    Args:
        depth: Distance from entry point (0 = entry point itself)

    Returns:
        Position score
    """
    return POSITION_SCORES.get(depth, DEFAULT_POSITION_SCORE)


def calculate_relevance(
    function_name: str,
    file_path: str,
    depth: int,
    code_content: Optional[str] = None,
) -> RelevanceScore:
    """Calculate relevance score for a code graph node.

    Args:
        function_name: Name of the function
        file_path: Path to the file containing the function
        depth: Distance from entry point in the call graph
        code_content: Optional function body text for deeper analysis

    Returns:
        RelevanceScore with breakdown
    """
    # Combine text for pattern matching
    text_parts = [function_name, file_path]
    if code_content:
        text_parts.append(code_content)
    combined_text = " ".join(text_parts)

    content_score, matched_patterns = score_content(combined_text)
    position_score = score_position(depth)

    total = max(0, content_score + position_score)  # Floor at 0

    # Determine level
    if total >= 80:
        level = "high"
    elif total >= 50:
        level = "medium"
    elif total >= 20:
        level = "low"
    else:
        level = "skip"

    return RelevanceScore(
        total=total,
        level=level,
        content_score=content_score,
        position_score=position_score,
        matched_patterns=matched_patterns,
    )
