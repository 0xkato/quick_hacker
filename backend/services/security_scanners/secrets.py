"""Secrets scanner for detecting hardcoded secrets and credentials.

This module provides pattern-based and entropy-based detection of secrets
in source code files. It supports detection of:
- AWS access keys and secret keys
- GitHub tokens (personal access, OAuth, etc.)
- Generic API keys and secrets
- Private keys (RSA, DSA, EC, etc.)
- JWT tokens

Key features:
- Shannon entropy calculation for detecting high-randomness strings
- Pattern-based detection using regex
- Redaction of secrets in findings
- Fingerprinting for deduplication
- Cancellation support via ScanLimits
- Binary file skipping
"""
from __future__ import annotations

import asyncio
import math
import re
import time
from collections import Counter
from typing import Optional

from .base import (
    WorkspacePolicy,
    ScanLimits,
    ScanFinding,
    ScanResult,
    Severity,
    redact_secret,
    fingerprint_secret,
    read_file_safe,
    ScannerTool,
)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Shannon entropy measures the randomness/unpredictability of a string.
    Higher entropy indicates more random/uniform distribution of characters,
    which is characteristic of secrets like API keys and passwords.

    Args:
        data: The string to calculate entropy for

    Returns:
        Shannon entropy value (0.0 for empty/uniform strings, higher for random)
    """
    if not data:
        return 0.0

    length = len(data)
    if length == 0:
        return 0.0

    # Count frequency of each character
    freq = Counter(data)

    # Calculate entropy: -sum(p * log2(p)) for each probability p
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


# Secret patterns for detection
# Each pattern includes:
# - name: Unique identifier
# - pattern: Compiled regex pattern
# - severity: Severity level from base
# - description: Human-readable description
SECRET_PATTERNS: list[dict] = [
    {
        "name": "aws_access_key",
        "pattern": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": Severity.CRITICAL,
        "description": "AWS Access Key ID",
    },
    {
        "name": "aws_secret_key",
        "pattern": re.compile(r"(?i)(aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "severity": Severity.CRITICAL,
        "description": "AWS Secret Access Key",
    },
    {
        "name": "github_token",
        "pattern": re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,})"),
        "severity": Severity.CRITICAL,
        "description": "GitHub Token (Personal Access, OAuth, etc.)",
    },
    {
        "name": "generic_api_key",
        "pattern": re.compile(r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"),
        "severity": Severity.HIGH,
        "description": "Generic API Key",
    },
    {
        "name": "generic_secret",
        "pattern": re.compile(r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?([A-Za-z0-9!@#$%^&*()_\-+=]{8,})['\"]?"),
        "severity": Severity.HIGH,
        "description": "Generic Secret or Password",
    },
    {
        "name": "private_key",
        "pattern": re.compile(r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
        "severity": Severity.CRITICAL,
        "description": "Private Key Header",
    },
    {
        "name": "jwt",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": Severity.HIGH,
        "description": "JSON Web Token (JWT)",
    },
]


def _extract_secret_from_match(match: re.Match, pattern_name: str) -> str:
    """Extract the actual secret value from a regex match.

    Args:
        match: The regex match object
        pattern_name: Name of the pattern that matched

    Returns:
        The secret value (from group 2 if exists, else full match)
    """
    # For patterns with assignment (key=value), the secret is in group 2
    if pattern_name in ("aws_secret_key", "generic_api_key", "generic_secret"):
        try:
            return match.group(2)
        except (IndexError, AttributeError):
            return match.group(0)
    # For other patterns, the secret is the full match or group 1
    try:
        return match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
    except (IndexError, AttributeError):
        return match.group(0)


def _scan_for_secrets_sync(
    policy: WorkspacePolicy,
    limits: ScanLimits,
    entropy_threshold: float = 4.5,
    max_files: Optional[int] = None,
    max_matches: Optional[int] = None,
) -> ScanResult:
    """Synchronous implementation of secrets scanning.

    Scans files in the workspace for secrets using:
    1. Pattern-based detection for known secret formats
    2. Entropy-based detection for high-randomness strings

    Args:
        policy: WorkspacePolicy defining file boundaries
        limits: ScanLimits for cancellation and deadline
        entropy_threshold: Minimum entropy for entropy-based detection (default 4.5)
        max_files: Maximum number of files to scan (optional)
        max_matches: Maximum number of findings to return (optional)

    Returns:
        ScanResult with findings and metrics
    """
    start_time = time.time()
    findings: list[ScanFinding] = []
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0

    # Pattern to extract potential secrets in strings (for entropy check)
    string_pattern = re.compile(r'["\'][A-Za-z0-9!@#$%^&*()_\-+=/.]{16,}["\']')

    for file_path in policy.iter_files():
        # Check cancellation
        if limits.is_cancelled():
            break

        # Check max_files limit
        if max_files is not None and files_scanned >= max_files:
            break

        # Check max_matches limit
        if max_matches is not None and len(findings) >= max_matches:
            break

        # Read file content (will skip binary files)
        content = read_file_safe(file_path)
        if content is None:
            files_skipped += 1
            continue

        files_scanned += 1
        bytes_scanned += len(content.encode("utf-8"))

        # Scan each line
        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            # Check limits during line scanning
            if limits.is_cancelled():
                break
            if max_matches is not None and len(findings) >= max_matches:
                break

            # Pattern-based detection
            for pattern_def in SECRET_PATTERNS:
                match = pattern_def["pattern"].search(line)
                if match:
                    secret_value = _extract_secret_from_match(match, pattern_def["name"])
                    redacted = redact_secret(secret_value)
                    fp = fingerprint_secret(secret_value)

                    finding = ScanFinding(
                        tool=ScannerTool.SECRETS,
                        severity=pattern_def["severity"],
                        title=pattern_def["description"],
                        description=f"Found {pattern_def['description']} in source code",
                        file_path=str(file_path),
                        line_number=line_num,
                        matched_text=redacted,
                        metadata={
                            "pattern_name": pattern_def["name"],
                            "fingerprint": fp,
                        },
                    )
                    findings.append(finding)

            # Entropy-based detection for strings in assignment context
            # Look for high-entropy strings that might be secrets
            for string_match in string_pattern.finditer(line):
                # Extract the string content (without quotes)
                matched_str = string_match.group(0)[1:-1]

                # Skip if already matched by a pattern
                already_matched = any(
                    p["pattern"].search(matched_str) for p in SECRET_PATTERNS
                )
                if already_matched:
                    continue

                # Check if this is in a secret-like context
                context_pattern = re.compile(r"(?i)(secret|key|token|password|api|auth|credential)")
                if not context_pattern.search(line):
                    continue

                # Calculate entropy
                entropy = shannon_entropy(matched_str)
                if entropy >= entropy_threshold:
                    redacted = redact_secret(matched_str)
                    fp = fingerprint_secret(matched_str)

                    finding = ScanFinding(
                        tool=ScannerTool.SECRETS,
                        severity=Severity.MEDIUM,
                        title="High Entropy String",
                        description=f"Found high-entropy string (entropy: {entropy:.2f}) in secret-like context",
                        file_path=str(file_path),
                        line_number=line_num,
                        matched_text=redacted,
                        metadata={
                            "pattern_name": "high_entropy",
                            "fingerprint": fp,
                            "entropy": entropy,
                        },
                    )
                    findings.append(finding)

    duration_ms = int((time.time() - start_time) * 1000)
    was_cancelled = limits.is_cancelled()

    return ScanResult(
        success=True,
        findings=findings,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        bytes_scanned=bytes_scanned,
        duration_ms=duration_ms,
        cancelled=was_cancelled,
        error=None,
    )


async def scan_for_secrets(
    policy: WorkspacePolicy,
    limits: ScanLimits,
    entropy_threshold: float = 4.5,
    max_files: Optional[int] = None,
    max_matches: Optional[int] = None,
) -> ScanResult:
    """Async wrapper for secrets scanning.

    Runs the synchronous scanner in a thread pool to avoid blocking
    the event loop during file I/O operations.

    Args:
        policy: WorkspacePolicy defining file boundaries
        limits: ScanLimits for cancellation and deadline
        entropy_threshold: Minimum entropy for entropy-based detection (default 4.5)
        max_files: Maximum number of files to scan (optional)
        max_matches: Maximum number of findings to return (optional)

    Returns:
        ScanResult with findings and metrics
    """
    return await asyncio.to_thread(
        _scan_for_secrets_sync,
        policy,
        limits,
        entropy_threshold,
        max_files,
        max_matches,
    )
