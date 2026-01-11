"""Dependency audit scanner for detecting vulnerable packages.

This module provides scanning of dependency lockfiles to detect packages
with known vulnerabilities. It supports multiple ecosystems:
- npm (package-lock.json, yarn.lock, pnpm-lock.yaml)
- Python (requirements.txt, Pipfile.lock)

Key features:
- Auto-detection of lockfiles in workspace
- Version range checking against advisory database
- Support for multiple lockfile formats
- Cancellation support via ScanLimits
- Max matches limiting
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Optional

from .base import (
    WorkspacePolicy,
    ScanLimits,
    ScanFinding,
    ScanResult,
    Severity,
    ScannerTool,
    read_file_safe,
)


# Load advisory database
_ADVISORY_DB_PATH = Path(__file__).parent / "data" / "advisory_db.json"
_ADVISORY_DB: dict = {}


def _load_advisory_db() -> dict:
    """Load the advisory database from JSON file.

    Returns:
        Dictionary containing vulnerability data
    """
    global _ADVISORY_DB
    if _ADVISORY_DB:
        return _ADVISORY_DB

    try:
        with open(_ADVISORY_DB_PATH, "r", encoding="utf-8") as f:
            _ADVISORY_DB = json.load(f)
    except (OSError, json.JSONDecodeError):
        _ADVISORY_DB = {"version": "unknown", "npm": {}, "pypi": {}}

    return _ADVISORY_DB


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison.

    Handles prerelease tags by stripping them.

    Args:
        version: Version string (e.g., "1.2.3", "1.0.0-alpha")

    Returns:
        Tuple of integers representing version parts
    """
    # Strip prerelease/build metadata
    version = re.split(r"[-+]", version)[0]

    # Extract numeric parts
    parts = []
    for part in version.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            # Non-numeric part, stop parsing
            break

    # Ensure at least 3 parts for comparison
    while len(parts) < 3:
        parts.append(0)

    return tuple(parts)


def _compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version
        v2: Second version

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    p1 = _parse_version(v1)
    p2 = _parse_version(v2)

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def _check_version_in_range(version: str, range_spec: str) -> bool:
    """Check if a version matches a version range specification.

    Supports:
    - <X.Y.Z (less than)
    - <=X.Y.Z (less than or equal)
    - >X.Y.Z (greater than)
    - >=X.Y.Z (greater than or equal)
    - ==X.Y.Z (exact match)
    - Combined ranges with comma (>=1.0.0,<2.0.0)

    Args:
        version: The version to check
        range_spec: The version range specification

    Returns:
        True if version matches the range, False otherwise
    """
    # Split combined ranges
    ranges = [r.strip() for r in range_spec.split(",")]

    for r in ranges:
        r = r.strip()
        if not r:
            continue

        # Parse operator and version
        if r.startswith("<="):
            target = r[2:]
            if _compare_versions(version, target) > 0:
                return False
        elif r.startswith(">="):
            target = r[2:]
            if _compare_versions(version, target) < 0:
                return False
        elif r.startswith("<"):
            target = r[1:]
            if _compare_versions(version, target) >= 0:
                return False
        elif r.startswith(">"):
            target = r[1:]
            if _compare_versions(version, target) <= 0:
                return False
        elif r.startswith("=="):
            target = r[2:]
            if _compare_versions(version, target) != 0:
                return False
        else:
            # Assume exact match if no operator
            if _compare_versions(version, r) != 0:
                return False

    return True


def _parse_npm_lockfile(content: str) -> list[tuple[str, str]]:
    """Parse npm package-lock.json to extract packages and versions.

    Supports both lockfile v1 (dependencies) and v2 (packages) formats.

    Args:
        content: The lockfile content as string

    Returns:
        List of (package_name, version) tuples
    """
    packages: list[tuple[str, str]] = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return packages

    lockfile_version = data.get("lockfileVersion", 1)

    if lockfile_version >= 2 and "packages" in data:
        # v2 format - packages are in "packages" object
        for key, pkg_info in data.get("packages", {}).items():
            if not key:  # Skip root package (empty key)
                continue
            # Extract package name from node_modules path
            if key.startswith("node_modules/"):
                name = key.replace("node_modules/", "", 1)
                # Handle scoped packages
                if "/" in name and not name.startswith("@"):
                    name = name.split("/")[0]
            else:
                continue

            version = pkg_info.get("version")
            if version:
                packages.append((name, version))
    else:
        # v1 format - packages are in "dependencies" object
        for name, pkg_info in data.get("dependencies", {}).items():
            version = pkg_info.get("version")
            if version:
                packages.append((name, version))

    return packages


def _parse_yarn_lockfile(content: str) -> list[tuple[str, str]]:
    """Parse yarn.lock to extract packages and versions.

    Args:
        content: The yarn.lock content as string

    Returns:
        List of (package_name, version) tuples
    """
    packages: list[tuple[str, str]] = []

    # Pattern to match package declarations
    # e.g., "lodash@^4.17.21:" or "lodash@^4.17.21, lodash@^4.17.20:"
    pkg_pattern = re.compile(r'^([^@\s][^@]*|@[^/]+/[^@]+)@[^:]+:?\s*$', re.MULTILINE)
    version_pattern = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)

    lines = content.split('\n')
    current_package = None

    for line in lines:
        # Check for package declaration
        if not line.startswith(' ') and '@' in line and ':' in line:
            # Extract package name (before first @version)
            match = re.match(r'^"?([^@\s][^@]*|@[^/]+/[^@]+)@', line)
            if match:
                current_package = match.group(1).strip('"')
        elif current_package and 'version' in line:
            # Extract version
            match = re.search(r'version\s+"([^"]+)"', line)
            if match:
                packages.append((current_package, match.group(1)))
                current_package = None

    return packages


def _parse_pnpm_lockfile(content: str) -> list[tuple[str, str]]:
    """Parse pnpm-lock.yaml to extract packages and versions.

    Args:
        content: The pnpm-lock.yaml content as string

    Returns:
        List of (package_name, version) tuples
    """
    packages: list[tuple[str, str]] = []

    # Pattern to match package entries like "/lodash/4.17.21:"
    pkg_pattern = re.compile(r'^  /([^/]+)/([^/:]+):?', re.MULTILINE)

    for match in pkg_pattern.finditer(content):
        name = match.group(1)
        version = match.group(2)
        packages.append((name, version))

    return packages


def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Parse requirements.txt to extract packages and versions.

    Handles:
    - Basic format: package==version
    - Extras: package[extra]==version
    - Various operators: ==, >=, <=, >, <, ~=
    - Comments and empty lines

    Args:
        content: The requirements.txt content as string

    Returns:
        List of (package_name, version) tuples
    """
    packages: list[tuple[str, str]] = []

    for line in content.split('\n'):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith('#') or line.startswith('-'):
            continue

        # Remove inline comments
        if '#' in line:
            line = line.split('#')[0].strip()

        # Remove extras like [security]
        if '[' in line:
            line = re.sub(r'\[[^\]]+\]', '', line)

        # Extract package name and version
        # Match patterns like: package==1.0.0, package>=1.0.0, etc.
        match = re.match(r'^([a-zA-Z0-9_-]+)\s*(==|>=|<=|>|<|~=|!=)\s*([^\s;]+)', line)
        if match:
            name = match.group(1).lower()
            operator = match.group(2)
            version = match.group(3)

            # For version range checks, we mainly care about exact versions
            # But also capture >= and <= for potential matching
            if operator == '==':
                packages.append((name, version))
            elif operator in ('>=', '<=', '>', '<', '~='):
                packages.append((name, version))

    return packages


def _parse_pipfile_lock(content: str) -> list[tuple[str, str]]:
    """Parse Pipfile.lock to extract packages and versions.

    Args:
        content: The Pipfile.lock content as string

    Returns:
        List of (package_name, version) tuples
    """
    packages: list[tuple[str, str]] = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return packages

    # Process both default and develop dependencies
    for section in ['default', 'develop']:
        for name, pkg_info in data.get(section, {}).items():
            version = pkg_info.get("version", "")
            # Remove == prefix if present
            if version.startswith("=="):
                version = version[2:]
            if version:
                packages.append((name.lower(), version))

    return packages


def _get_lockfile_type(filename: str) -> Optional[str]:
    """Determine the type of lockfile based on filename.

    Args:
        filename: Name of the file

    Returns:
        Lockfile type string or None if not recognized
    """
    name = filename.lower()
    if name == "package-lock.json":
        return "npm"
    elif name == "yarn.lock":
        return "yarn"
    elif name == "pnpm-lock.yaml":
        return "pnpm"
    elif name == "requirements.txt":
        return "requirements"
    elif name == "pipfile.lock":
        return "pipfile"
    return None


def _get_ecosystem(lockfile_type: str) -> str:
    """Get the ecosystem name for a lockfile type.

    Args:
        lockfile_type: Type of lockfile

    Returns:
        Ecosystem name (npm or pypi)
    """
    if lockfile_type in ("npm", "yarn", "pnpm"):
        return "npm"
    return "pypi"


def _parse_lockfile(content: str, lockfile_type: str) -> list[tuple[str, str]]:
    """Parse a lockfile based on its type.

    Args:
        content: Lockfile content
        lockfile_type: Type of lockfile

    Returns:
        List of (package_name, version) tuples
    """
    if lockfile_type == "npm":
        return _parse_npm_lockfile(content)
    elif lockfile_type == "yarn":
        return _parse_yarn_lockfile(content)
    elif lockfile_type == "pnpm":
        return _parse_pnpm_lockfile(content)
    elif lockfile_type == "requirements":
        return _parse_requirements_txt(content)
    elif lockfile_type == "pipfile":
        return _parse_pipfile_lock(content)
    return []


def _severity_from_string(severity_str: str) -> Severity:
    """Convert severity string to Severity enum.

    Args:
        severity_str: Severity as string

    Returns:
        Severity enum value
    """
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(severity_str.lower(), Severity.MEDIUM)


def _audit_dependencies_sync(
    policy: WorkspacePolicy,
    limits: ScanLimits,
    lockfile_path: Optional[str] = None,
    max_matches: Optional[int] = None,
) -> ScanResult:
    """Synchronous implementation of dependency auditing.

    Scans lockfiles in the workspace for packages with known vulnerabilities.

    Args:
        policy: WorkspacePolicy defining file boundaries
        limits: ScanLimits for cancellation and deadline
        lockfile_path: Optional specific lockfile to scan (auto-detect if None)
        max_matches: Maximum number of findings to return (optional)

    Returns:
        ScanResult with findings and metrics
    """
    start_time = time.time()
    findings: list[ScanFinding] = []
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0

    # Load advisory database
    advisory_db = _load_advisory_db()
    db_version = advisory_db.get("version", "unknown")

    # Determine which lockfiles to scan
    lockfiles_to_scan: list[Path] = []

    if lockfile_path:
        # Scan specific lockfile
        path = Path(lockfile_path)
        if path.exists() and policy.validate_path(path):
            lockfiles_to_scan.append(path)
    else:
        # Auto-detect lockfiles
        lockfile_patterns = [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "requirements.txt",
            "Pipfile.lock",
        ]
        for pattern in lockfile_patterns:
            for path in policy.iter_files(pattern):
                lockfiles_to_scan.append(path)

    # Scan each lockfile
    for lockfile in lockfiles_to_scan:
        # Check cancellation
        if limits.is_cancelled():
            break

        # Check max_matches limit
        if max_matches is not None and len(findings) >= max_matches:
            break

        # Read lockfile content
        content = read_file_safe(lockfile)
        if content is None:
            files_skipped += 1
            continue

        files_scanned += 1
        bytes_scanned += len(content.encode("utf-8"))

        # Determine lockfile type
        lockfile_type = _get_lockfile_type(lockfile.name)
        if not lockfile_type:
            continue

        # Parse lockfile
        packages = _parse_lockfile(content, lockfile_type)
        ecosystem = _get_ecosystem(lockfile_type)

        # Get advisories for this ecosystem
        advisories = advisory_db.get(ecosystem, {})

        # Check each package against advisories
        for pkg_name, pkg_version in packages:
            # Check cancellation
            if limits.is_cancelled():
                break

            # Check max_matches limit
            if max_matches is not None and len(findings) >= max_matches:
                break

            # Look up advisories for this package
            pkg_advisories = advisories.get(pkg_name.lower(), [])

            for advisory in pkg_advisories:
                # Check if version is in vulnerable range
                vuln_range = advisory.get("range", "")
                if _check_version_in_range(pkg_version, vuln_range):
                    severity = _severity_from_string(advisory.get("severity", "medium"))
                    advisory_id = advisory.get("advisory_id", "unknown")
                    cve = advisory.get("cve")
                    title = advisory.get("title", "Unknown vulnerability")

                    finding = ScanFinding(
                        tool=ScannerTool.DEPENDENCIES,
                        severity=severity,
                        title=f"Vulnerable dependency: {pkg_name}",
                        description=f"Package {pkg_name}@{pkg_version} has a known vulnerability: {title}",
                        file_path=str(lockfile),
                        line_number=1,  # Lockfiles don't have meaningful line numbers
                        matched_text=f"{pkg_name}@{pkg_version}",
                        metadata={
                            "ecosystem": ecosystem,
                            "package": pkg_name,
                            "installed_version": pkg_version,
                            "advisory_id": advisory_id,
                            "cve": cve,
                            "vulnerable_range": vuln_range,
                            "advisory_title": title,
                            "source_db_version": db_version,
                        },
                    )
                    findings.append(finding)

                    # Check max_matches limit after adding
                    if max_matches is not None and len(findings) >= max_matches:
                        break

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


async def audit_dependencies(
    policy: WorkspacePolicy,
    limits: ScanLimits,
    lockfile_path: Optional[str] = None,
    max_matches: Optional[int] = None,
) -> ScanResult:
    """Async wrapper for dependency auditing.

    Runs the synchronous scanner in a thread pool to avoid blocking
    the event loop during file I/O operations.

    Args:
        policy: WorkspacePolicy defining file boundaries
        limits: ScanLimits for cancellation and deadline
        lockfile_path: Optional specific lockfile to scan (auto-detect if None)
        max_matches: Maximum number of findings to return (optional)

    Returns:
        ScanResult with findings and metrics
    """
    return await asyncio.to_thread(
        _audit_dependencies_sync,
        policy,
        limits,
        lockfile_path,
        max_matches,
    )
