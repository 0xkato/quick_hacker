"""Intake helpers: support-contract validation and capability-profile detection.

These are lightweight, filesystem-only checks that inspect a cloned repo to
determine what infrastructure artefacts are present and what the repo is
capable of before any heavy scanning begins.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ContractValidation:
    """Result of validating the v1 support contract for a repo."""

    valid: bool
    reasons: list[str] = field(default_factory=list)
    compose_path: str | None = None
    openapi_path: str | None = None


@dataclass
class CapabilityProfile:
    """Detected capabilities and tech stack of a target repo."""

    has_openapi_spec: bool = False
    has_graphql_schema: bool = False
    has_tests: bool = False
    has_docker: bool = False
    has_health_check: bool = False
    openapi_path: str | None = None
    compose_path: str | None = None
    languages: list[str] = field(default_factory=list)
    framework: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_COMPOSE_NAMES = ("docker-compose.yml", "compose.yaml")

_OPENAPI_MARKERS = ("openapi", "swagger")

# Subdirectories to scan for OpenAPI specs (up to 2 levels deep).
_SPEC_SUBDIRS = ("docs", "api", "spec", "specs", "openapi", "swagger")

_EXTENSION_LANG_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
}

_PYTHON_FRAMEWORKS = {"fastapi": "fastapi", "django": "django", "flask": "flask"}
_NODE_FRAMEWORKS = {"express": "express", "next": "next", "fastify": "fastify"}


def _find_compose(repo_path: str) -> str | None:
    """Return the path of a compose file in the repo root, or None."""
    for name in _COMPOSE_NAMES:
        candidate = os.path.join(repo_path, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def _is_openapi_spec(filepath: str) -> bool:
    """Return True if *filepath* looks like an OpenAPI / Swagger spec."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in (".json", ".yaml", ".yml"):
        return False
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(4096)  # only need the header
    except OSError:
        return False
    content_lower = content.lower()
    return any(marker in content_lower for marker in _OPENAPI_MARKERS)


def _find_openapi(repo_path: str) -> str | None:
    """Search root + up to 2 levels of subdirs for an OpenAPI spec file."""
    # Check root first.
    for entry in _iter_files(repo_path):
        if _is_openapi_spec(entry):
            return entry

    # Check well-known subdirectories (depth 1).
    for subdir in _SPEC_SUBDIRS:
        subdir_path = os.path.join(repo_path, subdir)
        if not os.path.isdir(subdir_path):
            continue
        for entry in _iter_files(subdir_path):
            if _is_openapi_spec(entry):
                return entry
        # depth 2 — one level deeper inside the subdir
        for nested in _iter_dirs(subdir_path):
            for entry in _iter_files(nested):
                if _is_openapi_spec(entry):
                    return entry

    return None


def _iter_files(directory: str):
    """Yield full paths of files in *directory* (non-recursive)."""
    try:
        entries = os.listdir(directory)
    except OSError:
        return
    for name in sorted(entries):
        full = os.path.join(directory, name)
        if os.path.isfile(full):
            yield full


def _iter_dirs(directory: str):
    """Yield full paths of immediate subdirectories in *directory*."""
    try:
        entries = os.listdir(directory)
    except OSError:
        return
    for name in sorted(entries):
        full = os.path.join(directory, name)
        if os.path.isdir(full):
            yield full


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_support_contract(repo_path: str) -> ContractValidation:
    """Check whether *repo_path* satisfies the v1 support contract.

    The v1 contract requires:
    * A ``docker-compose.yml`` or ``compose.yaml`` in the repo root.
    * An OpenAPI or Swagger spec reachable in the root or up to 2 levels deep.
    """
    reasons: list[str] = []

    compose_path = _find_compose(repo_path)
    if compose_path is None:
        reasons.append("No docker-compose.yml or compose.yaml found")

    openapi_path = _find_openapi(repo_path)
    if openapi_path is None:
        reasons.append("No OpenAPI or Swagger spec found")

    return ContractValidation(
        valid=len(reasons) == 0,
        reasons=reasons,
        compose_path=compose_path,
        openapi_path=openapi_path,
    )


def detect_capability_profile(repo_path: str) -> CapabilityProfile:
    """Build a :class:`CapabilityProfile` by inspecting *repo_path*."""
    # Reuse compose / openapi detection.
    compose_path = _find_compose(repo_path)
    openapi_path = _find_openapi(repo_path)

    languages = _detect_languages(repo_path)
    framework = _detect_framework(repo_path)
    has_tests = _detect_tests(repo_path)
    has_graphql = _detect_graphql(repo_path)
    has_health = _detect_health_check(compose_path, openapi_path)

    return CapabilityProfile(
        has_openapi_spec=openapi_path is not None,
        has_graphql_schema=has_graphql,
        has_tests=has_tests,
        has_docker=compose_path is not None,
        has_health_check=has_health,
        openapi_path=openapi_path,
        compose_path=compose_path,
        languages=sorted(set(languages)),
        framework=framework,
    )


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def _detect_languages(repo_path: str) -> list[str]:
    """Walk the repo (top-level files only, plus one level deep) and return
    detected languages based on file extensions."""
    found: set[str] = set()
    for entry in _iter_files(repo_path):
        ext = os.path.splitext(entry)[1].lower()
        if ext in _EXTENSION_LANG_MAP:
            found.add(_EXTENSION_LANG_MAP[ext])
    # Also check one level of subdirectories so we don't miss `src/main.go`.
    for subdir in _iter_dirs(repo_path):
        for entry in _iter_files(subdir):
            ext = os.path.splitext(entry)[1].lower()
            if ext in _EXTENSION_LANG_MAP:
                found.add(_EXTENSION_LANG_MAP[ext])
    return sorted(found)


def _detect_framework(repo_path: str) -> str | None:
    """Detect framework from dependency files in the repo root."""
    # Python: requirements.txt or pyproject.toml
    for dep_file in ("requirements.txt", "pyproject.toml"):
        dep_path = os.path.join(repo_path, dep_file)
        if os.path.isfile(dep_path):
            try:
                with open(dep_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read().lower()
            except OSError:
                continue
            for marker, framework in _PYTHON_FRAMEWORKS.items():
                if marker in content:
                    return framework

    # Node: package.json
    pkg_path = os.path.join(repo_path, "package.json")
    if os.path.isfile(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read().lower()
        except OSError:
            return None
        for marker, framework in _NODE_FRAMEWORKS.items():
            if marker in content:
                return framework

    return None


def _detect_tests(repo_path: str) -> bool:
    """Return True if a ``tests/`` dir exists or test files are present."""
    if os.path.isdir(os.path.join(repo_path, "tests")):
        return True
    # Look for *_test.py or test_*.py in the root.
    for entry in _iter_files(repo_path):
        name = os.path.basename(entry)
        if name.endswith("_test.py") or name.startswith("test_"):
            return True
    return False


def _detect_graphql(repo_path: str) -> bool:
    """Return True if .graphql or .gql files exist anywhere in the first two
    levels of the repo."""
    for entry in _iter_files(repo_path):
        if _is_graphql_file(entry):
            return True
    for subdir in _iter_dirs(repo_path):
        for entry in _iter_files(subdir):
            if _is_graphql_file(entry):
                return True
    return False


def _is_graphql_file(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in (".graphql", ".gql")


def _detect_health_check(
    compose_path: str | None,
    openapi_path: str | None,
) -> bool:
    """Check compose for ``healthcheck:`` or OpenAPI paths for ``/health``."""
    if compose_path is not None:
        try:
            with open(compose_path, "r", encoding="utf-8", errors="replace") as fh:
                if "healthcheck:" in fh.read():
                    return True
        except OSError:
            pass

    if openapi_path is not None:
        try:
            with open(openapi_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
                if "/health" in content:
                    return True
        except OSError:
            pass

    return False
