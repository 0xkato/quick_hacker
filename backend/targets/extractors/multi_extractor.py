"""Unified multi-language surface extractor.

Detects the repository's languages and runs appropriate extractors.
Combines results from all extractors into a single target list.

Supports path scoping, target filtering, and directed targets to
narrow extraction in large codebases.
"""
from __future__ import annotations

import fnmatch
import logging
from pathlib import Path

from targets.extractors.openapi_extractor import extract_targets_from_file
from targets.extractors.c_extractor import extract_c_targets
from targets.extractors.python_extractor import extract_python_targets
from targets.extractors.solidity_extractor import extract_solidity_targets
from targets.extractors.go_extractor import extract_go_targets
from targets.extractors.rust_extractor import extract_rust_targets
from targets.extractors.java_extractor import extract_java_targets
from targets.extractors.js_extractor import extract_js_targets

logger = logging.getLogger(__name__)


def extract_all_targets(
    repo_path: str,
    openapi_path: str | None = None,
    languages: list[str] | None = None,
    target_scope: str | None = None,
    target_filters: dict | None = None,
    directed_targets: list[str] | None = None,
) -> list[dict]:
    """Extract fuzz targets from a repository using all available extractors.

    Args:
        repo_path: Path to the repository
        openapi_path: Path to OpenAPI spec (if known)
        languages: Detected languages (if known, speeds up extraction)
        target_scope: Comma-separated relative paths to restrict extraction
                      (e.g., ``"drivers/usb,net/bluetooth"``)
        target_filters: Include/exclude rules applied after extraction.
                        Supported keys: ``include_kinds``, ``exclude_kinds``,
                        ``include_languages``, ``exclude_languages``,
                        ``include_patterns``, ``exclude_patterns``,
                        ``min_priority``.
        directed_targets: Exact entry points to fuzz. When provided, these
                          are created as priority-1.0 targets. Extraction
                          still runs so the results are merged.

    Returns:
        Combined list of target descriptors from all extractors
    """
    targets = []

    # -----------------------------------------------------------------
    # Directed targets — user-specified exact entry points
    # -----------------------------------------------------------------
    if directed_targets:
        for entry in directed_targets:
            language = _infer_language(entry)
            parts = entry.split()
            kind = (
                "api_route"
                if parts[0] in ("GET", "POST", "PUT", "DELETE", "PATCH")
                else "native_function"
            )
            targets.append({
                "kind": kind,
                "entrypoint": entry,
                "language": language,
                "schemas": None,
                "stateful": False,
                "actors": [],
                "reset_strategy": "function_call",
                "priority_score": 1.0,
            })

    # -----------------------------------------------------------------
    # Path scoping — restrict which directories are scanned
    # -----------------------------------------------------------------
    scoped_paths: list[str] = []

    if target_scope:
        scope_dirs = [s.strip() for s in target_scope.split(",")]
        for scope_dir in scope_dirs:
            full_path = Path(repo_path) / scope_dir
            logger.info("Checking scope dir: %r -> %s (exists=%s, is_dir=%s)",
                        scope_dir, full_path, full_path.exists(), full_path.is_dir() if full_path.exists() else "N/A")
            if full_path.exists() and full_path.is_dir():
                scoped_paths.append(str(full_path))

        if not scoped_paths:
            logger.warning(
                "Target scope %r matched no directories in %s",
                target_scope,
                repo_path,
            )

    # The paths each extractor will search: scoped dirs or full repo
    search_paths: str | list[str] = scoped_paths if scoped_paths else repo_path

    # -----------------------------------------------------------------
    # Auto-detect languages from actual search paths
    # -----------------------------------------------------------------
    if not languages:
        if isinstance(search_paths, list):
            all_langs: set[str] = set()
            for sp in search_paths:
                all_langs.update(_detect_languages(sp))
            languages = list(all_langs)
        else:
            languages = _detect_languages(search_paths)

    # -----------------------------------------------------------------
    # API targets (OpenAPI) — not scoped by path
    # -----------------------------------------------------------------
    if openapi_path:
        try:
            api_targets = extract_targets_from_file(openapi_path)
            targets.extend(api_targets)
        except Exception:
            pass

    # -----------------------------------------------------------------
    # Language-specific extractors
    # -----------------------------------------------------------------
    extractor_map = {
        "c": lambda: extract_c_targets(search_paths, "c", repo_root=repo_path),
        "cpp": lambda: extract_c_targets(search_paths, "cpp", repo_root=repo_path),
        "c++": lambda: extract_c_targets(search_paths, "cpp", repo_root=repo_path),
        "python": lambda: extract_python_targets(search_paths),
        "solidity": lambda: extract_solidity_targets(search_paths),
        "go": lambda: extract_go_targets(search_paths),
        "rust": lambda: extract_rust_targets(search_paths),
        "java": lambda: extract_java_targets(search_paths),
        "javascript": lambda: extract_js_targets(search_paths),
        "typescript": lambda: extract_js_targets(search_paths),
    }

    logger.info("Extracting targets for languages: %s from paths: %s", languages, search_paths)

    for lang in languages:
        extractor = extractor_map.get(lang.lower())
        if extractor:
            try:
                lang_targets = extractor()
                logger.info("  %s extractor found %d targets", lang, len(lang_targets))
                targets.extend(lang_targets)
            except Exception:
                logger.exception("  %s extractor failed", lang)

    # -----------------------------------------------------------------
    # Apply filters
    # -----------------------------------------------------------------
    targets = _apply_filters(targets, target_filters)

    # -----------------------------------------------------------------
    # Deduplicate by entrypoint
    # -----------------------------------------------------------------
    seen: set[str] = set()
    deduped: list[dict] = []
    for t in targets:
        key = t.get("entrypoint", "")
        if key not in seen:
            seen.add(key)
            deduped.append(t)

    # Sort by priority
    deduped.sort(key=lambda t: t.get("priority_score", 0), reverse=True)

    return deduped


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _apply_filters(targets: list[dict], filters: dict | None) -> list[dict]:
    """Apply include/exclude filters to extracted targets."""
    if not filters:
        return targets

    filtered = []
    for t in targets:
        kind = t.get("kind", "")
        lang = t.get("language", "")
        entry = t.get("entrypoint", "")
        priority = t.get("priority_score", 0)

        # Kind filters
        include_kinds = filters.get("include_kinds")
        if include_kinds and kind not in include_kinds:
            continue
        exclude_kinds = filters.get("exclude_kinds", [])
        if kind in exclude_kinds:
            continue

        # Language filters
        include_langs = filters.get("include_languages")
        if include_langs and lang not in include_langs:
            continue
        exclude_langs = filters.get("exclude_languages", [])
        if lang in exclude_langs:
            continue

        # Pattern filters
        include_patterns = filters.get("include_patterns")
        if include_patterns:
            if not any(fnmatch.fnmatch(entry, p) for p in include_patterns):
                continue
        exclude_patterns = filters.get("exclude_patterns", [])
        if any(fnmatch.fnmatch(entry, p) for p in exclude_patterns):
            continue

        # Priority filter
        min_priority = filters.get("min_priority", 0)
        if priority < min_priority:
            continue

        filtered.append(t)

    return filtered


def _infer_language(entrypoint: str) -> str | None:
    """Infer language from entrypoint file extension."""
    if ":" in entrypoint:
        file_part = entrypoint.split(":")[0]
        ext_map = {
            ".py": "python",
            ".c": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".go": "go",
            ".rs": "rust",
            ".java": "java",
            ".js": "javascript",
            ".ts": "typescript",
            ".sol": "solidity",
        }
        for ext, lang in ext_map.items():
            if file_part.endswith(ext):
                return lang
    return None


def _detect_languages(repo_path: str) -> list[str]:
    """Detect languages in the repository by file extensions."""
    p = Path(repo_path)
    ext_to_lang = {
        ".py": "python", ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".h": "c",
        ".go": "go", ".rs": "rust", ".java": "java", ".sol": "solidity",
        ".js": "javascript", ".ts": "typescript", ".mjs": "javascript",
    }

    skip_dirs = {"node_modules", "vendor", ".git", "test", "tests", "build"}
    langs: set[str] = set()
    for f in p.rglob("*"):
        if f.is_file() and f.suffix in ext_to_lang:
            parts = {part.lower() for part in f.relative_to(p).parts}
            if not (skip_dirs & parts):
                langs.add(ext_to_lang[f.suffix])

    return list(langs)
