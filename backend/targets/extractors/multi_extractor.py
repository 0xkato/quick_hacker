"""Unified multi-language surface extractor.

Detects the repository's languages and runs appropriate extractors.
Combines results from all extractors into a single target list.
"""
from __future__ import annotations

from pathlib import Path
from targets.extractors.openapi_extractor import extract_targets_from_file
from targets.extractors.c_extractor import extract_c_targets
from targets.extractors.python_extractor import extract_python_targets
from targets.extractors.solidity_extractor import extract_solidity_targets
from targets.extractors.go_extractor import extract_go_targets
from targets.extractors.rust_extractor import extract_rust_targets
from targets.extractors.java_extractor import extract_java_targets
from targets.extractors.js_extractor import extract_js_targets


def extract_all_targets(
    repo_path: str,
    openapi_path: str | None = None,
    languages: list[str] | None = None,
) -> list[dict]:
    """Extract fuzz targets from a repository using all available extractors.

    Args:
        repo_path: Path to the repository
        openapi_path: Path to OpenAPI spec (if known)
        languages: Detected languages (if known, speeds up extraction)

    Returns:
        Combined list of target descriptors from all extractors
    """
    targets = []

    # Auto-detect languages if not provided
    if not languages:
        languages = _detect_languages(repo_path)

    # API targets (OpenAPI)
    if openapi_path:
        try:
            api_targets = extract_targets_from_file(openapi_path)
            targets.extend(api_targets)
        except Exception:
            pass

    # Language-specific extractors
    extractor_map = {
        "c": lambda: extract_c_targets(repo_path, "c"),
        "cpp": lambda: extract_c_targets(repo_path, "cpp"),
        "c++": lambda: extract_c_targets(repo_path, "cpp"),
        "python": lambda: extract_python_targets(repo_path),
        "solidity": lambda: extract_solidity_targets(repo_path),
        "go": lambda: extract_go_targets(repo_path),
        "rust": lambda: extract_rust_targets(repo_path),
        "java": lambda: extract_java_targets(repo_path),
        "javascript": lambda: extract_js_targets(repo_path),
        "typescript": lambda: extract_js_targets(repo_path),
    }

    for lang in languages:
        extractor = extractor_map.get(lang.lower())
        if extractor:
            try:
                lang_targets = extractor()
                targets.extend(lang_targets)
            except Exception:
                pass

    # Deduplicate by entrypoint
    seen = set()
    deduped = []
    for t in targets:
        key = t.get("entrypoint", "")
        if key not in seen:
            seen.add(key)
            deduped.append(t)

    # Sort by priority
    deduped.sort(key=lambda t: t.get("priority_score", 0), reverse=True)

    return deduped


def _detect_languages(repo_path: str) -> list[str]:
    """Detect languages in the repository by file extensions."""
    p = Path(repo_path)
    ext_to_lang = {
        ".py": "python", ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".h": "c",
        ".go": "go", ".rs": "rust", ".java": "java", ".sol": "solidity",
        ".js": "javascript", ".ts": "typescript", ".mjs": "javascript",
    }

    langs = set()
    for f in p.rglob("*"):
        if f.is_file() and f.suffix in ext_to_lang:
            rel = str(f.relative_to(p))
            if not any(skip in rel for skip in ["node_modules", "vendor", ".git", "test"]):
                langs.add(ext_to_lang[f.suffix])

    return list(langs)
