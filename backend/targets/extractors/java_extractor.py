"""Extract fuzzable targets from Java codebases."""
from __future__ import annotations

import re
from pathlib import Path


def extract_java_targets(repo_path: str | list[str]) -> list[dict]:
    paths = [repo_path] if isinstance(repo_path, str) else repo_path
    targets = []

    for base_path in paths:
        p = Path(base_path)
        for f in p.rglob("*.java"):
            rel = f.relative_to(p)
            if _should_skip(rel):
                continue
            try:
                content = f.read_text(errors="ignore")
                methods = _extract_methods(content, str(rel))
                targets.extend(methods)
            except Exception:
                continue

    return targets


def _extract_methods(content: str, file_path: str) -> list[dict]:
    targets = []

    # Find class name
    class_match = re.search(r'(?:public\s+)?class\s+(\w+)', content)
    class_name = class_match.group(1) if class_match else "Unknown"

    # Find public methods
    method_pattern = re.compile(
        r'public\s+(?:static\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)'
    )

    for match in method_pattern.finditer(content):
        method_name = match.group(1)
        params = match.group(2)

        # Skip common non-fuzzable methods
        if method_name in ("main", "toString", "equals", "hashCode", "compareTo"):
            continue

        fuzzable_params = ["byte[]", "String", "InputStream", "Reader", "ByteBuffer"]
        is_fuzzable = any(fp in params for fp in fuzzable_params)
        is_parser = any(kw in method_name.lower() for kw in ["parse", "decode", "deserialize", "read", "process"])

        if is_fuzzable or is_parser:
            targets.append({
                "kind": "native_function",
                "entrypoint": f"{file_path}:{class_name}.{method_name}",
                "language": "java",
                "schemas": None,
                "stateful": False,
                "actors": [],
                "reset_strategy": "function_call",
                "priority_score": 0.7 if is_fuzzable else 0.4,
            })

    return targets


def _should_skip(path: Path) -> bool:
    skip = ["test", "Test", ".git", "build", "target", "generated"]
    return any(s in str(path) for s in skip)
