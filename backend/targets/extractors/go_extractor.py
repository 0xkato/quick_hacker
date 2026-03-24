"""Extract fuzzable targets from Go codebases."""
from __future__ import annotations

import re
from pathlib import Path


def extract_go_targets(repo_path: str) -> list[dict]:
    """Extract fuzzable Go function targets."""
    targets = []
    p = Path(repo_path)

    for f in p.rglob("*.go"):
        rel = f.relative_to(p)
        if _should_skip(rel):
            continue
        try:
            content = f.read_text(errors="ignore")
            funcs = _extract_functions(content, str(rel))
            targets.extend(funcs)
        except Exception:
            continue

    return targets


def _extract_functions(content: str, file_path: str) -> list[dict]:
    targets = []

    # Match exported functions (capitalized)
    func_pattern = re.compile(r'func\s+(?:\(\w+\s+\*?\w+\)\s+)?([A-Z]\w+)\s*\(([^)]*)\)')

    for match in func_pattern.finditer(content):
        func_name = match.group(1)
        params = match.group(2)

        fuzzable_params = ["[]byte", "string", "io.Reader", "[]uint8", "interface{}"]
        is_fuzzable = any(fp in params for fp in fuzzable_params)
        is_parser = _is_parser_function(func_name)

        if is_fuzzable or is_parser:
            pkg = _detect_package(content)
            targets.append({
                "kind": "native_function",
                "entrypoint": f"{file_path}:{func_name}",
                "language": "go",
                "schemas": None,
                "stateful": False,
                "actors": [],
                "reset_strategy": "function_call",
                "priority_score": 0.7 if is_fuzzable else 0.4,
            })

    return targets


def _detect_package(content: str) -> str:
    match = re.search(r'^package\s+(\w+)', content, re.MULTILINE)
    return match.group(1) if match else "main"


def _is_parser_function(name: str) -> bool:
    keywords = ["Parse", "Decode", "Unmarshal", "Read", "Load", "Process", "Handle", "Convert"]
    return any(name.startswith(kw) or kw in name for kw in keywords)


def _should_skip(path: Path) -> bool:
    skip = ["test", "vendor", ".git", "testdata"]
    parts = str(path).lower()
    return any(s in parts for s in skip) or str(path).endswith("_test.go")
