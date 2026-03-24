"""Extract fuzzable targets from Rust codebases."""
from __future__ import annotations

import re
from pathlib import Path


def extract_rust_targets(repo_path: str) -> list[dict]:
    targets = []
    p = Path(repo_path)

    for f in p.rglob("*.rs"):
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

    func_pattern = re.compile(r'pub\s+fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)')

    for match in func_pattern.finditer(content):
        func_name = match.group(1)
        params = match.group(2)

        fuzzable_params = ["&[u8]", "&str", "Vec<u8>", "String", "&mut", "impl Read", "Bytes"]
        is_fuzzable = any(fp in params for fp in fuzzable_params)
        is_parser = any(kw in func_name.lower() for kw in ["parse", "decode", "deserialize", "read", "from_"])

        if is_fuzzable or is_parser:
            targets.append({
                "kind": "native_function",
                "entrypoint": f"{file_path}:{func_name}",
                "language": "rust",
                "schemas": None,
                "stateful": False,
                "actors": [],
                "reset_strategy": "function_call",
                "priority_score": 0.7 if is_fuzzable else 0.4,
            })

    return targets


def _should_skip(path: Path) -> bool:
    skip = ["test", "target", ".git", "benches"]
    return any(s in str(path).lower() for s in skip)
