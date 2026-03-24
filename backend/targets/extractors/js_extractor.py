"""Extract fuzzable targets from JavaScript/TypeScript codebases."""
from __future__ import annotations

import re
from pathlib import Path


def extract_js_targets(repo_path: str) -> list[dict]:
    targets = []
    p = Path(repo_path)

    for ext in [".js", ".ts", ".mjs", ".mts"]:
        for f in p.rglob(f"*{ext}"):
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
    language = "typescript" if file_path.endswith((".ts", ".mts")) else "javascript"

    # Match exported functions
    patterns = [
        re.compile(r'export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)'),
        re.compile(r'export\s+(?:const|let)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)'),
        re.compile(r'module\.exports\.(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)'),
    ]

    for pattern in patterns:
        for match in pattern.finditer(content):
            func_name = match.group(1)
            params = match.group(2)

            if func_name.startswith("test") or func_name.startswith("_"):
                continue

            fuzzable_params = ["data", "buf", "input", "body", "payload", "content", "raw", "buffer"]
            is_fuzzable = any(fp in params.lower() for fp in fuzzable_params)
            is_parser = any(kw in func_name.lower() for kw in ["parse", "decode", "process", "handle", "transform"])

            if is_fuzzable or is_parser:
                targets.append({
                    "kind": "native_function",
                    "entrypoint": f"{file_path}:{func_name}",
                    "language": language,
                    "schemas": None,
                    "stateful": False,
                    "actors": [],
                    "reset_strategy": "function_call",
                    "priority_score": 0.6 if is_fuzzable else 0.3,
                })

    return targets


def _should_skip(path: Path) -> bool:
    skip = ["test", "spec", "node_modules", ".git", "dist", "build", "__tests__"]
    return any(s in str(path).lower() for s in skip)
