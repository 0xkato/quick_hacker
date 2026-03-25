"""Extract fuzzable functions from C/C++ codebases.

Finds exported functions, parser entry points, and input handlers
by analyzing source files and headers.
"""
from __future__ import annotations

import re
from pathlib import Path


def extract_c_targets(repo_path: str | list[str], language: str = "c") -> list[dict]:
    """Extract fuzzable C/C++ function targets from a repository."""
    paths = [repo_path] if isinstance(repo_path, str) else repo_path
    targets = []

    extensions = {"c": [".c", ".h"], "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".h"], "c++": [".cpp", ".cc", ".hpp", ".h"]}
    exts = extensions.get(language, [".c", ".cpp", ".h"])

    for base_path in paths:
        p = Path(base_path)
        for ext in exts:
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
    """Extract function declarations that look fuzzable."""
    targets = []

    # Match function definitions: return_type function_name(params)
    func_pattern = re.compile(
        r'^\s*(?:static\s+)?(?:inline\s+)?'
        r'(?:int|void|char\s*\*|size_t|bool|unsigned|long|FILE\s*\*|struct\s+\w+\s*\*?)\s+'
        r'(\w+)\s*\(([^)]*)\)',
        re.MULTILINE
    )

    for match in func_pattern.finditer(content):
        func_name = match.group(1)
        params = match.group(2).strip()

        # Skip common non-fuzzable functions
        if func_name in ("main", "printf", "fprintf", "malloc", "free", "memcpy"):
            continue

        # Prioritize functions that take buffer/data/input parameters
        fuzzable_indicators = ["buf", "data", "input", "str", "msg", "packet", "payload",
                              "char *", "const char *", "uint8_t *", "void *", "size_t"]
        is_fuzzable = any(ind in params.lower() for ind in fuzzable_indicators)

        if is_fuzzable or _is_parser_function(func_name):
            targets.append({
                "kind": "native_function",
                "entrypoint": f"{file_path}:{func_name}",
                "language": "c" if file_path.endswith((".c", ".h")) else "cpp",
                "schemas": None,
                "stateful": False,
                "actors": [],
                "reset_strategy": "process_restart",
                "priority_score": 0.8 if is_fuzzable else 0.5,
            })

    return targets


def _is_parser_function(name: str) -> bool:
    """Check if function name suggests it's a parser."""
    parser_keywords = ["parse", "decode", "deserialize", "read", "load", "process",
                       "handle", "recv", "accept", "extract", "convert", "transform"]
    return any(kw in name.lower() for kw in parser_keywords)


def _should_skip(path: Path) -> bool:
    """Skip test files, build artifacts, vendor code."""
    skip = ["test", "spec", "build", "vendor", "third_party", "node_modules", ".git"]
    return any(s in str(path).lower() for s in skip)
