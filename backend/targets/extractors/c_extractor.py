"""Extract fuzzable functions from C/C++ codebases.

Finds exported functions, parser entry points, and input handlers
by analyzing source files and headers.
"""
from __future__ import annotations

import re
from pathlib import Path


def extract_c_targets(
    repo_path: str | list[str],
    language: str = "c",
    repo_root: str | None = None,
) -> list[dict]:
    """Extract fuzzable C/C++ function targets from a repository.

    Args:
        repo_path: Path(s) to scan for source files.
        language: "c" or "cpp" to select file extensions.
        repo_root: If provided, entrypoints are relative to this root
                   (not the search path). Ensures consistent paths when
                   scanning a scoped subdirectory.
    """
    paths = [repo_path] if isinstance(repo_path, str) else repo_path
    root = Path(repo_root) if repo_root else Path(paths[0])
    targets = []

    extensions = {
        "c": [".c"],
        "cpp": [".cpp", ".cc", ".cxx"],
        "c++": [".cpp", ".cc"],
    }
    exts = extensions.get(language, [".c", ".cpp"])

    for base_path in paths:
        p = Path(base_path)
        for ext in exts:
            for f in p.rglob(f"*{ext}"):
                rel = f.relative_to(root)
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
    """Extract function definitions that look fuzzable.

    Uses a permissive regex that matches any C/C++ return type including
    typedefs (uint8_t, bt_status_t, etc.), struct pointers, and qualifiers.
    Skips forward declarations (lines ending with ;).
    """
    targets = []

    # Permissive pattern: qualifiers + any type + function_name(params)
    func_pattern = re.compile(
        r'^\s*'
        r'(?:(?:static|extern|inline|const|volatile|__attribute__\s*\([^)]*\))\s+)*'
        r'(?:(?:unsigned|signed|long|short|const|volatile|enum|struct|union)\s+)*'
        r'(?:\w+)\s*\*?\s+'
        r'(\w+)\s*\(([^)]*)\)',
        re.MULTILINE,
    )

    for match in func_pattern.finditer(content):
        func_name = match.group(1)
        params = match.group(2).strip()

        # Skip forward declarations (semicolon after closing paren)
        after = content[match.end():match.end() + 30].lstrip()
        if after.startswith(";"):
            continue

        # Skip common non-fuzzable functions
        if func_name in (
            "main", "printf", "fprintf", "snprintf", "sprintf",
            "malloc", "free", "memcpy", "memset", "memmove",
            "strlen", "strcmp", "strncmp", "strcpy", "strncpy",
        ):
            continue

        # Prioritize functions that take buffer/data/input parameters
        fuzzable_indicators = [
            "buf", "data", "input", "str", "msg", "packet", "payload",
            "char *", "const char *", "uint8_t *", "void *", "size_t",
            "net_buf", "pdu", "frame", "bytes", "len",
        ]
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
    parser_keywords = [
        "parse", "decode", "deserialize", "read", "load", "process",
        "handle", "recv", "accept", "extract", "convert", "transform",
    ]
    return any(kw in name.lower() for kw in parser_keywords)


def _should_skip(path: Path) -> bool:
    """Skip test dirs, build artifacts, vendor code.

    Uses path-component matching (not substring) to avoid false positives
    like 'attestation.c' matching 'test'.
    """
    skip = {"test", "tests", "spec", "specs", "build", "vendor",
            "third_party", "node_modules", ".git"}
    return bool(skip & {p.lower() for p in path.parts})
