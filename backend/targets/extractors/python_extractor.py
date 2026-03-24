"""Extract fuzzable functions from Python codebases."""
from __future__ import annotations

import ast
import re
from pathlib import Path


def extract_python_targets(repo_path: str) -> list[dict]:
    """Extract fuzzable Python function targets."""
    targets = []
    p = Path(repo_path)

    for f in p.rglob("*.py"):
        rel = f.relative_to(p)
        if _should_skip(rel):
            continue
        try:
            content = f.read_text(errors="ignore")
            tree = ast.parse(content)
            funcs = _extract_functions(tree, content, str(rel))
            targets.extend(funcs)
        except (SyntaxError, Exception):
            continue

    return targets


def _extract_functions(tree: ast.Module, content: str, file_path: str) -> list[dict]:
    """Extract functions that look fuzzable from an AST."""
    targets = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name

            # Skip private, test, and dunder methods
            if name.startswith("_") and not name.startswith("__init__"):
                continue
            if name.startswith("test_"):
                continue

            # Check if function takes data-like parameters
            params = [arg.arg for arg in node.args.args if arg.arg != "self"]
            fuzzable_params = ["data", "buf", "input", "payload", "content", "body",
                             "text", "raw", "bytes", "stream", "request", "query"]

            is_fuzzable = any(any(fp in p.lower() for fp in fuzzable_params) for p in params)
            is_parser = _is_parser_function(name)

            if is_fuzzable or is_parser:
                module_path = file_path.replace("/", ".").replace(".py", "")
                targets.append({
                    "kind": "native_function",
                    "entrypoint": f"{file_path}:{name}",
                    "language": "python",
                    "schemas": None,
                    "stateful": False,
                    "actors": [],
                    "reset_strategy": "function_call",
                    "priority_score": 0.7 if is_fuzzable else 0.4,
                })

    return targets


def _is_parser_function(name: str) -> bool:
    parser_keywords = ["parse", "decode", "deserialize", "load", "read", "process",
                       "handle", "convert", "transform", "validate", "sanitize"]
    return any(kw in name.lower() for kw in parser_keywords)


def _should_skip(path: Path) -> bool:
    skip = ["test", "spec", "build", "vendor", "node_modules", ".git", "__pycache__", "venv", "migrations"]
    return any(s in str(path).lower() for s in skip)
