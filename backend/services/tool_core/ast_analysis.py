"""AST analysis capabilities for ToolCore."""
from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from typing import Any


class ASTAnalysisMixin:
    """Mixin for AST analysis operations.

    This mixin provides methods for analyzing source files using AST parsing
    and dataflow tracing. It requires the following attributes to be set:
    - repo_path: Path to repository root
    - _validate_path: Method to validate file paths
    """

    async def analyze_ast(self, file_path: str) -> dict[str, Any]:
        """Analyze a source file with best-effort AST parsing.

        Currently supports Python files (`.py`).
        """
        resolved = self._validate_path(file_path)
        suffix = resolved.suffix.lower()

        content = await asyncio.to_thread(resolved.read_text, errors="ignore")

        if suffix != ".py":
            return {
                "file_path": file_path,
                "language": "unknown",
                "supported": False,
                "error": f"Unsupported file type for AST analysis: {suffix}",
            }

        tree = ast.parse(content)

        functions: list[dict[str, Any]] = []
        classes: list[dict[str, Any]] = []
        imports: list[dict[str, Any]] = []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(
                    {
                        "name": node.name,
                        "line_start": getattr(node, "lineno", None),
                        "line_end": getattr(node, "end_lineno", None),
                        "args": [a.arg for a in node.args.args],
                        "is_async": isinstance(node, ast.AsyncFunctionDef),
                    }
                )
            elif isinstance(node, ast.ClassDef):
                classes.append(
                    {
                        "name": node.name,
                        "line_start": getattr(node, "lineno", None),
                        "line_end": getattr(node, "end_lineno", None),
                        "methods": [
                            n.name
                            for n in node.body
                            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                        ],
                    }
                )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(
                        {
                            "module": alias.name,
                            "asname": alias.asname,
                            "line": getattr(node, "lineno", None),
                        }
                    )
            elif isinstance(node, ast.ImportFrom):
                imports.append(
                    {
                        "module": node.module,
                        "names": [a.name for a in node.names],
                        "level": node.level,
                        "line": getattr(node, "lineno", None),
                    }
                )

        return {
            "file_path": file_path,
            "language": "python",
            "supported": True,
            "functions": functions,
            "classes": classes,
            "imports": imports,
        }

    async def trace_dataflow(self, file_path: str, line_number: int) -> dict[str, Any]:
        """Best-effort local dataflow trace for a given file location.

        This is intentionally conservative and Python-only for now; it is meant to
        help the model gather evidence, not to prove exploitability on its own.
        """
        resolved = self._validate_path(file_path)
        if resolved.suffix.lower() != ".py":
            return {
                "file_path": file_path,
                "line_number": line_number,
                "supported": False,
                "error": "trace_dataflow currently supports Python files only",
            }

        content = await asyncio.to_thread(resolved.read_text, errors="ignore")
        tree = ast.parse(content)

        # Find the smallest enclosing function.
        enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None = None
        enclosing_span: int | None = None
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start is None or end is None:
                continue
            if start <= line_number <= end:
                span = end - start
                if enclosing is None or (enclosing_span is not None and span < enclosing_span):
                    enclosing = node
                    enclosing_span = span

        if enclosing is None:
            return {
                "file_path": file_path,
                "line_number": line_number,
                "supported": True,
                "enclosing_function": None,
                "variables": [],
            }

        # Collect assignments up to the target line.
        assignments: dict[str, ast.AST] = {}
        for node in ast.walk(enclosing):
            node_line = getattr(node, "lineno", None)
            if node_line is None or node_line >= line_number:
                continue
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = node.value
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.value is not None:
                    assignments[node.target.id] = node.value
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    assignments[node.target.id] = node.value

        # Find variable names referenced on the target line.
        referenced: set[str] = set()
        for node in ast.walk(enclosing):
            if getattr(node, "lineno", None) != line_number:
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                    referenced.add(sub.id)

        args = {a.arg for a in enclosing.args.args}

        def fmt(expr: ast.AST) -> str:
            try:
                return ast.unparse(expr)
            except Exception:
                return expr.__class__.__name__

        traces: list[dict[str, Any]] = []
        for name in sorted(referenced):
            chain: list[str] = [name]
            origin: str | None = None

            cur = name
            for _ in range(10):
                if cur in args:
                    origin = "parameter"
                    break
                expr = assignments.get(cur)
                if expr is None:
                    break
                if isinstance(expr, ast.Name):
                    cur = expr.id
                    chain.append(cur)
                    continue
                origin = fmt(expr)
                break

            traces.append({"name": name, "chain": chain, "origin": origin})

        return {
            "file_path": file_path,
            "line_number": int(line_number),
            "supported": True,
            "enclosing_function": {
                "name": enclosing.name,
                "line_start": getattr(enclosing, "lineno", None),
                "line_end": getattr(enclosing, "end_lineno", None),
                "is_async": isinstance(enclosing, ast.AsyncFunctionDef),
            },
            "variables": traces,
        }
