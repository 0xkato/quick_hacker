"""Static call-tree builder for FastAPI projects.

This is a lightweight, best-effort call tree intended for security triage:
- Rooted at a FastAPI route handler
- Expands into in-repo function calls
- Optionally includes external calls as leaf nodes
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from .framework_parsers import FrameworkParsers


IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build"}


@dataclass(frozen=True)
class _FunctionRef:
    module: str
    name: str

    @property
    def symbol_id(self) -> str:
        return f"{self.module}:{self.name}"


@dataclass
class _ModuleInfo:
    module: str
    file_rel: str
    tree: ast.AST
    imported_modules: dict[str, str]
    imported_symbols: dict[str, tuple[str, str]]
    functions: dict[str, ast.AST]


class CallTreeBuilder:
    """Build a call-tree rooted at a FastAPI HTTP route handler."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self._module_to_file: dict[str, str] = {}
        self._module_cache: dict[str, _ModuleInfo] = {}
        self._index_modules()

    def list_fastapi_routes(self) -> list[dict]:
        """Return FastAPI routes with stable IDs."""
        parsers = FrameworkParsers(str(self.repo_path))
        routes = [r for r in parsers.parse_routes() if r.get("framework") == "fastapi"]

        enriched: list[dict] = []
        for r in routes:
            route_id = self._route_id(r)
            enriched.append(
                {
                    "id": route_id,
                    "method": r.get("method", ""),
                    "path": r.get("path", ""),
                    "handler": r.get("handler", ""),
                    "file": r.get("file", ""),
                    "line": r.get("line"),
                    "framework": r.get("framework", ""),
                    "label": f'{r.get("method", "")} {r.get("path", "")}',
                }
            )
        return enriched

    def build_call_tree(
        self,
        route: dict,
        max_depth: int = 4,
        include_external: bool = True,
        max_nodes: int = 250,
    ) -> dict:
        """Build a call tree for a parsed route."""
        route_id = route.get("id") or self._route_id(route)
        timestamp = datetime.utcnow().isoformat()

        nodes: list[dict] = []
        edges: list[dict] = []
        next_node_id = 0
        next_edge_id = 0

        def alloc_node_id() -> str:
            nonlocal next_node_id
            nid = f"n{next_node_id}"
            next_node_id += 1
            return nid

        def alloc_edge_id() -> str:
            nonlocal next_edge_id
            eid = f"e{next_edge_id}"
            next_edge_id += 1
            return eid

        def add_node(node_type: str, label: str, data: dict) -> str:
            node_id = alloc_node_id()
            nodes.append(
                {
                    "id": node_id,
                    "type": node_type,
                    "label": label,
                    "status": "completed",
                    "data": data,
                    "timestamp": timestamp,
                }
            )
            return node_id

        def add_edge(source: str, target: str, label: Optional[str] = None) -> None:
            edges.append(
                {
                    "id": alloc_edge_id(),
                    "source": source,
                    "target": target,
                    "label": label,
                }
            )

        # Root: route node
        route_node_id = add_node(
            "entry_point",
            f'{route.get("method", "")} {route.get("path", "")}'.strip(),
            {
                "symbol_id": f'route:{route.get("method", "")} {route.get("path", "")}'.strip(),
                "file": route.get("file"),
                "line": route.get("line"),
                "handler": route.get("handler"),
                "method": route.get("method"),
                "path": route.get("path"),
            },
        )

        handler_file = str(route.get("file") or "")
        handler_name = str(route.get("handler") or "")
        handler_module = self._path_to_module(handler_file)

        handler_node = self._find_function(handler_module, handler_name)
        handler_ref = _FunctionRef(module=handler_module, name=handler_name)

        # Root: handler function
        handler_node_id = add_node(
            "function",
            f"{handler_name}()",
            {
                "symbol_id": handler_ref.symbol_id,
                "module": handler_module,
                "file": handler_file,
                "line": getattr(handler_node, "lineno", route.get("line")),
            },
        )
        add_edge(route_node_id, handler_node_id, "calls")

        if next_node_id >= max_nodes:
            return {"session_id": route_id, "nodes": nodes, "edges": edges, "current_node_id": None}

        # Track already-expanded functions to prevent duplicate work across paths
        visited: set[str] = set()

        def expand_function(
            caller_ref: _FunctionRef,
            caller_node_id: str,
            caller_ast: ast.AST,
            depth: int,
            stack: list[str],
        ) -> None:
            if depth >= max_depth:
                return

            for call_name, callee in self._iter_calls(caller_ref.module, caller_ast):
                if next_node_id >= max_nodes:
                    return

                if callee is None:
                    if not include_external:
                        continue
                    ext_node_id = add_node(
                        "external",
                        call_name,
                        {"symbol_id": f"external:{call_name}", "name": call_name},
                    )
                    add_edge(caller_node_id, ext_node_id, "calls")
                    continue

                if callee.symbol_id in stack:
                    cycle_node_id = add_node(
                        "cycle",
                        f"{callee.name}()",
                        {
                            "symbol_id": callee.symbol_id,
                            "module": callee.module,
                            "file": self._module_to_file.get(callee.module),
                            "cycle": True,
                        },
                    )
                    add_edge(caller_node_id, cycle_node_id, "calls")
                    continue

                callee_ast = self._find_function(callee.module, callee.name)
                callee_file = self._module_to_file.get(callee.module)

                callee_node_id = add_node(
                    "function",
                    f"{callee.name}()",
                    {
                        "symbol_id": callee.symbol_id,
                        "module": callee.module,
                        "file": callee_file,
                        "line": getattr(callee_ast, "lineno", None),
                    },
                )
                add_edge(caller_node_id, callee_node_id, "calls")

                # Only expand if not already visited (prevents duplicate work across paths)
                if callee.symbol_id not in visited:
                    visited.add(callee.symbol_id)
                    expand_function(
                        callee,
                        callee_node_id,
                        callee_ast,
                        depth + 1,
                        stack + [callee.symbol_id],
                    )

        # Mark handler as visited before expanding
        visited.add(handler_ref.symbol_id)
        expand_function(
            handler_ref,
            handler_node_id,
            handler_node,
            0,
            [handler_ref.symbol_id],
        )

        return {
            "session_id": route_id,
            "nodes": nodes,
            "edges": edges,
            "current_node_id": None,
        }

    def _index_modules(self) -> None:
        for file_path in self.repo_path.rglob("*.py"):
            if not file_path.is_file():
                continue
            if any(part in IGNORED_DIRS for part in file_path.parts):
                continue
            rel = file_path.relative_to(self.repo_path).as_posix()
            module = self._path_to_module(rel)
            if module:
                self._module_to_file[module] = rel

    def _path_to_module(self, file_rel: str) -> str:
        rel = Path(file_rel)
        if rel.suffix != ".py":
            return rel.as_posix().replace("/", ".")

        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)

    def _route_id(self, route: dict) -> str:
        key = f'{route.get("method","")} {route.get("path","")} {route.get("file","")}:{route.get("line","")} {route.get("handler","")}'
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]

    def _get_module_info(self, module: str) -> _ModuleInfo:
        cached = self._module_cache.get(module)
        if cached:
            return cached

        file_rel = self._module_to_file.get(module)
        if not file_rel:
            raise ValueError(f"Unknown module: {module}")

        source = (self.repo_path / file_rel).read_text(errors="replace")
        tree = ast.parse(source)

        imported_modules: dict[str, str] = {}
        imported_symbols: dict[str, tuple[str, str]] = {}
        functions: dict[str, ast.AST] = {}

        for node in tree.body:  # type: ignore[attr-defined]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[node.name] = node
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name
                    imported_modules[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                imported_from_module = self._resolve_import_from_module(module, node)
                if not imported_from_module:
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    imported_symbols[local] = (imported_from_module, alias.name)

        info = _ModuleInfo(
            module=module,
            file_rel=file_rel,
            tree=tree,
            imported_modules=imported_modules,
            imported_symbols=imported_symbols,
            functions=functions,
        )
        self._module_cache[module] = info
        return info

    def _resolve_import_from_module(self, current_module: str, node: ast.ImportFrom) -> Optional[str]:
        raw_module = node.module or ""
        level = getattr(node, "level", 0) or 0

        if level == 0:
            return raw_module or None

        current_parts = current_module.split(".") if current_module else []
        if level > len(current_parts):
            return raw_module or None

        base = current_parts[: len(current_parts) - level]
        if raw_module:
            return ".".join(base + raw_module.split("."))
        return ".".join(base) if base else None

    def _find_function(self, module: str, name: str) -> ast.AST:
        info = self._get_module_info(module)
        node = info.functions.get(name)
        if not node:
            raise ValueError(f"Function not found: {module}:{name}")
        return node

    def _iter_calls(self, module: str, function_node: ast.AST) -> list[tuple[str, Optional[_FunctionRef]]]:
        info = self._get_module_info(module)
        calls: list[tuple[str, Optional[_FunctionRef]]] = []

        for node in ast.walk(function_node):
            if not isinstance(node, ast.Call):
                continue

            callee_name = self._format_call_name(node.func)
            if not callee_name:
                continue

            target = self._resolve_call(module, info, node.func)
            calls.append((callee_name, target))

        return calls

    def _format_call_name(self, func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
            return func.attr
        return None

    def _resolve_call(self, module: str, info: _ModuleInfo, func: ast.AST) -> Optional[_FunctionRef]:
        # Direct function call: foo()
        if isinstance(func, ast.Name):
            if func.id in info.functions:
                return _FunctionRef(module=module, name=func.id)

            imported = info.imported_symbols.get(func.id)
            if imported:
                imported_module, imported_name = imported
                if imported_module in self._module_to_file:
                    try:
                        imported_info = self._get_module_info(imported_module)
                        if imported_name in imported_info.functions:
                            return _FunctionRef(module=imported_module, name=imported_name)
                    except Exception:
                        return None
            return None

        # Attribute call: mod.foo()
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            attr = func.attr

            imported_module = info.imported_modules.get(base)
            if imported_module and imported_module in self._module_to_file:
                imported_info = self._get_module_info(imported_module)
                if attr in imported_info.functions:
                    return _FunctionRef(module=imported_module, name=attr)

            imported_symbol = info.imported_symbols.get(base)
            if imported_symbol:
                base_module, base_name = imported_symbol
                candidate_module = f"{base_module}.{base_name}"
                if candidate_module in self._module_to_file:
                    candidate_info = self._get_module_info(candidate_module)
                    if attr in candidate_info.functions:
                        return _FunctionRef(module=candidate_module, name=attr)

        return None
