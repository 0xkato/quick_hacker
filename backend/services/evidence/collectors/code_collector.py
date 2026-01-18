"""Code evidence collector - snippet extraction and file reading."""
import ast
import re
from pathlib import Path
from typing import Optional

from services.evidence.types import SymbolInfo


class CodeCollector:
    """Handles code snippet extraction and file operations."""

    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)
        self.file_cache: dict[str, list[str]] = {}

    def extract_snippet(self, file_path: str, line_number: int, context_lines: int = 30) -> str:
        """Extract ±context_lines around the reported line."""
        try:
            lines = self.read_file_lines(file_path)
            if not lines:
                return ""

            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)

            snippet_lines = []
            for i in range(start, end):
                snippet_lines.append(f"{i+1:4d} | {lines[i]}")

            return "\n".join(snippet_lines)
        except Exception:
            return ""

    def extract_handler_snippet(self, file_path: str, symbol_info: SymbolInfo) -> Optional[str]:
        """Extract handler/function code from symbol info."""
        try:
            lines = self.read_file_lines(file_path)
            if not lines:
                return None

            # Extract lines for the symbol
            start = max(0, symbol_info.line_start - 1)
            end = min(len(lines), symbol_info.line_end)

            handler_lines = []
            for i in range(start, end):
                handler_lines.append(lines[i])

            return "\n".join(handler_lines)
        except Exception:
            return None

    def read_file_lines(self, file_path: str) -> list[str]:
        """Read file lines with caching."""
        if file_path in self.file_cache:
            return self.file_cache[file_path]

        try:
            full_path = self.repo_root / file_path
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.rstrip('\n') for line in f.readlines()]

            # Cache for future use
            self.file_cache[file_path] = lines
            return lines
        except Exception:
            return []

    def identify_symbol(self, file_path: str, line_number: int) -> Optional[SymbolInfo]:
        """Identify enclosing function/class via AST parse."""
        try:
            full_path = self.repo_root / file_path

            # Only try AST for Python files
            if not file_path.endswith('.py'):
                return self._identify_symbol_heuristic(file_path, line_number)

            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()

            tree = ast.parse(content)

            # Walk AST to find enclosing function or class
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                        if node.lineno <= line_number <= (node.end_lineno or node.lineno):
                            symbol_type = "class" if isinstance(node, ast.ClassDef) else "function"
                            return SymbolInfo(
                                name=node.name,
                                qualified_name=node.name,  # TODO: Could compute full qual name
                                type=symbol_type,
                                line_start=node.lineno,
                                line_end=node.end_lineno or node.lineno,
                                file_path=file_path
                            )

            return None
        except Exception:
            # Fallback to heuristic
            return self._identify_symbol_heuristic(file_path, line_number)

    def _identify_symbol_heuristic(self, file_path: str, line_number: int) -> Optional[SymbolInfo]:
        """Heuristic: scan backwards for def/class."""
        try:
            lines = self.read_file_lines(file_path)
            if not lines:
                return None

            # Scan backwards
            for i in range(line_number - 1, -1, -1):
                line = lines[i].strip()

                # Check for function definition
                func_match = re.match(r'(async\s+)?def\s+(\w+)\s*\(', line)
                if func_match:
                    return SymbolInfo(
                        name=func_match.group(2),
                        qualified_name=func_match.group(2),
                        type="function",
                        line_start=i + 1,
                        line_end=min(i + 100, len(lines)),  # Estimate
                        file_path=file_path
                    )

                # Check for class definition
                class_match = re.match(r'class\s+(\w+)', line)
                if class_match:
                    return SymbolInfo(
                        name=class_match.group(1),
                        qualified_name=class_match.group(1),
                        type="class",
                        line_start=i + 1,
                        line_end=min(i + 200, len(lines)),  # Estimate
                        file_path=file_path
                    )

            return None
        except Exception:
            return None

    def detect_framework(self, file_path: str) -> Optional[str]:
        """Detect framework from imports in file."""
        try:
            lines = self.read_file_lines(file_path)
            if not lines:
                return None

            # Check first 100 lines for imports
            import_section = "\n".join(lines[:100])

            # Framework patterns
            if re.search(r'from\s+fastapi|import\s+fastapi', import_section, re.IGNORECASE):
                return "fastapi"
            if re.search(r'from\s+flask|import\s+flask', import_section, re.IGNORECASE):
                return "flask"
            if re.search(r'from\s+django|import\s+django', import_section, re.IGNORECASE):
                return "django"
            if re.search(r'from\s+aiohttp|import\s+aiohttp', import_section, re.IGNORECASE):
                return "aiohttp"
            if re.search(r'from\s+tornado|import\s+tornado', import_section, re.IGNORECASE):
                return "tornado"
            if re.search(r'from\s+sanic|import\s+sanic', import_section, re.IGNORECASE):
                return "sanic"

            return None
        except Exception:
            return None
