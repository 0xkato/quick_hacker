"""
Evidence gathering service for vulnerability triage.

Symbol-centered evidence collection with strict time budgets.
Runs synchronously (called via asyncio.to_thread).
"""

import ast
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from models.schemas import Finding, BudgetConfig


# Excluded directories for ripgrep searches
EXCLUDED_DIRS = [
    ".git", ".venv", "venv", "site-packages", "node_modules",
    "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".tox", "htmlcov", "coverage", ".coverage", "eggs", ".eggs",
    "*.egg-info", "target", "vendor"
]


@dataclass
class SymbolInfo:
    """Information about the enclosing symbol (function/class)."""
    name: str
    qualified_name: str
    type: str  # "function" or "class"
    line_start: int
    line_end: int
    file_path: str


@dataclass
class EvidenceMatch:
    """A single evidence match from ripgrep."""
    file: str
    line: int
    snippet: str  # ±5 lines context
    match_type: str  # source, sink, auth_gate, route_registration, etc.


@dataclass
class SSRFAnalysis:
    """SSRF-specific analysis."""
    url_is_constant: bool = False
    url_from_config: bool = False
    url_expression: Optional[str] = None


@dataclass
class EvidenceResult:
    """Complete evidence gathered for a finding."""
    snippet: str  # ±30 lines around reported line
    symbol_info: Optional[SymbolInfo]
    framework: Optional[str]
    matches: list[EvidenceMatch] = field(default_factory=list)
    ssrf_analysis: Optional[SSRFAnalysis] = None
    timed_out: bool = False


class EvidenceGatherer:
    """
    Symbol-centered evidence collection with strict budgets.

    Responsibilities:
    - Extract context snippet (±30 lines)
    - Identify enclosing symbol via AST
    - Detect framework from imports
    - Run type-specific rg searches
    - Return structured evidence matches
    """

    def __init__(self, repo_root: str, budgets: BudgetConfig):
        self.repo_root = Path(repo_root)
        self.budget_ms_per_finding = budgets.per_finding_ms
        self.max_evidence_bytes = budgets.max_evidence_bytes
        self.max_snippet_lines = budgets.max_snippet_lines
        self.file_cache: dict[str, list[str]] = {}

    def gather(self, finding: Finding) -> EvidenceResult:
        """
        Gather evidence for a single finding.
        Returns: EvidenceResult with matches, snippet, symbol_info
        """
        start_time = time.time()

        try:
            # Step 1: Read file and extract snippet
            snippet = self._extract_snippet(finding.file_path, finding.line_start)

            # Step 2: Identify enclosing symbol
            symbol_info = self._identify_symbol(finding.file_path, finding.line_start)

            # Step 3: Detect framework
            framework = self._detect_framework(finding.file_path, symbol_info)

            # Step 4: Type-specific searches
            matches = self._gather_type_specific_evidence(
                finding, symbol_info, framework, start_time
            )

            # Step 5: SSRF-specific analysis
            ssrf_analysis = None
            if "ssrf" in finding.vulnerability_type.lower():
                ssrf_analysis = self._analyze_ssrf(finding, snippet, symbol_info)

            elapsed_ms = (time.time() - start_time) * 1000

            return EvidenceResult(
                snippet=snippet,
                symbol_info=symbol_info,
                framework=framework,
                matches=matches,
                ssrf_analysis=ssrf_analysis,
                timed_out=elapsed_ms > self.budget_ms_per_finding
            )
        except Exception as e:
            # On error, return minimal evidence
            return EvidenceResult(
                snippet=f"Error gathering evidence: {str(e)}",
                symbol_info=None,
                framework=None,
                matches=[],
                timed_out=(time.time() - start_time) * 1000 > self.budget_ms_per_finding
            )

    def _extract_snippet(self, file_path: str, line_number: int, context_lines: int = 30) -> str:
        """Extract ±context_lines around the reported line."""
        try:
            lines = self._read_file_lines(file_path)
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

    def _read_file_lines(self, file_path: str) -> list[str]:
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

    def _identify_symbol(self, file_path: str, line_number: int) -> Optional[SymbolInfo]:
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
            lines = self._read_file_lines(file_path)
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

    def _detect_framework(self, file_path: str, symbol_info: Optional[SymbolInfo]) -> Optional[str]:
        """Detect framework from imports in file."""
        try:
            lines = self._read_file_lines(file_path)
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

    def _gather_type_specific_evidence(
        self,
        finding: Finding,
        symbol_info: Optional[SymbolInfo],
        framework: Optional[str],
        start_time: float
    ) -> list[EvidenceMatch]:
        """Gather evidence based on vulnerability type."""
        matches = []

        try:
            # Check remaining budget
            elapsed_ms = (time.time() - start_time) * 1000
            if elapsed_ms > self.budget_ms_per_finding:
                return matches

            # Search for sources
            matches.extend(self._search_sources(finding, symbol_info))

            # Search for sinks
            matches.extend(self._search_sinks(finding, symbol_info))

            # Search for auth gates
            matches.extend(self._search_auth_gates(finding, symbol_info))

            # Search for route registration (STRONG reachability)
            matches.extend(self._search_route_registration(finding, symbol_info, framework))

            return matches
        except Exception:
            return matches

    def _search_sources(self, finding: Finding, symbol_info: Optional[SymbolInfo]) -> list[EvidenceMatch]:
        """Search for user input sources."""
        patterns = [
            r'request\.(get|post|query_params|path_params|body|json|form|files|cookies|headers)',
            r'websocket\.(receive|accept|iter)',
            r'input\s*\(',
            r'sys\.argv',
            r'os\.environ',
            r'@app\.(get|post|put|delete|patch)',
        ]

        return self._rg_search(patterns, finding.file_path, symbol_info, "source")

    def _search_sinks(self, finding: Finding, symbol_info: Optional[SymbolInfo]) -> list[EvidenceMatch]:
        """Search for dangerous sinks."""
        patterns = [
            r'subprocess\.(call|run|Popen|check_output).*shell\s*=\s*True',
            r'os\.(system|popen|exec)',
            r'eval\s*\(',
            r'exec\s*\(',
            r'__import__\s*\(',
            r'\.execute\s*\(',  # SQL
            r'\.raw\s*\(',  # Django ORM
            r'pickle\.loads',
            r'yaml\.load\(',
            r'requests\.(get|post|put|delete|patch|request)',
            r'httpx\.(get|post|put|delete|patch|request)',
            r'\.get\(.*http',  # aiohttp client
        ]

        return self._rg_search(patterns, finding.file_path, symbol_info, "sink")

    def _search_auth_gates(self, finding: Finding, symbol_info: Optional[SymbolInfo]) -> list[EvidenceMatch]:
        """Search for authentication/authorization checks."""
        patterns = [
            r'@require_auth',
            r'@login_required',
            r'@permission_required',
            r'check_permission',
            r'check_auth',
            r'verify_token',
            r'is_authenticated',
            r'Depends\(.*auth',
        ]

        return self._rg_search(patterns, finding.file_path, symbol_info, "auth_gate")

    def _search_route_registration(
        self,
        finding: Finding,
        symbol_info: Optional[SymbolInfo],
        framework: Optional[str]
    ) -> list[EvidenceMatch]:
        """Search for route/handler registration (STRONG reachability evidence)."""
        patterns = []

        if framework == "fastapi":
            patterns = [
                r'@app\.(get|post|put|delete|patch|api_route)',
                r'@router\.(get|post|put|delete|patch|api_route)',
                r'\.add_api_route\(',
            ]
        elif framework == "flask":
            patterns = [
                r'@app\.route\(',
                r'@bp\.route\(',
                r'\.add_url_rule\(',
            ]
        elif framework == "django":
            patterns = [
                r'path\(',
                r'url\(',
                r're_path\(',
            ]
        elif framework == "aiohttp":
            patterns = [
                r'\.add_route\(',
                r'app\.router\.add_',
            ]
        else:
            # Generic patterns
            patterns = [
                r'@app\.(get|post|route)',
                r'@router\.',
                r'\.route\(',
                r'\.add_route\(',
            ]

        if not patterns:
            return []

        return self._rg_search(patterns, finding.file_path, symbol_info, "route_registration")

    def _rg_search(
        self,
        patterns: list[str],
        file_path: str,
        symbol_info: Optional[SymbolInfo],
        match_type: str
    ) -> list[EvidenceMatch]:
        """Run ripgrep search with patterns."""
        matches = []

        try:
            # Build ripgrep command
            rg_args = ["rg", "--json", "--context", "5", "--max-count", "10"]

            # Add exclusions
            for excluded in EXCLUDED_DIRS:
                rg_args.extend(["--glob", f"!{excluded}"])

            # Combine patterns with OR
            pattern = "|".join(f"({p})" for p in patterns)
            rg_args.append(pattern)

            # If symbol info, search within those line ranges
            # For simplicity, we'll search the whole file (ripgrep doesn't support line ranges directly)
            full_path = self.repo_root / file_path
            if not full_path.exists():
                return matches

            rg_args.append(str(full_path))

            # Run ripgrep with timeout
            result = subprocess.run(
                rg_args,
                capture_output=True,
                text=True,
                timeout=1  # 1 second timeout per search
            )

            # Parse JSON output
            import json
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get('type') == 'match':
                        match_data = data.get('data', {})
                        line_number = match_data.get('line_number', 0)

                        # Get context
                        lines = match_data.get('lines', {}).get('text', '')

                        matches.append(EvidenceMatch(
                            file=file_path,
                            line=line_number,
                            snippet=lines,
                            match_type=match_type
                        ))

                        # Limit matches
                        if len(matches) >= 20:
                            break
                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return matches

    def _analyze_ssrf(
        self,
        finding: Finding,
        snippet: str,
        symbol_info: Optional[SymbolInfo]
    ) -> SSRFAnalysis:
        """Analyze SSRF call site for URL construction."""
        analysis = SSRFAnalysis()

        try:
            # Look for URL patterns in snippet
            url_patterns = [
                r'https?://[^\s\'"]+',  # Hardcoded URLs
                r'url\s*=\s*[\'"]https?://[^\'"]+[\'"]',  # url = "http://..."
                r'\.get\([\'"]https?://',  # requests.get("http://...")
            ]

            for pattern in url_patterns:
                if re.search(pattern, snippet):
                    analysis.url_is_constant = True
                    break

            # Look for config/env patterns
            config_patterns = [
                r'os\.environ\[',
                r'os\.getenv\(',
                r'config\.',
                r'settings\.',
                r'env\.',
            ]

            for pattern in config_patterns:
                if re.search(pattern, snippet):
                    analysis.url_from_config = True
                    break

        except Exception:
            pass

        return analysis
