"""Route evidence collector - route registration detection."""
import subprocess
import json
from pathlib import Path
from typing import Optional

from models.schemas import Finding
from services.evidence.types import SymbolInfo, EvidenceMatch


# Excluded directories for ripgrep searches
EXCLUDED_DIRS = [
    ".git", ".venv", "venv", "site-packages", "node_modules",
    "dist", "build", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".tox", "htmlcov", "coverage", ".coverage", "eggs", ".eggs",
    "*.egg-info", "target", "vendor"
]


class RouteCollector:
    """Handles route registration detection."""

    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)

    def search_route_registration(
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
