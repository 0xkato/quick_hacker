"""Auth gate evidence collector - authentication detection."""
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


class AuthGateCollector:
    """Handles authentication gate detection."""

    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)

    def search_auth_gates(
        self,
        finding: Finding,
        symbol_info: Optional[SymbolInfo]
    ) -> list[EvidenceMatch]:
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

    def search_sources(
        self,
        finding: Finding,
        symbol_info: Optional[SymbolInfo]
    ) -> list[EvidenceMatch]:
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

    def search_sinks(
        self,
        finding: Finding,
        symbol_info: Optional[SymbolInfo]
    ) -> list[EvidenceMatch]:
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
