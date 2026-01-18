"""Types and models for evidence collection."""
from dataclasses import dataclass, field
from typing import Protocol, Optional

from models.schemas import Finding


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


class EvidenceCollector(Protocol):
    """Protocol for evidence collectors."""

    def collect(self, finding: Finding, repo_root: str) -> dict:
        """
        Collect specific type of evidence for a finding.

        Args:
            finding: Finding to collect evidence for
            repo_root: Repository root path

        Returns:
            Dictionary of collected evidence
        """
        ...
