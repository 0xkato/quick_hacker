"""
Evidence gathering service for vulnerability triage.

Symbol-centered evidence collection with strict time budgets.
Runs synchronously (called via asyncio.to_thread).
"""

import re
import time
from pathlib import Path
from typing import Optional

from models.schemas import Finding, BudgetConfig, Evidence, InputChannel
from services.input_channel_inference import infer_input_channel
from services.evidence.types import SymbolInfo, SSRFAnalysis
from services.evidence.collectors import CodeCollector, RouteCollector, AuthGateCollector


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

        # Initialize collectors
        self.code_collector = CodeCollector(repo_root)
        self.route_collector = RouteCollector(repo_root)
        self.auth_gate_collector = AuthGateCollector(repo_root)

    def gather(self, finding: Finding) -> Evidence:
        """
        Gather evidence for a single finding.
        Returns: Evidence with matches, snippet, symbol_info, and input channel inference
        """
        start_time = time.time()

        try:
            # Step 1: Read file and extract snippet
            snippet = self.code_collector.extract_snippet(finding.file_path, finding.line_start)

            # Step 2: Identify enclosing symbol
            symbol_info_dataclass = self.code_collector.identify_symbol(
                finding.file_path, finding.line_start
            )

            # Step 3: Detect framework
            framework = self.code_collector.detect_framework(finding.file_path)

            # Step 4: Type-specific searches
            matches_dataclasses = self._gather_type_specific_evidence(
                finding, symbol_info_dataclass, framework, start_time
            )

            # Step 5: SSRF-specific analysis
            ssrf_analysis_dataclass = None
            if "ssrf" in finding.vulnerability_type.lower():
                ssrf_analysis_dataclass = self._analyze_ssrf(finding, snippet, symbol_info_dataclass)

            elapsed_ms = (time.time() - start_time) * 1000

            # Convert dataclasses to dicts for Pydantic model
            symbol_info_dict = None
            if symbol_info_dataclass:
                symbol_info_dict = {
                    "name": symbol_info_dataclass.name,
                    "qualified_name": symbol_info_dataclass.qualified_name,
                    "type": symbol_info_dataclass.type,
                    "line_start": symbol_info_dataclass.line_start,
                    "line_end": symbol_info_dataclass.line_end,
                    "file_path": symbol_info_dataclass.file_path,
                }

            matches_dicts = [
                {
                    "file": m.file,
                    "line": m.line,
                    "snippet": m.snippet,
                    "match_type": m.match_type,
                }
                for m in matches_dataclasses
            ]

            ssrf_analysis_dict = None
            if ssrf_analysis_dataclass:
                ssrf_analysis_dict = {
                    "url_is_constant": ssrf_analysis_dataclass.url_is_constant,
                    "url_from_config": ssrf_analysis_dataclass.url_from_config,
                    "url_expression": ssrf_analysis_dataclass.url_expression,
                }

            # Extract evidence fields for Evidence model
            handler_snippet = None
            route_registration = None
            auth_gates = []
            dataflow_snippet = None

            # Handler snippet from symbol
            if symbol_info_dataclass:
                handler_snippet = self.code_collector.extract_handler_snippet(
                    finding.file_path, symbol_info_dataclass
                )

            # Extract route registration and auth gates from matches
            for match in matches_dataclasses:
                if match.match_type == "route_registration":
                    route_registration = match.snippet
                elif match.match_type == "auth_gate":
                    auth_gates.append(match.snippet)
                elif match.match_type == "dataflow":
                    dataflow_snippet = match.snippet

            # Create Evidence model
            evidence = Evidence(
                finding_id=finding.id,
                snippet=snippet,
                handler_snippet=handler_snippet,
                symbol_info=symbol_info_dict,
                framework=framework,
                route_registration=route_registration,
                auth_gates=auth_gates,
                dataflow_snippet=dataflow_snippet,
                matches=matches_dicts,
                ssrf_analysis=ssrf_analysis_dict,
                timed_out=elapsed_ms > self.budget_ms_per_finding,
                # Phase 3 fields initialized with defaults
                input_channel=InputChannel.unknown,
                input_channel_deterministic=False,
                input_channel_signals=[],
                input_channel_reason="",
            )

            # Phase 3: Infer input channel
            infer_input_channel(finding=finding, evidence=evidence)

            return evidence

        except Exception as e:
            # On error, return minimal evidence
            error_evidence = Evidence(
                finding_id=finding.id,
                snippet=f"Error gathering evidence: {str(e)}",
                handler_snippet=None,
                symbol_info=None,
                framework=None,
                route_registration=None,
                auth_gates=[],
                dataflow_snippet=None,
                matches=[],
                ssrf_analysis=None,
                timed_out=(time.time() - start_time) * 1000 > self.budget_ms_per_finding,
                input_channel=InputChannel.unknown,
                input_channel_deterministic=False,
                input_channel_signals=[],
                input_channel_reason=f"Error: {str(e)}",
            )
            return error_evidence

    def _gather_type_specific_evidence(
        self,
        finding: Finding,
        symbol_info: Optional[SymbolInfo],
        framework: Optional[str],
        start_time: float
    ) -> list:
        """Gather evidence based on vulnerability type."""
        matches = []

        try:
            # Check remaining budget
            elapsed_ms = (time.time() - start_time) * 1000
            if elapsed_ms > self.budget_ms_per_finding:
                return matches

            # Search for sources
            matches.extend(self.auth_gate_collector.search_sources(finding, symbol_info))

            # Search for sinks
            matches.extend(self.auth_gate_collector.search_sinks(finding, symbol_info))

            # Search for auth gates
            matches.extend(self.auth_gate_collector.search_auth_gates(finding, symbol_info))

            # Search for route registration (STRONG reachability)
            matches.extend(
                self.route_collector.search_route_registration(finding, symbol_info, framework)
            )

            return matches
        except Exception:
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


class EvidenceService:
    """
    Unified evidence collection and quest management.

    Provides a single API for both synchronous evidence gathering
    and asynchronous quest orchestration.
    """

    def __init__(self, repo_root: str, budgets: BudgetConfig, llm_client=None, db_conn=None):
        self.gatherer = EvidenceGatherer(repo_root, budgets)
        self.quest_manager = None

        # Only initialize quest manager if LLM client and DB are provided
        if llm_client and db_conn:
            # Import here to avoid circular dependencies
            from services.evidence.quest_manager import EvidenceQuestOrchestrator
            self.quest_manager = EvidenceQuestOrchestrator(repo_root, llm_client, db_conn)

    def gather(self, finding: Finding) -> Evidence:
        """Synchronous evidence collection."""
        return self.gatherer.gather(finding)

    async def create_quest(self, finding: Finding, evidence: Evidence, missing_items: list[str]):
        """Create asynchronous evidence quest."""
        if not self.quest_manager:
            raise ValueError("Quest manager not initialized (no LLM client or database)")
        return await self.quest_manager.create_quest(finding, evidence, missing_items)

    async def run_quest(self, quest, finding: Finding, evidence: Evidence):
        """Run asynchronous evidence quest."""
        if not self.quest_manager:
            raise ValueError("Quest manager not initialized (no LLM client or database)")
        return await self.quest_manager.run_quest(quest, finding, evidence)
