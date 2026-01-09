"""Prompt assembly orchestrator - combines layers for each phase."""

from typing import Dict, Any, List, Optional
from .base import ProviderAdapter, CoreConstraints
from .phases import build_exploration_prompt, build_triage_prompt, build_verification_pipeline
from .analysis import (
    build_sqli_prompt,
    build_cmdi_prompt,
    build_xss_prompt,
    build_ssrf_prompt,
    build_path_traversal_prompt,
)


class PromptAssembler:
    """Assembles complete prompts for each phase."""

    ANALYZERS = {
        "sql_injection": build_sqli_prompt,
        "command_injection": build_cmdi_prompt,
        "xss": build_xss_prompt,
        "ssrf": build_ssrf_prompt,
        "path_traversal": build_path_traversal_prompt,
    }

    def __init__(self, model_name: str):
        self.model_name = model_name
        self.adapter = ProviderAdapter()

    def assemble_exploration(
        self,
        repo_name: str,
        repo_root: Optional[str] = None,
        known_languages: Optional[List[str]] = None,
    ) -> str:
        """Assemble Phase 1 exploration prompt."""
        base = build_exploration_prompt(repo_name, repo_root, known_languages)
        with_constraints = CoreConstraints.get_all() + "\n\n" + base
        return self.adapter.format_prompt(with_constraints, self.model_name)

    def assemble_triage(
        self,
        tech_stack: Dict[str, Any],
        entry_points: Optional[List[Dict]] = None,
        threat_model: Optional[str] = None,
    ) -> str:
        """Assemble Phase 2 triage prompt."""
        base = build_triage_prompt(tech_stack, threat_model, entry_points)
        with_constraints = CoreConstraints.get_all() + "\n\n" + base
        return self.adapter.format_prompt(with_constraints, self.model_name)

    def assemble_analysis(
        self,
        vuln_type: str,
        candidates: List[Dict[str, Any]],
        framework: Optional[str] = None,
        tech_stack: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Assemble Phase 3 analysis prompt for specific vuln type."""
        builder = self.ANALYZERS.get(vuln_type)
        if not builder:
            raise ValueError(f"Unknown vulnerability type: {vuln_type}. Known: {list(self.ANALYZERS.keys())}")

        base = builder(candidates, framework, tech_stack)
        with_constraints = CoreConstraints.get_all() + "\n\n" + base
        return self.adapter.format_prompt(with_constraints, self.model_name)

    def assemble_verification(self, finding: Dict[str, Any]) -> str:
        """Assemble Phase 4 verification pipeline prompt."""
        base = build_verification_pipeline(finding)
        with_constraints = CoreConstraints.get_all() + "\n\n" + base
        return self.adapter.format_prompt(with_constraints, self.model_name)

    def get_supported_vuln_types(self) -> List[str]:
        """Return list of supported vulnerability types."""
        return list(self.ANALYZERS.keys())
