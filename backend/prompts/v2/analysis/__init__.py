"""Phase 3: Specialized analysis prompts by vulnerability type."""

from .base_analysis import BaseAnalysisPrompt
from .sql_injection import SQLInjectionAnalyzer, build_sqli_prompt
from .command_injection import CommandInjectionAnalyzer, build_cmdi_prompt
from .path_traversal import PathTraversalAnalyzer, build_path_traversal_prompt
from .xss import XSSAnalyzer, build_xss_prompt
from .ssrf import SSRFAnalyzer, build_ssrf_prompt

__all__ = [
    "BaseAnalysisPrompt",
    "SQLInjectionAnalyzer", "build_sqli_prompt",
    "CommandInjectionAnalyzer", "build_cmdi_prompt",
    "PathTraversalAnalyzer", "build_path_traversal_prompt",
    "XSSAnalyzer", "build_xss_prompt",
    "SSRFAnalyzer", "build_ssrf_prompt",
]
