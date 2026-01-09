"""Phase 3: Specialized analysis prompts by vulnerability type."""

from .base_analysis import BaseAnalysisPrompt
from .sql_injection import SQLInjectionAnalyzer, build_sqli_prompt
from .command_injection import CommandInjectionAnalyzer, build_cmdi_prompt

__all__ = [
    "BaseAnalysisPrompt",
    "SQLInjectionAnalyzer", "build_sqli_prompt",
    "CommandInjectionAnalyzer", "build_cmdi_prompt",
]
