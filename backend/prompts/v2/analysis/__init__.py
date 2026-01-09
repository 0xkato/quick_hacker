"""Phase 3: Specialized analysis prompts by vulnerability type."""

from .base_analysis import BaseAnalysisPrompt
from .sql_injection import SQLInjectionAnalyzer, build_sqli_prompt

__all__ = [
    "BaseAnalysisPrompt",
    "SQLInjectionAnalyzer", "build_sqli_prompt",
]
