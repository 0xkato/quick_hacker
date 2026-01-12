"""Agent prompts for dual-model analysis."""

from .scanner_prompt import format_scanner_prompt
from .analyzer_prompt import format_analyzer_prompt

__all__ = ["format_scanner_prompt", "format_analyzer_prompt"]
