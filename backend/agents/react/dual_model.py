"""Dual-model configuration for scanner/analyzer phases.

This module provides a wrapper around the core dual_model_config module,
adding ReAct-specific functionality for managing scanner and analyzer providers.
"""

from typing import Optional, Tuple
from dataclasses import dataclass

from models.schemas import ProviderConfig, AgentCreateRequest, HandoffMode
from agents.dual_model_config import (
    DEFAULT_SCANNER_MODELS,
    resolve_dual_model_config,
    get_handoff_mode,
)


@dataclass
class DualModelState:
    """State for dual-model scanner/analyzer configuration."""
    scanner_config: Optional[ProviderConfig]
    analyzer_config: Optional[ProviderConfig]
    is_dual_mode: bool
    handoff_mode: HandoffMode
    current_phase: str = "scanner"  # "scanner" or "analyzer"

    @classmethod
    def from_request(cls, request: AgentCreateRequest) -> "DualModelState":
        """
        Create dual model state from agent request.

        Args:
            request: Agent creation request

        Returns:
            Initialized dual model state
        """
        scanner_config, analyzer_config, is_dual_mode = resolve_dual_model_config(request)
        handoff_mode = get_handoff_mode(request)

        return cls(
            scanner_config=scanner_config,
            analyzer_config=analyzer_config,
            is_dual_mode=is_dual_mode,
            handoff_mode=handoff_mode,
            current_phase="scanner"
        )

    def should_use_scanner(self) -> bool:
        """Check if currently in scanner phase."""
        return self.is_dual_mode and self.current_phase == "scanner"

    def should_use_analyzer(self) -> bool:
        """Check if currently in analyzer phase."""
        return self.is_dual_mode and self.current_phase == "analyzer"

    def switch_to_analyzer(self) -> None:
        """Transition from scanner to analyzer phase."""
        if not self.is_dual_mode:
            raise ValueError("Cannot switch to analyzer in single-model mode")
        self.current_phase = "analyzer"

    def get_current_config(self) -> Optional[ProviderConfig]:
        """Get the provider config for current phase."""
        if not self.is_dual_mode:
            return None
        return self.scanner_config if self.current_phase == "scanner" else self.analyzer_config
