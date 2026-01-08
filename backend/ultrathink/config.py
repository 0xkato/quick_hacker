"""Configuration for ultrathink hierarchical verification cascade."""

from dataclasses import dataclass, field
from typing import Optional
from models.schemas import ThinkingMode, UltrathinkGate, Severity


# Models known to support native extended thinking
NATIVE_THINKING_MODELS = {
    "claude-opus-4-5-20251101",
    "claude-sonnet-4-20250514",
    # Add future Claude models with extended thinking
}

# Models that work well with simulated CoT
SIMULATED_THINKING_MODELS = {
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-4o-mini",
}


@dataclass
class GateConfig:
    """Configuration for a single verification gate."""

    name: str
    confidence_threshold: float = 0.85
    thinking_budget_tokens: int = 15000
    timeout_seconds: int = 120
    required: bool = True

    # Gate-specific settings
    adversarial_strength: float = 0.8  # How hard to argue against (0-1)
    require_evidence: bool = True
    require_code_refs: bool = True


@dataclass
class UltrathinkConfig:
    """Master configuration for ultrathink cascade."""

    # Thinking mode
    thinking_mode: ThinkingMode = ThinkingMode.AUTO
    min_thinking_tokens: int = 10000
    max_thinking_tokens: int = 50000

    # Reasoning transparency
    capture_full_trace: bool = True
    expose_thinking_to_user: bool = True

    # Severity triggers (which severities always get ultrathink)
    ultrathink_severities: set[Severity] = field(default_factory=lambda: {
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
    })

    # Gate configurations
    gates: list[GateConfig] = field(default_factory=lambda: [
        GateConfig(
            name=UltrathinkGate.TRIAGE.value,
            confidence_threshold=0.60,
            thinking_budget_tokens=5000,
            timeout_seconds=30,
            adversarial_strength=0.3,
        ),
        GateConfig(
            name=UltrathinkGate.DEEP_ANALYSIS.value,
            confidence_threshold=0.75,
            thinking_budget_tokens=25000,
            timeout_seconds=180,
            adversarial_strength=0.5,
        ),
        GateConfig(
            name=UltrathinkGate.DEVILS_ADVOCATE.value,
            confidence_threshold=0.80,
            thinking_budget_tokens=20000,
            timeout_seconds=120,
            adversarial_strength=0.9,  # Maximum adversarial
        ),
        GateConfig(
            name=UltrathinkGate.PROOF_GENERATOR.value,
            confidence_threshold=0.85,
            thinking_budget_tokens=15000,
            timeout_seconds=90,
            adversarial_strength=0.7,
        ),
        GateConfig(
            name=UltrathinkGate.FINAL_GATE.value,
            confidence_threshold=0.90,
            thinking_budget_tokens=10000,
            timeout_seconds=60,
            adversarial_strength=0.8,
        ),
    ])

    def resolve_thinking_mode(self, model: str) -> ThinkingMode:
        """Resolve AUTO thinking mode based on model."""
        if self.thinking_mode != ThinkingMode.AUTO:
            return self.thinking_mode

        if model in NATIVE_THINKING_MODELS:
            return ThinkingMode.NATIVE
        elif model in SIMULATED_THINKING_MODELS:
            return ThinkingMode.SIMULATED
        else:
            return ThinkingMode.STRUCTURED

    def get_gate(self, gate: UltrathinkGate) -> GateConfig:
        """Get config for a specific gate."""
        for g in self.gates:
            if g.name == gate.value:
                return g
        raise ValueError(f"Unknown gate: {gate}")

    def should_ultrathink(self, severity: Severity) -> bool:
        """Check if this severity should trigger ultrathink."""
        return severity in self.ultrathink_severities
