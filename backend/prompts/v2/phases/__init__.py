"""Phase-specific prompts."""

from .exploration import ExplorationPrompt, build_exploration_prompt
from .triage import TriagePrompt, build_triage_prompt
from .verification import (
    EvidenceVerificationPrompt,
    DevilsAdvocatePrompt,
    ProofOfConceptPrompt,
    FinalGatePrompt,
    build_verification_pipeline,
)

__all__ = [
    "ExplorationPrompt", "build_exploration_prompt",
    "TriagePrompt", "build_triage_prompt",
    "EvidenceVerificationPrompt",
    "DevilsAdvocatePrompt",
    "ProofOfConceptPrompt",
    "FinalGatePrompt",
    "build_verification_pipeline",
]
