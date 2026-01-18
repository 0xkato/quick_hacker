"""Vulnerability classification module.

Provides StrictClassifier for zero false-positive vulnerability classification
with modular gate architecture for each vulnerability category.
"""
from .classifier import StrictClassifier, ClassificationResult
from .gates.base import BaseGate, GateResult

__all__ = [
    "StrictClassifier",
    "ClassificationResult",
    "BaseGate",
    "GateResult",
]
