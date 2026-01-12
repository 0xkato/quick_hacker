"""Models for persistent sink/signal tracking.

Sink signals are investigation leads (sources/sinks/interesting hotspots), not validated findings.
They persist per project so repeated scans can go deeper over time without mixing projects.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class CandidateStatus(str, Enum):
    """Taxonomy of validation outcomes (zero-FP protocol)."""
    PENDING = "pending"
    VALIDATED_VULNERABILITY = "validated_vulnerability"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    HARDENING_OPPORTUNITY = "hardening_opportunity"
    NOT_A_VULNERABILITY = "not_a_vulnerability"
    DUPLICATE = "duplicate"


class SinkSignalStatus(str, Enum):
    UNREVIEWED = "unreviewed"
    QUEUED = "queued"
    REVIEWED = "reviewed"
    DISMISSED = "dismissed"
    PROMOTED = "promoted"


class SinkSignalKind(str, Enum):
    ENTRY_POINT = "entry_point"
    SINK = "sink"
    OTHER = "other"


class RiskTier(str, Enum):
    S = "S"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"


class SinkSignal(BaseModel):
    """A persistent investigation lead."""

    fingerprint: str = Field(..., description="Deterministic ID used for deduplication")
    kind: SinkSignalKind
    label: str
    file_path: str
    line_number: Optional[int] = None

    status: SinkSignalStatus = SinkSignalStatus.UNREVIEWED
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Where this signal came from (e.g., 'attack_surface_triage', 'llm', 'external:<tool>')
    source: str = "llm"

    # Deterministic/system classification (optional).
    system_risk_tier: Optional[RiskTier] = None
    system_score: Optional[int] = Field(None, ge=0, le=100)
    system_reasoning: Optional[str] = None

    # LLM classification (optional override/annotation).
    llm_risk_tier: Optional[RiskTier] = None
    llm_score: Optional[int] = Field(None, ge=0, le=100)
    llm_reasoning: Optional[str] = None

    metadata: dict[str, Any] = Field(default_factory=dict)

