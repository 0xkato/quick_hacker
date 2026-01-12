# backend/agents/deep_audit/state.py
"""Supervisor state for LangGraph orchestration."""

from typing import List, Dict
from pydantic import BaseModel, Field


class SupervisorState(BaseModel):
    """
    Shared state for the Deep Audit supervisor graph.

    This state is passed between all LangGraph nodes and maintains
    the complete audit context including scopes, signals, coverage,
    and time budget.
    """

    # Project context
    project_id: str
    scan_tier: str  # quick/medium/advanced/pro/ultra/evil
    deadline: float  # Unix timestamp when budget expires

    # Repo understanding
    repo_profile_path: str = "/memories/repo_profile.json"
    scope_plan: List[Dict[str, str]] = Field(default_factory=list)  # [{scope_id, path, status}]
    completed_scopes: List[str] = Field(default_factory=list)

    # Coverage tracking
    coverage_map: Dict[str, bool] = Field(default_factory=dict)  # {file_path: touched}

    # Signal management
    signal_queue: List[str] = Field(default_factory=list)  # [signal_id] ranked by priority
    active_case_ids: List[str] = Field(default_factory=list)

    # Limits and counters
    max_signals: int = 100
    max_findings: int = 50
    signal_count: int = 0
    finding_count: int = 0

    class Config:
        """Pydantic config."""
        # Allow mutation for LangGraph state updates
        frozen = False
