"""ValidationProfile schema models for configuring finding validation behavior.

This module defines the core schema models for validation profiles, which control
how findings are validated, what evidence is required, and what attacker capabilities
are considered in scope for a given project.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AttackerRole(BaseModel):
    """Defines what input channels an attacker can/cannot control.

    Attacker roles model different threat actor capabilities. For example,
    a "remote_unauthenticated" attacker might control HTTP request bodies
    but not session tokens, while a "remote_authenticated" attacker might
    control both.

    Attributes:
        can_control: Input channels this attacker can control (e.g., http_body, query_params).
        cannot_control: Channels explicitly NOT attacker-controlled (e.g., server_env).
        inherits: Parent role name to inherit capabilities from.
        trust_boundary: The boundary this attacker operates from (e.g., network_edge).
        exceptions: When cannot_control items become controllable (key: channel, value: condition).
    """

    can_control: list[str] = Field(default_factory=list)
    cannot_control: list[str] = Field(default_factory=list)
    inherits: Optional[str] = None
    trust_boundary: Optional[str] = None
    exceptions: dict[str, str] = Field(default_factory=dict)


class TrustBoundary(BaseModel):
    """Defines a trust boundary between system components.

    Trust boundaries separate components with different trust levels.
    Data flowing across a trust boundary typically requires validation
    or authentication.

    Attributes:
        untrusted_side: Components on the untrusted side (e.g., external_client, public_internet).
        trusted_side: Components on the trusted side (e.g., internal_server, database).
        description: Human-readable description of what crossing this boundary means.
    """

    untrusted_side: list[str] = Field(default_factory=list)
    trusted_side: list[str] = Field(default_factory=list)
    description: Optional[str] = None


class CategoryEvidenceGate(BaseModel):
    """Defines evidence requirements for a vulnerability category.

    Evidence gates specify what proof is needed before a finding
    in a particular category is considered valid. They also define
    auto-reject conditions and verification tools.

    Attributes:
        required: Evidence items required (default: source_identified, sink_identified,
                  dataflow_chain, shipped_reachability, security_impact).
        reject_if: Conditions that auto-reject a finding (e.g., no_user_input, dead_code).
        verifiers: Verification tools to use (e.g., gdb, sqlmap, valgrind).
    """

    required: list[str] = Field(
        default_factory=lambda: [
            "source_identified",
            "sink_identified",
            "dataflow_chain",
            "shipped_reachability",
            "security_impact",
        ]
    )
    reject_if: list[str] = Field(default_factory=list)
    verifiers: list[str] = Field(default_factory=list)


class ValidationProfile(BaseModel):
    """Configuration profile for finding validation behavior.

    A validation profile defines the rules and requirements for validating
    security findings in a project. It includes attacker models, trust
    boundaries, evidence requirements, and other validation settings.

    Attributes:
        excluded_paths: Directory path prefixes to skip during analysis (e.g., "tools/", "test/").
        attacker_roles: Named attacker role definitions (e.g., remote_network, local_user).
        trust_boundaries: Named trust boundary definitions.
        evidence_gates: Evidence requirements per vulnerability category.
        enabled_verifiers: List of verification tools enabled for this profile.
        default_verdict: Default verdict when evidence is inconclusive.
        require_shipped_reachability: Whether to require proof that code ships/is reachable.
    """

    excluded_paths: list[str] = Field(default_factory=list)
    attacker_roles: dict[str, AttackerRole] = Field(default_factory=dict)
    trust_boundaries: dict[str, TrustBoundary] = Field(default_factory=dict)
    evidence_gates: dict[str, CategoryEvidenceGate] = Field(default_factory=dict)
    enabled_verifiers: list[str] = Field(default_factory=list)
    default_verdict: str = "not_actionable"
    require_shipped_reachability: bool = True
