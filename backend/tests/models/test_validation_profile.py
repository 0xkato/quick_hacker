"""Tests for ValidationProfile schema models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models.validation_profile import (
    AttackerRole,
    CategoryEvidenceGate,
    TrustBoundary,
    ValidationProfile,
)


class TestAttackerRole:
    """Tests for the AttackerRole model."""

    def test_attacker_role_minimal_creation(self) -> None:
        """AttackerRole can be created with minimal fields."""
        role = AttackerRole(
            can_control=["http_request_body"],
            cannot_control=["server_environment"],
        )
        assert role.can_control == ["http_request_body"]
        assert role.cannot_control == ["server_environment"]
        assert role.inherits is None
        assert role.trust_boundary is None
        assert role.exceptions == {}

    def test_attacker_role_full_creation(self) -> None:
        """AttackerRole can be created with all fields."""
        role = AttackerRole(
            can_control=["http_request_body", "query_params"],
            cannot_control=["server_config", "database_schema"],
            inherits="base_remote",
            trust_boundary="network_edge",
            exceptions={"server_config": "when_admin_panel_exposed"},
        )
        assert role.can_control == ["http_request_body", "query_params"]
        assert role.cannot_control == ["server_config", "database_schema"]
        assert role.inherits == "base_remote"
        assert role.trust_boundary == "network_edge"
        assert role.exceptions == {"server_config": "when_admin_panel_exposed"}

    def test_attacker_role_empty_lists(self) -> None:
        """AttackerRole allows empty lists."""
        role = AttackerRole(can_control=[], cannot_control=[])
        assert role.can_control == []
        assert role.cannot_control == []


class TestTrustBoundary:
    """Tests for the TrustBoundary model."""

    def test_trust_boundary_minimal_creation(self) -> None:
        """TrustBoundary can be created with minimal fields."""
        boundary = TrustBoundary(
            untrusted_side=["external_client"],
            trusted_side=["internal_server"],
        )
        assert boundary.untrusted_side == ["external_client"]
        assert boundary.trusted_side == ["internal_server"]
        assert boundary.description is None

    def test_trust_boundary_with_description(self) -> None:
        """TrustBoundary can include a description."""
        boundary = TrustBoundary(
            untrusted_side=["public_internet", "user_browser"],
            trusted_side=["api_gateway", "backend_services"],
            description="Data crossing this boundary requires authentication and input validation",
        )
        assert boundary.description == "Data crossing this boundary requires authentication and input validation"

    def test_trust_boundary_empty_sides(self) -> None:
        """TrustBoundary allows empty lists for sides."""
        boundary = TrustBoundary(untrusted_side=[], trusted_side=[])
        assert boundary.untrusted_side == []
        assert boundary.trusted_side == []


class TestCategoryEvidenceGate:
    """Tests for the CategoryEvidenceGate model."""

    def test_evidence_gate_defaults(self) -> None:
        """CategoryEvidenceGate has correct defaults."""
        gate = CategoryEvidenceGate()
        expected_required = [
            "source_identified",
            "sink_identified",
            "dataflow_chain",
            "shipped_reachability",
            "security_impact",
        ]
        assert gate.required == expected_required
        assert gate.reject_if == []
        assert gate.verifiers == []

    def test_evidence_gate_custom_required(self) -> None:
        """CategoryEvidenceGate allows custom required evidence."""
        gate = CategoryEvidenceGate(
            required=["source_identified", "sink_identified"],
            reject_if=["no_user_input", "dead_code"],
            verifiers=["gdb", "valgrind"],
        )
        assert gate.required == ["source_identified", "sink_identified"]
        assert gate.reject_if == ["no_user_input", "dead_code"]
        assert gate.verifiers == ["gdb", "valgrind"]

    def test_evidence_gate_empty_lists(self) -> None:
        """CategoryEvidenceGate allows empty lists."""
        gate = CategoryEvidenceGate(
            required=[],
            reject_if=[],
            verifiers=[],
        )
        assert gate.required == []
        assert gate.reject_if == []
        assert gate.verifiers == []


class TestValidationProfile:
    """Tests for the ValidationProfile model."""

    def test_validation_profile_defaults(self) -> None:
        """ValidationProfile has correct defaults."""
        profile = ValidationProfile()
        assert profile.excluded_paths == []
        assert profile.attacker_roles == {}
        assert profile.trust_boundaries == {}
        assert profile.evidence_gates == {}
        assert profile.enabled_verifiers == []
        assert profile.default_verdict == "not_actionable"
        assert profile.require_shipped_reachability is True

    def test_validation_profile_full_creation(self) -> None:
        """ValidationProfile can be created with all fields."""
        remote_attacker = AttackerRole(
            can_control=["http_body"],
            cannot_control=["env_vars"],
        )
        network_boundary = TrustBoundary(
            untrusted_side=["client"],
            trusted_side=["server"],
        )
        sqli_gate = CategoryEvidenceGate(
            required=["source_identified", "sink_identified"],
            verifiers=["sqlmap"],
        )

        profile = ValidationProfile(
            excluded_paths=["vendor/", "node_modules/", "*.test.js"],
            attacker_roles={"remote_network": remote_attacker},
            trust_boundaries={"network_edge": network_boundary},
            evidence_gates={"sql_injection": sqli_gate},
            enabled_verifiers=["gdb", "sqlmap"],
            default_verdict="needs_review",
            require_shipped_reachability=False,
        )

        assert profile.excluded_paths == ["vendor/", "node_modules/", "*.test.js"]
        assert "remote_network" in profile.attacker_roles
        assert profile.attacker_roles["remote_network"].can_control == ["http_body"]
        assert "network_edge" in profile.trust_boundaries
        assert profile.trust_boundaries["network_edge"].trusted_side == ["server"]
        assert "sql_injection" in profile.evidence_gates
        assert profile.evidence_gates["sql_injection"].verifiers == ["sqlmap"]
        assert profile.enabled_verifiers == ["gdb", "sqlmap"]
        assert profile.default_verdict == "needs_review"
        assert profile.require_shipped_reachability is False

    def test_validation_profile_multiple_roles(self) -> None:
        """ValidationProfile supports multiple attacker roles."""
        profile = ValidationProfile(
            attacker_roles={
                "remote_unauthenticated": AttackerRole(
                    can_control=["http_request"],
                    cannot_control=["session", "auth_tokens"],
                ),
                "remote_authenticated": AttackerRole(
                    can_control=["http_request", "user_input"],
                    cannot_control=["admin_endpoints"],
                    inherits="remote_unauthenticated",
                ),
                "local_user": AttackerRole(
                    can_control=["filesystem", "env_vars"],
                    cannot_control=["kernel_memory"],
                    trust_boundary="process_boundary",
                ),
            }
        )
        assert len(profile.attacker_roles) == 3
        assert profile.attacker_roles["remote_authenticated"].inherits == "remote_unauthenticated"
        assert profile.attacker_roles["local_user"].trust_boundary == "process_boundary"

    def test_validation_profile_multiple_boundaries(self) -> None:
        """ValidationProfile supports multiple trust boundaries."""
        profile = ValidationProfile(
            trust_boundaries={
                "network_edge": TrustBoundary(
                    untrusted_side=["internet"],
                    trusted_side=["dmz"],
                    description="External network boundary",
                ),
                "dmz_to_internal": TrustBoundary(
                    untrusted_side=["dmz"],
                    trusted_side=["internal_network"],
                    description="DMZ to internal network boundary",
                ),
            }
        )
        assert len(profile.trust_boundaries) == 2
        assert profile.trust_boundaries["network_edge"].description == "External network boundary"

    def test_validation_profile_multiple_evidence_gates(self) -> None:
        """ValidationProfile supports multiple evidence gates per category."""
        profile = ValidationProfile(
            evidence_gates={
                "sql_injection": CategoryEvidenceGate(
                    required=["source_identified", "sink_identified", "dataflow_chain"],
                    verifiers=["sqlmap"],
                ),
                "xss": CategoryEvidenceGate(
                    required=["source_identified", "sink_identified"],
                    reject_if=["output_encoded"],
                ),
                "rce": CategoryEvidenceGate(
                    required=["source_identified", "sink_identified", "dataflow_chain", "security_impact"],
                    verifiers=["gdb"],
                ),
            }
        )
        assert len(profile.evidence_gates) == 3
        assert "sqlmap" in profile.evidence_gates["sql_injection"].verifiers
        assert "output_encoded" in profile.evidence_gates["xss"].reject_if


class TestSerializationRoundtrip:
    """Tests for JSON serialization and deserialization."""

    def test_attacker_role_roundtrip(self) -> None:
        """AttackerRole survives JSON roundtrip."""
        role = AttackerRole(
            can_control=["a", "b"],
            cannot_control=["c"],
            inherits="base",
            trust_boundary="edge",
            exceptions={"c": "when_x"},
        )
        json_data = role.model_dump()
        restored = AttackerRole.model_validate(json_data)
        assert restored == role

    def test_trust_boundary_roundtrip(self) -> None:
        """TrustBoundary survives JSON roundtrip."""
        boundary = TrustBoundary(
            untrusted_side=["a"],
            trusted_side=["b"],
            description="test",
        )
        json_data = boundary.model_dump()
        restored = TrustBoundary.model_validate(json_data)
        assert restored == boundary

    def test_validation_profile_roundtrip(self) -> None:
        """ValidationProfile survives JSON roundtrip."""
        profile = ValidationProfile(
            excluded_paths=["vendor/"],
            attacker_roles={
                "remote": AttackerRole(
                    can_control=["http"],
                    cannot_control=["db"],
                )
            },
            trust_boundaries={
                "network": TrustBoundary(
                    untrusted_side=["client"],
                    trusted_side=["server"],
                )
            },
            evidence_gates={
                "sqli": CategoryEvidenceGate(
                    verifiers=["sqlmap"],
                )
            },
            enabled_verifiers=["gdb"],
            default_verdict="reject",
            require_shipped_reachability=False,
        )
        json_data = profile.model_dump()
        restored = ValidationProfile.model_validate(json_data)
        assert restored == profile
