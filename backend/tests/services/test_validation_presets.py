"""Tests for validation profile presets."""

import pytest
from copy import deepcopy

from models.validation_profile import ValidationProfile, AttackerRole, TrustBoundary, CategoryEvidenceGate
from services.validation.presets import VALIDATION_PRESETS, get_preset


class TestValidationPresets:
    """Tests for VALIDATION_PRESETS dictionary."""

    def test_presets_exist(self):
        """All required presets should exist."""
        assert "large_c_codebase" in VALIDATION_PRESETS
        assert "webapp" in VALIDATION_PRESETS
        assert "strict" in VALIDATION_PRESETS
        assert "blank" in VALIDATION_PRESETS

    def test_presets_are_validation_profiles(self):
        """All presets should be ValidationProfile instances."""
        for name, preset in VALIDATION_PRESETS.items():
            assert isinstance(preset, ValidationProfile), f"{name} should be a ValidationProfile"


class TestLargeCCodebasePreset:
    """Tests for the large_c_codebase preset."""

    @pytest.fixture
    def preset(self):
        """Get the large_c_codebase preset."""
        return VALIDATION_PRESETS["large_c_codebase"]

    def test_excluded_paths(self, preset):
        """Should have correct excluded paths."""
        expected_paths = [
            "tools/",
            "test/",
            "tests/",
            "testing/",
            "build/",
            "buildtools/",
            "third_party/",
            "infra/",
        ]
        assert preset.excluded_paths == expected_paths

    def test_attacker_roles_exist(self, preset):
        """Should have remote_network and sandboxed_process attacker roles."""
        assert "remote_network" in preset.attacker_roles
        assert "sandboxed_process" in preset.attacker_roles

    def test_remote_network_role(self, preset):
        """remote_network role should have correct capabilities."""
        role = preset.attacker_roles["remote_network"]
        assert isinstance(role, AttackerRole)

        # can_control
        assert "network_input" in role.can_control
        assert "http_request" in role.can_control
        assert "ipc_messages" in role.can_control

        # cannot_control
        assert "cli_args" in role.cannot_control
        assert "env_vars" in role.cannot_control
        assert "local_files" in role.cannot_control

    def test_sandboxed_process_role(self, preset):
        """sandboxed_process role should inherit from remote_network and add capabilities."""
        role = preset.attacker_roles["sandboxed_process"]
        assert isinstance(role, AttackerRole)

        # inherits
        assert role.inherits == "remote_network"

        # additional can_control
        assert "shared_memory" in role.can_control
        assert "mojo_messages" in role.can_control

    def test_trust_boundaries(self, preset):
        """Should have process_sandbox and network_edge trust boundaries."""
        assert "process_sandbox" in preset.trust_boundaries
        assert "network_edge" in preset.trust_boundaries

        for name, boundary in preset.trust_boundaries.items():
            assert isinstance(boundary, TrustBoundary), f"{name} should be a TrustBoundary"

    def test_evidence_gates(self, preset):
        """Should have memory_corruption and command_injection evidence gates."""
        assert "memory_corruption" in preset.evidence_gates
        assert "command_injection" in preset.evidence_gates

        # memory_corruption should have gdb verifier
        memory_gate = preset.evidence_gates["memory_corruption"]
        assert isinstance(memory_gate, CategoryEvidenceGate)
        assert "gdb" in memory_gate.verifiers

    def test_enabled_verifiers(self, preset):
        """Should have gdb enabled."""
        assert "gdb" in preset.enabled_verifiers


class TestWebappPreset:
    """Tests for the webapp preset."""

    @pytest.fixture
    def preset(self):
        """Get the webapp preset."""
        return VALIDATION_PRESETS["webapp"]

    def test_excluded_paths(self, preset):
        """Should have correct excluded paths."""
        expected_paths = [
            "test/",
            "tests/",
            "spec/",
            "fixtures/",
            "vendor/",
            "node_modules/",
        ]
        assert preset.excluded_paths == expected_paths

    def test_attacker_roles(self, preset):
        """Should have remote_web and authenticated_user attacker roles."""
        assert "remote_web" in preset.attacker_roles
        assert "authenticated_user" in preset.attacker_roles

        for name, role in preset.attacker_roles.items():
            assert isinstance(role, AttackerRole), f"{name} should be an AttackerRole"

    def test_trust_boundaries(self, preset):
        """Should have auth_boundary and server_boundary trust boundaries."""
        assert "auth_boundary" in preset.trust_boundaries
        assert "server_boundary" in preset.trust_boundaries

    def test_evidence_gates(self, preset):
        """Should have xss and sqli evidence gates."""
        assert "xss" in preset.evidence_gates
        assert "sqli" in preset.evidence_gates


class TestStrictPreset:
    """Tests for the strict preset."""

    @pytest.fixture
    def preset(self):
        """Get the strict preset."""
        return VALIDATION_PRESETS["strict"]

    def test_default_verdict(self, preset):
        """Should have default_verdict='not_actionable'."""
        assert preset.default_verdict == "not_actionable"

    def test_require_shipped_reachability(self, preset):
        """Should have require_shipped_reachability=True."""
        assert preset.require_shipped_reachability is True

    def test_empty_collections(self, preset):
        """Should have empty collections (except defaults)."""
        # The strict preset is intentionally minimal
        assert preset.excluded_paths == []
        assert preset.attacker_roles == {}
        assert preset.trust_boundaries == {}
        assert preset.evidence_gates == {}
        assert preset.enabled_verifiers == []


class TestBlankPreset:
    """Tests for the blank preset."""

    @pytest.fixture
    def preset(self):
        """Get the blank preset."""
        return VALIDATION_PRESETS["blank"]

    def test_is_empty_validation_profile(self, preset):
        """Should be an empty ValidationProfile with all defaults."""
        # Compare against a fresh ValidationProfile()
        default = ValidationProfile()
        assert preset.excluded_paths == default.excluded_paths
        assert preset.attacker_roles == default.attacker_roles
        assert preset.trust_boundaries == default.trust_boundaries
        assert preset.evidence_gates == default.evidence_gates
        assert preset.enabled_verifiers == default.enabled_verifiers
        assert preset.default_verdict == default.default_verdict
        assert preset.require_shipped_reachability == default.require_shipped_reachability


class TestGetPreset:
    """Tests for the get_preset function."""

    def test_returns_preset_by_name(self):
        """Should return the correct preset by name."""
        preset = get_preset("large_c_codebase")
        assert preset is not None
        assert isinstance(preset, ValidationProfile)
        assert preset.excluded_paths == VALIDATION_PRESETS["large_c_codebase"].excluded_paths

    def test_returns_none_for_unknown_preset(self):
        """Should return None for unknown preset names."""
        assert get_preset("nonexistent") is None
        assert get_preset("") is None
        assert get_preset("LARGE_C_CODEBASE") is None  # Case-sensitive

    def test_returns_deep_copy(self):
        """Should return a deep copy, not the original."""
        preset1 = get_preset("large_c_codebase")
        preset2 = get_preset("large_c_codebase")

        # Should be equal but not the same object
        assert preset1 == preset2
        assert preset1 is not preset2

        # Modifying one should not affect the other
        preset1.excluded_paths.append("modified/")
        assert "modified/" not in preset2.excluded_paths

        # Should not affect the original either
        assert "modified/" not in VALIDATION_PRESETS["large_c_codebase"].excluded_paths

    def test_deep_copy_includes_nested_objects(self):
        """Deep copy should include nested objects like attacker roles."""
        preset = get_preset("large_c_codebase")

        # Modify nested object
        preset.attacker_roles["remote_network"].can_control.append("modified_input")

        # Original should not be affected
        original = VALIDATION_PRESETS["large_c_codebase"]
        assert "modified_input" not in original.attacker_roles["remote_network"].can_control
