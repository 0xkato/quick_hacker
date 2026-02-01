"""Validation profile presets for common use cases.

This module provides pre-configured ValidationProfile instances for common
security analysis scenarios. These presets can be used as starting points
and customized as needed.
"""

from copy import deepcopy
from typing import Optional

from models.validation_profile import (
    AttackerRole,
    CategoryEvidenceGate,
    TrustBoundary,
    ValidationProfile,
)


# Preset: large_c_codebase
# For large C/C++ codebases like Chromium, where memory safety and IPC are key concerns
_large_c_codebase = ValidationProfile(
    excluded_paths=[
        "tools/",
        "test/",
        "tests/",
        "testing/",
        "build/",
        "buildtools/",
        "third_party/",
        "infra/",
    ],
    attacker_roles={
        "remote_network": AttackerRole(
            can_control=["network_input", "http_request", "ipc_messages"],
            cannot_control=["cli_args", "env_vars", "local_files"],
        ),
        "sandboxed_process": AttackerRole(
            inherits="remote_network",
            can_control=["shared_memory", "mojo_messages"],
        ),
    },
    trust_boundaries={
        "process_sandbox": TrustBoundary(
            untrusted_side=["renderer_process", "gpu_process"],
            trusted_side=["browser_process", "network_service"],
            description="Chrome process sandbox boundary",
        ),
        "network_edge": TrustBoundary(
            untrusted_side=["external_network", "user_input"],
            trusted_side=["internal_processing"],
            description="Network input boundary",
        ),
    },
    evidence_gates={
        "memory_corruption": CategoryEvidenceGate(
            verifiers=["gdb"],
        ),
        "command_injection": CategoryEvidenceGate(),
    },
    enabled_verifiers=["gdb"],
)


# Preset: webapp
# For web applications where XSS and SQL injection are common concerns
_webapp = ValidationProfile(
    excluded_paths=[
        "test/",
        "tests/",
        "spec/",
        "fixtures/",
        "vendor/",
        "node_modules/",
    ],
    attacker_roles={
        "remote_web": AttackerRole(
            can_control=["http_request", "query_params", "form_data", "cookies"],
            cannot_control=["server_env", "database_config"],
        ),
        "authenticated_user": AttackerRole(
            inherits="remote_web",
            can_control=["session_data", "user_preferences"],
        ),
    },
    trust_boundaries={
        "auth_boundary": TrustBoundary(
            untrusted_side=["anonymous_user", "unauthenticated_request"],
            trusted_side=["authenticated_session", "authorized_user"],
            description="Authentication boundary",
        ),
        "server_boundary": TrustBoundary(
            untrusted_side=["client_request", "user_input"],
            trusted_side=["server_processing", "database"],
            description="Server-side boundary",
        ),
    },
    evidence_gates={
        "xss": CategoryEvidenceGate(
            required=[
                "source_identified",
                "sink_identified",
                "dataflow_chain",
                "shipped_reachability",
                "security_impact",
            ],
        ),
        "sqli": CategoryEvidenceGate(
            required=[
                "source_identified",
                "sink_identified",
                "dataflow_chain",
                "shipped_reachability",
                "security_impact",
            ],
        ),
    },
)


# Preset: strict
# Minimal profile with strict settings - use when you want conservative defaults
_strict = ValidationProfile(
    excluded_paths=[],
    attacker_roles={},
    trust_boundaries={},
    evidence_gates={},
    enabled_verifiers=[],
    default_verdict="not_actionable",
    require_shipped_reachability=True,
)


# Preset: blank
# Empty profile with all defaults - use as a base for custom profiles
_blank = ValidationProfile()


# Dictionary of all available presets
VALIDATION_PRESETS: dict[str, ValidationProfile] = {
    "large_c_codebase": _large_c_codebase,
    "webapp": _webapp,
    "strict": _strict,
    "blank": _blank,
}


def get_preset(name: str) -> Optional[ValidationProfile]:
    """Get a validation preset by name.

    Returns a deep copy of the preset to prevent accidental modification
    of the original preset definitions.

    Args:
        name: The name of the preset (case-sensitive).

    Returns:
        A deep copy of the ValidationProfile preset, or None if not found.

    Examples:
        >>> preset = get_preset("large_c_codebase")
        >>> preset.excluded_paths.append("custom/")  # Won't affect original
    """
    if name not in VALIDATION_PRESETS:
        return None
    return deepcopy(VALIDATION_PRESETS[name])
