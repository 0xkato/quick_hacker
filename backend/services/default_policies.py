"""Default VRP triage policies."""
from models.schemas import (
    TriagePolicy,
    PathClassificationConfig,
    EvidenceGates,
    CommandInjectionGate,
    IntegerOverflowGate,
    MemoryCorruptionGate,
    DosGate,
)


# VRP Google OSS Strict Policy
# Designed for public bug bounty programs with high signal-to-noise requirements
VRP_GOOGLE_OSS_STRICT = TriagePolicy(
    name="vrp-google-oss-strict",

    # Path classification: pragmatic defaults for common project structures
    path_classification=PathClassificationConfig(
        runtime_roots=["src/", "app/", "backend/", "frontend/", "lib/", "libs/"],
        tooling_roots=["tools/", "scripts/", "examples/", "samples/"],
        third_party_roots=[
            "third_party/", "vendor/", "node_modules/",
            ".venv/", "site-packages/", "dist/", "build/",
            "target/", "out/"
        ],
        test_roots=["test/", "tests/", "__tests__/"],
        ci_roots=[".github/", ".gitlab/", "ci/"],
        docs_roots=["docs/", "documentation/"],
        migration_roots=["migrations/", "migrate/"]
    ),

    # Path filtering: exclude test/tools/third_party/ci/docs/migrations
    filter_third_party=True,
    filter_tests=True,
    filter_ci=True,
    filter_docs=True,
    filter_migrations=True,

    # Tooling findings require stronger boundary (CI/automated context)
    tooling_requires_ci_boundary=True,

    # Evidence gates with strict requirements
    evidence_gates=EvidenceGates(
        command_injection=CommandInjectionGate(
            require_shell_execution=True,  # Must use shell=True or os.system
            require_attacker_controls_shell_string=True,  # Not just arguments
            credible_boundaries=["network", "ci_artifact", "repo_checkout", "file_input"]
        ),
        integer_overflow=IntegerOverflowGate(
            require_attacker_controlled_operands=True,  # Attacker controls operands
            require_overflow_prone_operation=True,  # Multiplication or unchecked addition
            require_allocation_or_bounds_use=True,  # malloc, array index, buffer size
            require_proven_mismatch=True  # 32-bit calc -> 64-bit size, etc.
        ),
        memory_corruption=MemoryCorruptionGate(
            require_asan_trace=False,  # Prefer but don't require
            require_release_config=True,  # Must trigger in NDEBUG/release
            require_untrusted_input_path=True
        ),
        dos=DosGate(
            require_service_boundary=True  # Network service, not local script
        )
    ),

    # Output filtering: only report VALID and BUG dispositions
    report_hardening=False,
    report_by_design=False
)
