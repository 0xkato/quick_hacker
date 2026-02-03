# backend/tests/agents/deep_audit/test_foundation.py
import pytest
from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
    TrustBoundary,
    AttackerCapability,
)


class TestFoundationContext:
    def test_foundation_context_creation(self):
        """Foundation context can be created with all components."""
        repo_profile = RepoProfile(
            languages=["C++", "Python"],
            frameworks=["gRPC"],
            build_system="Bazel",
            entry_point_files=["src/main.cc"],
        )
        scope_map = ScopeMap(
            security_critical=["crypto/", "auth/"],
            test_code=["test/", "*_test.cc"],
            vendor_code=["third_party/"],
            generated_code=["build/gen/"],
        )
        threat_model = ThreatModel(
            trust_boundaries=[
                TrustBoundary(name="network", description="External network access")
            ],
            attacker_capabilities=[
                AttackerCapability.NETWORK_ACCESS,
                AttackerCapability.UNAUTHENTICATED,
            ],
            in_scope_paths=["src/", "api/"],
            out_of_scope_paths=["internal_tools/"],
            out_of_scope_reasons={"internal_tools/": "Admin-only, requires VPN"},
        )

        context = FoundationContext(
            repo_profile=repo_profile,
            scope_map=scope_map,
            threat_model=threat_model,
        )

        assert context.repo_profile.languages == ["C++", "Python"]
        assert "crypto/" in context.scope_map.security_critical
        assert AttackerCapability.NETWORK_ACCESS in context.threat_model.attacker_capabilities

    def test_foundation_context_to_prompt_injection(self):
        """Foundation context can be serialized for prompt injection."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=["Python"], frameworks=[], build_system="pip", entry_point_files=[]),
            scope_map=ScopeMap(security_critical=[], test_code=["tests/"], vendor_code=[], generated_code=[]),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS],
                in_scope_paths=["src/"],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        prompt_text = context.to_prompt_context()

        assert "Python" in prompt_text
        assert "tests/" in prompt_text
        assert "NETWORK_ACCESS" in prompt_text

    def test_is_path_in_scope(self):
        """Foundation context can determine if path is in scope."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=[], frameworks=[], build_system="", entry_point_files=[]),
            scope_map=ScopeMap(
                security_critical=["src/"],
                test_code=["tests/", "*_test.py"],
                vendor_code=["vendor/"],
                generated_code=[],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[],
                in_scope_paths=["src/", "api/"],
                out_of_scope_paths=["internal/"],
                out_of_scope_reasons={},
            ),
        )

        assert context.is_in_scope("src/handler.py") == True
        assert context.is_in_scope("tests/test_handler.py") == False  # Test code
        assert context.is_in_scope("vendor/lib.py") == False  # Vendor
        assert context.is_in_scope("internal/admin.py") == False  # Out of scope

    def test_is_security_critical(self):
        """Foundation context can determine if path is security-critical."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=[], frameworks=[], build_system="", entry_point_files=[]),
            scope_map=ScopeMap(
                security_critical=["crypto/", "auth/", "*_security.py"],
                test_code=[],
                vendor_code=[],
                generated_code=[],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[],
                in_scope_paths=[],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        assert context.is_security_critical("crypto/aes.py") == True
        assert context.is_security_critical("auth/login.py") == True
        assert context.is_security_critical("utils_security.py") == True
        assert context.is_security_critical("utils/helpers.py") == False

    def test_to_dict_and_from_dict_roundtrip(self):
        """Foundation context can be serialized and deserialized."""
        original = FoundationContext(
            repo_profile=RepoProfile(
                languages=["Python", "Go"],
                frameworks=["FastAPI"],
                build_system="pip",
                entry_point_files=["main.py"],
                total_files=100,
                total_lines=5000,
                metadata={"version": "1.0"},
            ),
            scope_map=ScopeMap(
                security_critical=["auth/"],
                test_code=["tests/"],
                vendor_code=["vendor/"],
                generated_code=["gen/"],
                module_purposes={"auth/": "Authentication logic"},
            ),
            threat_model=ThreatModel(
                trust_boundaries=[
                    TrustBoundary(name="api", description="API boundary", entry_points=["/api/"])
                ],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS, AttackerCapability.UNAUTHENTICATED],
                in_scope_paths=["src/"],
                out_of_scope_paths=["tools/"],
                out_of_scope_reasons={"tools/": "Internal tooling"},
                assumptions=["All users are untrusted"],
            ),
        )

        # Convert to dict and back
        data = original.to_dict()
        restored = FoundationContext.from_dict(data)

        # Verify all fields are preserved
        assert restored.repo_profile.languages == ["Python", "Go"]
        assert restored.repo_profile.frameworks == ["FastAPI"]
        assert restored.repo_profile.total_files == 100
        assert restored.repo_profile.metadata == {"version": "1.0"}
        assert restored.scope_map.security_critical == ["auth/"]
        assert restored.scope_map.module_purposes == {"auth/": "Authentication logic"}
        assert len(restored.threat_model.trust_boundaries) == 1
        assert restored.threat_model.trust_boundaries[0].name == "api"
        assert AttackerCapability.NETWORK_ACCESS in restored.threat_model.attacker_capabilities
        assert restored.threat_model.assumptions == ["All users are untrusted"]

    def test_glob_pattern_matching(self):
        """Foundation context correctly matches glob patterns."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=[], frameworks=[], build_system="", entry_point_files=[]),
            scope_map=ScopeMap(
                security_critical=[],
                test_code=["*_test.py", "test_*.py", "tests/**"],
                vendor_code=[],
                generated_code=[],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[],
                in_scope_paths=[],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        # Glob patterns should match
        assert context.is_in_scope("handler_test.py") == False
        assert context.is_in_scope("test_handler.py") == False
        # Non-matching paths should be in scope
        assert context.is_in_scope("handler.py") == True
        assert context.is_in_scope("src/main.py") == True

    def test_glob_pattern_matching_nested(self):
        """Foundation context matches glob patterns in nested directories."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=[], frameworks=[], build_system="", entry_point_files=[]),
            scope_map=ScopeMap(
                security_critical=[],
                test_code=["*_test.py", "test_*.py"],
                vendor_code=["vendor/"],
                generated_code=[],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[],
                in_scope_paths=[],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        # Glob patterns should match at any depth
        assert context.is_in_scope("src/handler_test.py") == False
        assert context.is_in_scope("src/test_handler.py") == False

        # Directory patterns should match at any depth
        assert context.is_in_scope("vendor/lib.py") == False
        assert context.is_in_scope("internal/vendor/lib.py") == False
