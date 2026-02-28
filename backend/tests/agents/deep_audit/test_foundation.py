# backend/tests/agents/deep_audit/test_foundation.py
import pytest
from agents.deep_audit.foundation import (
    FoundationContext,
    GuardInfo,
    RepoProfile,
    ScopeMap,
    ThreatModel,
    TrustBoundary,
    AttackerCapability,
    SuspiciousSignal,
    SignalCategory,
    SignalSeverity,
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


class TestSuspiciousSignal:
    def test_signal_creation(self):
        """Suspicious signal can be created with required fields."""
        signal = SuspiciousSignal(
            signal_id="sig-001",
            category=SignalCategory.COMMAND_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="src/api/execute.py",
            line_start=45,
            code_snippet="os.system(user_input)",
            why_suspicious="User-controlled string flows to os.system()",
            entry_point_trace=["POST /api/run", "handle_run()", "os.system()"],
        )

        assert signal.signal_id == "sig-001"
        assert signal.category == SignalCategory.COMMAND_INJECTION
        assert signal.severity == SignalSeverity.HIGH
        assert len(signal.entry_point_trace) == 3

    def test_signal_to_specialist_context(self):
        """Signal can be formatted for specialist consumption."""
        signal = SuspiciousSignal(
            signal_id="sig-001",
            category=SignalCategory.SQL_INJECTION,
            severity=SignalSeverity.CRITICAL,
            file_path="src/db/query.py",
            line_start=100,
            code_snippet="cursor.execute(f'SELECT * FROM {table}')",
            why_suspicious="String interpolation in SQL query",
            entry_point_trace=["GET /api/data", "get_data()", "execute()"],
        )

        context = signal.to_specialist_context()

        assert "sig-001" in context
        assert "SQL_INJECTION" in context
        assert "src/db/query.py:100" in context
        assert "String interpolation" in context


class TestGuardInfo:
    def test_from_dict_defaults_effectiveness_to_unknown(self):
        """GuardInfo.from_dict() must default effectiveness to 'unknown', not 'effective'."""
        guard = GuardInfo.from_dict({})
        assert guard.effectiveness == "unknown"

    def test_from_dict_preserves_explicit_effective(self):
        """GuardInfo.from_dict() preserves 'effective' when explicitly provided."""
        guard = GuardInfo.from_dict({"effectiveness": "effective"})
        assert guard.effectiveness == "effective"

    def test_from_dict_accepts_unknown_effectiveness(self):
        """GuardInfo.from_dict() accepts 'unknown' as a valid effectiveness value."""
        guard = GuardInfo.from_dict({"effectiveness": "unknown"})
        assert guard.effectiveness == "unknown"

    def test_from_dict_roundtrip(self):
        """GuardInfo.to_dict() -> from_dict() preserves all fields."""
        original = GuardInfo(
            file_path="src/auth.py",
            line_number=42,
            guard_type="authorization",
            code_snippet="if user.is_admin:",
            description="Admin check",
            effectiveness="partial",
            bypass_reason="Only checks role, not resource ownership",
        )
        restored = GuardInfo.from_dict(original.to_dict())
        assert restored.file_path == original.file_path
        assert restored.effectiveness == "partial"
        assert restored.bypass_reason == "Only checks role, not resource ownership"

    def test_validate_downgrades_effective_without_snippet(self):
        """A guard marked 'effective' without code_snippet is downgraded to 'unknown'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="",
            description="Validates input",
            effectiveness="effective",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"

    def test_validate_downgrades_effective_without_bypass_resistance(self):
        """A guard marked 'effective' without bypass_reason explanation is downgraded to 'unknown'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="if not re.match(r'^[a-z]+$', user_input):",
            description="Validates input is lowercase alpha",
            effectiveness="effective",
            bypass_reason="",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"

    def test_validate_keeps_effective_with_full_evidence(self):
        """A guard with code_snippet AND bypass_reason stays 'effective'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="if not re.match(r'^[a-z]+$', user_input): raise ValueError",
            description="Validates input is lowercase alpha only",
            effectiveness="effective",
            bypass_reason="Regex is anchored and restrictive; no bypass feasible",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "effective"

    def test_validate_keeps_partial_with_snippet(self):
        """A guard marked 'partial' with code_snippet stays 'partial'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="sanitization",
            code_snippet="html.escape(user_input)",
            description="HTML escapes user input",
            effectiveness="partial",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "partial"

    def test_validate_downgrades_partial_without_snippet(self):
        """A guard marked 'partial' without code_snippet is downgraded to 'unknown'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="sanitization",
            code_snippet="",
            description="Sanitizes input",
            effectiveness="partial",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"

    def test_validate_keeps_bypassable(self):
        """A guard marked 'bypassable' stays 'bypassable' (already weakest evaluated state)."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="",
            description="Validates input",
            effectiveness="bypassable",
            bypass_reason="Encoding bypass allows special chars",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "bypassable"

    def test_validate_keeps_unknown(self):
        """A guard already 'unknown' stays 'unknown'."""
        guard = GuardInfo(
            file_path="src/auth.py",
            line_number=10,
            guard_type="validation",
            code_snippet="",
            description="Validates input",
            effectiveness="unknown",
        )
        guard.validate_effectiveness()
        assert guard.effectiveness == "unknown"


class TestComputeTraceQuality:
    def _make_signal(self, trace_steps=None, guards=None):
        """Helper to build a SuspiciousSignal with specific trace data."""
        return SuspiciousSignal(
            signal_id="test-sig",
            category=SignalCategory.COMMAND_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="src/api/run.py",
            line_start=10,
            code_snippet="os.system(cmd)",
            why_suspicious="User input in command",
            entry_point_trace=["POST /run"],
            trace_steps=trace_steps or [],
            guards=guards or [],
        )

    def test_unknown_guards_get_no_credit(self):
        """Guards with 'unknown' effectiveness contribute 0 to trace quality."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "unknown"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.8)

    def test_effective_guards_get_credit(self):
        """Guards with 'effective' effectiveness get the +0.1 credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "effective"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.9)

    def test_partial_guards_get_credit(self):
        """Guards with 'partial' effectiveness get credit (they were evaluated)."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "partial"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.9)

    def test_bypassable_guards_get_credit(self):
        """Guards with 'bypassable' effectiveness get credit (they were evaluated)."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "bypassable", "bypass_reason": "encoding bypass"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.9)

    def test_no_guards_no_guard_credit(self):
        """Signals with no guards get 0 guard credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.8)

    def test_guard_without_snippet_gets_no_credit(self):
        """Guards without code_snippet get no credit, even if marked effective."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "", "effectiveness": "effective"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.8)

    def test_guard_with_none_effectiveness_gets_no_credit(self):
        """Guards with None effectiveness should not get credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": None},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.8)

    def test_guard_with_invalid_effectiveness_gets_no_credit(self):
        """Guards with invalid effectiveness values should not get credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "validate(x)", "effectiveness": "invalid"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(0.8)

    def test_mixed_guards_only_evaluated_get_credit(self):
        """Only guards with evaluated (non-unknown) effectiveness AND code snippets get credit."""
        signal = self._make_signal(
            trace_steps=[
                {"role": "source", "file_path": "a.py", "line_number": 1},
                {"role": "propagation", "file_path": "a.py", "line_number": 5},
                {"role": "sink", "file_path": "b.py", "line_number": 2},
            ],
            guards=[
                {"code_snippet": "check(x)", "effectiveness": "unknown"},
                {"code_snippet": "sanitize(x)", "effectiveness": "effective"},
            ],
        )
        quality = signal.compute_trace_quality()
        assert quality == pytest.approx(1.0)
