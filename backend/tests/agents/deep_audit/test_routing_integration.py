# backend/tests/agents/deep_audit/test_routing_integration.py
"""Integration tests for signal routing flow."""
import pytest
from datetime import datetime

from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
    AttackerCapability,
    SuspiciousSignal,
    SignalCategory,
    SignalSeverity,
)
from agents.deep_audit.specialists.registry import (
    SpecialistFamily,
    SpecialistRegistry,
    get_family_for_signal,
    get_specialists_for_signal,
    CATEGORY_TO_FAMILY,
)
from agents.deep_audit.state import (
    SignalStatus,
    SignalState,
    CampaignState,
    CampaignPhase,
)


class TestDeciderRouting:
    """Test Decider agent routing logic."""

    def test_all_signal_categories_have_family_mapping(self):
        """Every SignalCategory maps to a SpecialistFamily."""
        for category in SignalCategory:
            family = get_family_for_signal(category)
            assert family is not None
            assert isinstance(family, SpecialistFamily)

    def test_injection_categories_route_to_injection_family(self):
        """All injection-type signals route to INJECTION family."""
        injection_categories = [
            SignalCategory.SQL_INJECTION,
            SignalCategory.NOSQL_INJECTION,
            SignalCategory.COMMAND_INJECTION,
            SignalCategory.TEMPLATE_INJECTION,
            SignalCategory.EXPRESSION_INJECTION,
            SignalCategory.LDAP_INJECTION,
            SignalCategory.XPATH_INJECTION,
            SignalCategory.CRLF_INJECTION,
            SignalCategory.LOG_INJECTION,
            SignalCategory.EMAIL_INJECTION,
        ]

        for category in injection_categories:
            assert get_family_for_signal(category) == SpecialistFamily.INJECTION

    def test_memory_safety_categories_route_correctly(self):
        """All memory safety signals route to MEMORY_SAFETY family."""
        memory_categories = [
            SignalCategory.BUFFER_OVERFLOW,
            SignalCategory.USE_AFTER_FREE,
            SignalCategory.DOUBLE_FREE,
            SignalCategory.UNINITIALIZED_MEMORY,
            SignalCategory.INTEGER_OVERFLOW,
            SignalCategory.FORMAT_STRING,
            SignalCategory.TYPE_CONFUSION,
            SignalCategory.UNSAFE_FFI,
        ]

        for category in memory_categories:
            assert get_family_for_signal(category) == SpecialistFamily.MEMORY_SAFETY

    def test_web_categories_route_correctly(self):
        """Web-related signals route to appropriate families."""
        # Web edge cases
        assert get_family_for_signal(SignalCategory.SSRF) == SpecialistFamily.WEB_EDGE_CASES
        assert get_family_for_signal(SignalCategory.REQUEST_SMUGGLING) == SpecialistFamily.WEB_EDGE_CASES
        assert get_family_for_signal(SignalCategory.CACHE_POISONING) == SpecialistFamily.WEB_EDGE_CASES

        # Browser/client
        assert get_family_for_signal(SignalCategory.XSS) == SpecialistFamily.BROWSER_CLIENT
        assert get_family_for_signal(SignalCategory.PROTOTYPE_POLLUTION) == SpecialistFamily.BROWSER_CLIENT
        assert get_family_for_signal(SignalCategory.CLICKJACKING) == SpecialistFamily.BROWSER_CLIENT


class TestFamilyCoordinatorRouting:
    """Test Family Coordinator specialist assignment."""

    def test_registry_has_64_specialists(self):
        """Registry contains exactly 64 specialists."""
        registry = SpecialistRegistry()
        assert len(registry.all_specialists) == 64

    def test_each_family_has_specialists(self):
        """Every family has at least one specialist."""
        registry = SpecialistRegistry()

        for family in SpecialistFamily:
            specialists = registry.get_by_family(family)
            assert len(specialists) >= 1, f"Family {family} has no specialists"

    def test_specialist_counts_per_family(self):
        """Each family has the expected number of specialists."""
        registry = SpecialistRegistry()

        expected_counts = {
            SpecialistFamily.MEMORY_SAFETY: 8,
            SpecialistFamily.INJECTION: 10,
            SpecialistFamily.WEB_EDGE_CASES: 4,
            SpecialistFamily.BROWSER_CLIENT: 4,
            SpecialistFamily.DESERIALIZATION_PARSING: 6,
            SpecialistFamily.FILE_SYSTEM: 4,
            SpecialistFamily.AUTHN_SESSION: 5,
            SpecialistFamily.AUTHZ_BUSINESS_LOGIC: 5,
            SpecialistFamily.CRYPTO_SECRETS: 4,
            SpecialistFamily.INFRASTRUCTURE: 4,
            SpecialistFamily.SUPPLY_CHAIN: 3,
            SpecialistFamily.CONCURRENCY: 2,
            SpecialistFamily.DATA_EXPOSURE: 2,
            SpecialistFamily.API_DESIGN: 3,
        }

        for family, expected in expected_counts.items():
            actual = len(registry.get_by_family(family))
            assert actual == expected, f"Family {family}: expected {expected}, got {actual}"

    def test_specialists_have_triggers(self):
        """Most specialists have trigger categories defined."""
        registry = SpecialistRegistry()

        specialists_with_triggers = 0
        for specialist in registry.all_specialists:
            if specialist.triggers:
                specialists_with_triggers += 1

        # At least 40 specialists should have explicit triggers
        assert specialists_with_triggers >= 40

    def test_signal_routes_to_correct_specialist(self):
        """Signals route to specialists that handle their category."""
        test_cases = [
            (SignalCategory.SQL_INJECTION, "sql_injection_auditor"),
            (SignalCategory.XSS, "xss_auditor"),
            (SignalCategory.SSRF, "ssrf_auditor"),
            (SignalCategory.PATH_TRAVERSAL, "path_traversal_auditor"),
            (SignalCategory.CSRF, "csrf_auditor"),
        ]

        for category, expected_specialist in test_cases:
            specialists = get_specialists_for_signal(category)
            assert expected_specialist in specialists, f"{category} should route to {expected_specialist}"


class TestEndToEndRouting:
    """Test complete signal routing flow."""

    @pytest.fixture
    def sample_foundation_context(self):
        """Create a sample Foundation Context."""
        return FoundationContext(
            repo_profile=RepoProfile(
                languages=["Python"],
                frameworks=["FastAPI"],
                build_system="pip",
                entry_point_files=["main.py"],
            ),
            scope_map=ScopeMap(
                security_critical=["api/", "auth/"],
                test_code=["tests/"],
                vendor_code=["vendor/"],
                generated_code=[],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS, AttackerCapability.UNAUTHENTICATED],
                in_scope_paths=["src/", "api/"],
                out_of_scope_paths=["internal/"],
                out_of_scope_reasons={"internal/": "Admin only"},
            ),
        )

    def test_sql_injection_signal_full_routing(self, sample_foundation_context):
        """SQL injection signal routes through complete pipeline."""
        # Create signal
        signal = SuspiciousSignal(
            signal_id="sql-001",
            category=SignalCategory.SQL_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="api/users.py",
            line_start=45,
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            why_suspicious="String interpolation in SQL query",
            entry_point_trace=["POST /api/users", "get_user()", "execute()"],
        )

        # Step 1: Decider routes to family
        family = get_family_for_signal(signal.category)
        assert family == SpecialistFamily.INJECTION

        # Step 2: Family Coordinator assigns specialists
        specialists = get_specialists_for_signal(signal.category)
        assert "sql_injection_auditor" in specialists

        # Step 3: Create signal state and track
        state = SignalState(signal=signal)
        state.assigned_family = family.value
        state.assigned_specialists = specialists
        state.status = SignalStatus.ASSIGNED

        assert state.assigned_family == "injection"
        assert "sql_injection_auditor" in state.assigned_specialists

    def test_multiple_signals_route_independently(self, sample_foundation_context):
        """Multiple signals route independently to their specialists."""
        signals = [
            SuspiciousSignal(
                signal_id="sig-001",
                category=SignalCategory.SQL_INJECTION,
                severity=SignalSeverity.HIGH,
                file_path="api/db.py",
                line_start=10,
                code_snippet="query = f'SELECT {col}'",
                why_suspicious="SQL interpolation",
                entry_point_trace=["GET /data"],
            ),
            SuspiciousSignal(
                signal_id="sig-002",
                category=SignalCategory.XSS,
                severity=SignalSeverity.MEDIUM,
                file_path="api/render.py",
                line_start=20,
                code_snippet="return f'<div>{user_input}</div>'",
                why_suspicious="Unescaped output",
                entry_point_trace=["GET /page"],
            ),
            SuspiciousSignal(
                signal_id="sig-003",
                category=SignalCategory.COMMAND_INJECTION,
                severity=SignalSeverity.CRITICAL,
                file_path="api/exec.py",
                line_start=30,
                code_snippet="os.system(cmd)",
                why_suspicious="User input to system",
                entry_point_trace=["POST /run"],
            ),
        ]

        routed = []
        for signal in signals:
            family = get_family_for_signal(signal.category)
            specialists = get_specialists_for_signal(signal.category)
            routed.append({
                "signal_id": signal.signal_id,
                "family": family,
                "specialists": specialists,
            })

        # Verify independent routing
        assert routed[0]["family"] == SpecialistFamily.INJECTION
        assert routed[1]["family"] == SpecialistFamily.BROWSER_CLIENT
        assert routed[2]["family"] == SpecialistFamily.INJECTION

        assert "sql_injection_auditor" in routed[0]["specialists"]
        assert "xss_auditor" in routed[1]["specialists"]
        assert "command_injection_auditor" in routed[2]["specialists"]

    def test_signal_in_scope_filtering(self, sample_foundation_context):
        """Signals are filtered by Foundation Context scope."""
        context = sample_foundation_context

        # In-scope signal
        in_scope_path = "api/users.py"
        assert context.is_in_scope(in_scope_path)

        # Out-of-scope signals
        assert not context.is_in_scope("tests/test_users.py")  # Test code
        assert not context.is_in_scope("vendor/lib.py")  # Vendor
        assert not context.is_in_scope("internal/admin.py")  # Explicitly out of scope

    def test_campaign_tracks_multiple_signals(self, sample_foundation_context):
        """Campaign state can track multiple signals through pipeline."""
        campaign = CampaignState(
            project_id="test",
            scan_tier="medium",
            deadline=datetime.utcnow().timestamp() + 3600,
            foundation_context=sample_foundation_context,
            phase=CampaignPhase.ROUTING,
        )

        # Add multiple signals
        for i in range(5):
            signal = SuspiciousSignal(
                signal_id=f"sig-{i:03d}",
                category=SignalCategory.SQL_INJECTION,
                severity=SignalSeverity.MEDIUM,
                file_path=f"api/handler_{i}.py",
                line_start=i * 10,
                code_snippet="query = ...",
                why_suspicious="Test signal",
                entry_point_trace=[f"GET /api/{i}"],
            )
            campaign.signals[signal.signal_id] = SignalState(signal=signal)

        assert len(campaign.signals) == 5

        # Route all signals
        for signal_id, signal_state in campaign.signals.items():
            family = get_family_for_signal(signal_state.signal.category)
            signal_state.assigned_family = family.value
            signal_state.status = SignalStatus.ROUTED

        # Verify all routed
        for signal_state in campaign.signals.values():
            assert signal_state.status == SignalStatus.ROUTED
            assert signal_state.assigned_family == "injection"


class TestSpecialistDispatch:
    """Test specialist dispatch mechanics."""

    def test_specialist_info_has_proficiency(self):
        """All specialists have proficiency descriptions."""
        registry = SpecialistRegistry()

        for specialist in registry.all_specialists:
            assert specialist.proficiency, f"Specialist {specialist.id} missing proficiency"
            assert len(specialist.proficiency) > 10, f"Specialist {specialist.id} proficiency too short"

    def test_specialist_lookup_by_id(self):
        """Specialists can be looked up by ID."""
        registry = SpecialistRegistry()

        specialist = registry.get_by_id("sql_injection_auditor")
        assert specialist is not None
        assert specialist.name == "SQL Injection Auditor"
        assert specialist.family == SpecialistFamily.INJECTION

    def test_unknown_specialist_returns_none(self):
        """Unknown specialist ID returns None."""
        registry = SpecialistRegistry()

        specialist = registry.get_by_id("nonexistent_auditor")
        assert specialist is None

    def test_signal_context_generation(self):
        """Signals can generate specialist context."""
        signal = SuspiciousSignal(
            signal_id="sig-001",
            category=SignalCategory.SQL_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="api/db.py",
            line_start=45,
            code_snippet="cursor.execute(query)",
            why_suspicious="Dynamic SQL",
            entry_point_trace=["POST /api", "handler()", "execute()"],
            sink_function="cursor.execute",
            hunter_notes="Check parameterization",
        )

        context = signal.to_specialist_context()

        assert "sig-001" in context
        assert "SQL_INJECTION" in context
        assert "api/db.py:45" in context
        assert "cursor.execute" in context
        assert "Dynamic SQL" in context
        assert "POST /api" in context
