"""Integration tests for the full Foundation-to-Verification pipeline.

Tests the complete flow:
1. Foundation Phase builds context
2. Hunters output signals with Foundation Context
3. Decider routes signals to families
4. Specialists analyze signals
5. Arbiter resolves disagreements
6. Triager makes final classification
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime

from agents.deep_audit.foundation import (
    FoundationContext,
    RepoProfile,
    ScopeMap,
    ThreatModel,
    TrustBoundary,
    AttackerCapability,
    SuspiciousSignal,
    SignalCategory,
    SignalSeverity,
)
from agents.deep_audit.state import (
    CampaignState,
    CampaignPhase,
    SignalStatus,
    SignalState,
)
from agents.deep_audit.specialists.registry import (
    SpecialistFamily,
    get_family_for_signal,
    get_specialists_for_signal,
)
from agents.deep_audit.dispatcher import (
    WaveDispatcher,
    WavePlan,
    DispatchTask,
    WaveResult,
    SubagentResult,
)
from agents.deep_audit.filesystem import MemoriesFilesystem


class TestFoundationPhase:
    """Test Foundation Phase builds complete context."""

    def test_foundation_context_built_from_all_sources(self):
        """Foundation Context combines RepoProfiler, ScopeMapper, ThreatModeler outputs."""
        context = FoundationContext(
            repo_profile=RepoProfile(
                languages=["Python", "JavaScript"],
                frameworks=["FastAPI", "React"],
                build_system="pip",
                entry_point_files=["main.py", "src/app.tsx"],
            ),
            scope_map=ScopeMap(
                security_critical=["auth/", "crypto/", "api/"],
                test_code=["tests/", "*_test.py"],
                vendor_code=["node_modules/", "vendor/"],
                generated_code=["dist/", "build/"],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[
                    TrustBoundary(name="internet", description="Public internet access"),
                    TrustBoundary(name="database", description="Internal database"),
                ],
                attacker_capabilities=[
                    AttackerCapability.NETWORK_ACCESS,
                    AttackerCapability.UNAUTHENTICATED,
                ],
                in_scope_paths=["src/", "api/"],
                out_of_scope_paths=["internal_tools/", "admin/"],
                out_of_scope_reasons={"internal_tools/": "VPN-only access"},
            ),
        )

        # Context should provide scope checking
        assert context.is_in_scope("src/handler.py") is True
        assert context.is_in_scope("tests/test_handler.py") is False
        assert context.is_in_scope("vendor/lib.py") is False

        # Context should serialize for prompt injection
        prompt_text = context.to_prompt_context()
        assert "Python" in prompt_text
        assert "FastAPI" in prompt_text
        assert "NETWORK_ACCESS" in prompt_text


class TestHuntingPhaseWithContext:
    """Test Hunters use Foundation Context for filtering."""

    def test_hunter_signal_includes_foundation_context(self):
        """Signals should reference Foundation Context for scope awareness."""
        signal = SuspiciousSignal(
            signal_id="sig-001",
            category=SignalCategory.SQL_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="src/api/users.py",
            line_start=42,
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
            why_suspicious="String interpolation in SQL query with user-controlled input",
            entry_point_trace=["POST /api/users", "create_user()", "cursor.execute()"],
            foundation_context_summary="In-scope API code, attacker has network access",
        )

        context = signal.to_specialist_context()
        assert "sig-001" in context
        assert "SQL_INJECTION" in context
        assert "String interpolation" in context


class TestSignalRouting:
    """Test signal routing through Decider → Family → Specialists."""

    def test_decider_routes_to_correct_family(self):
        """Decider routes signals to appropriate families."""
        # SQL injection → Injection family
        assert get_family_for_signal(SignalCategory.SQL_INJECTION) == SpecialistFamily.INJECTION

        # Buffer overflow → Memory Safety family
        assert get_family_for_signal(SignalCategory.BUFFER_OVERFLOW) == SpecialistFamily.MEMORY_SAFETY

        # SSRF → Web Edge Cases family
        assert get_family_for_signal(SignalCategory.SSRF) == SpecialistFamily.WEB_EDGE_CASES

        # IDOR → AuthZ/Business Logic family
        assert get_family_for_signal(SignalCategory.IDOR) == SpecialistFamily.AUTHZ_BUSINESS_LOGIC

    def test_family_coordinator_assigns_specialists(self):
        """Family Coordinator assigns appropriate specialists for signal category."""
        # SQL injection should get SQL injection specialist
        specialists = get_specialists_for_signal(SignalCategory.SQL_INJECTION)
        assert "sql_injection_auditor" in specialists

        # Command injection should get command injection specialist
        specialists = get_specialists_for_signal(SignalCategory.COMMAND_INJECTION)
        assert "command_injection_auditor" in specialists


class TestCampaignStateTransitions:
    """Test campaign state tracks phases and signals correctly."""

    @pytest.fixture
    def campaign_state(self):
        """Create a test campaign state."""
        return CampaignState(
            project_id="test-project",
            scan_tier="quick",
            deadline=datetime.utcnow().timestamp() + 3600,
        )

    def test_initial_phase_is_foundation(self, campaign_state):
        """Campaign starts in Foundation phase."""
        assert campaign_state.phase == CampaignPhase.FOUNDATION

    def test_phase_advances_to_hunting_after_foundation(self, campaign_state):
        """Phase advances to Hunting after Foundation Context is set."""
        # Can't advance without Foundation Context
        assert campaign_state.advance_to_hunting() is False
        assert campaign_state.phase == CampaignPhase.FOUNDATION

        # Set Foundation Context
        campaign_state.foundation_context = FoundationContext(
            repo_profile=RepoProfile(languages=[], frameworks=[], build_system="", entry_point_files=[]),
            scope_map=ScopeMap(security_critical=[], test_code=[], vendor_code=[], generated_code=[]),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[],
                in_scope_paths=[],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        # Now can advance
        assert campaign_state.advance_to_hunting() is True
        assert campaign_state.phase == CampaignPhase.HUNTING

    def test_signal_lifecycle_tracking(self, campaign_state):
        """Signals progress through lifecycle statuses."""
        signal = SuspiciousSignal(
            signal_id="test-sig-001",
            category=SignalCategory.XSS,
            severity=SignalSeverity.MEDIUM,
            file_path="src/web/render.py",
            line_start=100,
            code_snippet="return f'<div>{user_input}</div>'",
            why_suspicious="Unsanitized user input in HTML",
            entry_point_trace=["GET /page", "render()"],
        )

        # Add signal
        state = campaign_state.add_signal(signal)
        assert state.status == SignalStatus.NEW

        # Route to family
        campaign_state.assign_signal_to_family("test-sig-001", "browser_client")
        assert campaign_state.signals["test-sig-001"].status == SignalStatus.ROUTED
        assert campaign_state.signals["test-sig-001"].assigned_family == "browser_client"

        # Assign to specialists
        campaign_state.assign_signal_to_specialists("test-sig-001", ["xss_auditor"])
        assert campaign_state.signals["test-sig-001"].status == SignalStatus.ASSIGNED
        assert "xss_auditor" in campaign_state.signals["test-sig-001"].assigned_specialists


class TestArbiterDisagreementResolution:
    """Test Arbiter resolves specialist disagreements."""

    @pytest.fixture
    def mock_filesystem(self, tmp_path):
        """Create a mock filesystem."""
        mock_fs = MagicMock(spec=MemoriesFilesystem)
        mock_fs.project_id = "test-project"
        return mock_fs

    def test_disagreement_detection(self, mock_filesystem, tmp_path):
        """Dispatcher detects when specialists disagree."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
        )

        # No disagreement with single report
        reports_single = {"specialist_a": {"verdict": "vulnerable"}}
        assert dispatcher.detect_specialist_disagreement("sig-001", reports_single) is False

        # No disagreement when both agree
        reports_agree = {
            "specialist_a": {"verdict": "vulnerable"},
            "specialist_b": {"verdict": "exploitable"},
        }
        assert dispatcher.detect_specialist_disagreement("sig-001", reports_agree) is False

        # Disagreement when one says vulnerable, other says not
        reports_disagree = {
            "specialist_a": {"verdict": "vulnerable"},
            "specialist_b": {"verdict": "not_vulnerable"},
        }
        assert dispatcher.detect_specialist_disagreement("sig-001", reports_disagree) is True


class TestDevilsAdvocateChallenging:
    """Test Devil's Advocate challenges quick dismissals."""

    @pytest.fixture
    def mock_filesystem(self, tmp_path):
        """Create a mock filesystem."""
        mock_fs = MagicMock(spec=MemoriesFilesystem)
        mock_fs.project_id = "test-project"
        return mock_fs

    def test_should_challenge_high_severity_quick_dismissal(self, mock_filesystem, tmp_path):
        """High severity signals dismissed quickly should be challenged."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
        )

        # Quick analysis result (output isn't used by should_challenge_result)
        result = SubagentResult(
            task_id="test-task",
            agent_type="Specialist",
            status="completed",
            output_path="/memories/result.json",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        # High severity + quick analysis → should challenge
        should_challenge, challenge_type = dispatcher.should_challenge_result(
            result,
            analysis_time_seconds=5.0,  # Very quick
            signal_severity="CRITICAL",
        )

        assert should_challenge is True
        assert challenge_type == "quick_dismissal"

    def test_thorough_analysis_not_challenged(self, mock_filesystem, tmp_path):
        """Thorough analysis should not be challenged."""
        dispatcher = WaveDispatcher(
            repo_path=str(tmp_path),
            filesystem=mock_filesystem,
        )

        result = SubagentResult(
            task_id="test-task",
            agent_type="Specialist",
            status="completed",
            output_path="/memories/result.json",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        # Long analysis time → no challenge needed
        should_challenge, _ = dispatcher.should_challenge_result(
            result,
            analysis_time_seconds=120.0,  # 2 minutes of analysis
            signal_severity="MEDIUM",
        )

        assert should_challenge is False


class TestEndToEndPipeline:
    """Test complete pipeline flow."""

    def test_campaign_tracks_full_signal_lifecycle(self):
        """Campaign state tracks signal from discovery to triage."""
        state = CampaignState(
            project_id="e2e-test",
            scan_tier="medium",
            deadline=datetime.utcnow().timestamp() + 7200,
        )

        # Phase 1: Foundation
        assert state.is_phase(CampaignPhase.FOUNDATION)

        state.foundation_context = FoundationContext(
            repo_profile=RepoProfile(
                languages=["Go"],
                frameworks=["gin"],
                build_system="go",
                entry_point_files=["main.go"],
            ),
            scope_map=ScopeMap(
                security_critical=["api/", "auth/"],
                test_code=["*_test.go"],
                vendor_code=["vendor/"],
                generated_code=["pb/"],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS],
                in_scope_paths=["api/", "cmd/"],
                out_of_scope_paths=["internal/admin/"],
                out_of_scope_reasons={},
            ),
        )
        state.advance_to_hunting()

        # Phase 2: Hunting
        assert state.is_phase(CampaignPhase.HUNTING)

        # Hunter finds a signal
        signal = SuspiciousSignal(
            signal_id="go-sql-001",
            category=SignalCategory.SQL_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="api/users.go",
            line_start=55,
            code_snippet='db.Query("SELECT * FROM users WHERE id = " + userID)',
            why_suspicious="String concatenation in SQL query",
            entry_point_trace=["GET /api/users/:id", "GetUser()", "db.Query()"],
        )
        state.add_signal(signal)

        # Phase 3: Routing
        state.advance_to_routing()
        assert state.is_phase(CampaignPhase.ROUTING)

        state.assign_signal_to_family("go-sql-001", "injection")
        state.assign_signal_to_specialists("go-sql-001", ["sql_injection_auditor"])

        # Phase 4: Verification
        state.advance_to_verification()
        assert state.is_phase(CampaignPhase.VERIFICATION)

        # Specialist reports back
        state.signals["go-sql-001"].specialist_reports["sql_injection_auditor"] = {
            "verdict": "vulnerable",
            "confidence": 95,
            "reasoning": "User ID directly concatenated into SQL query without parameterization",
        }

        # Phase 5: Resolution
        state.advance_to_resolution()
        assert state.is_phase(CampaignPhase.RESOLUTION)

        # Final disposition
        state.signals["go-sql-001"].final_disposition = "VALID_SECURITY_ISSUE"
        state.update_signal_status("go-sql-001", SignalStatus.TRIAGED)

        # Verify end state
        final_signal = state.get_signal("go-sql-001")
        assert final_signal.status == SignalStatus.TRIAGED
        assert final_signal.final_disposition == "VALID_SECURITY_ISSUE"
        assert "sql_injection_auditor" in final_signal.specialist_reports
