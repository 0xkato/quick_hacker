# backend/tests/agents/deep_audit/test_foundation_integration.py
"""Integration tests for Foundation phase."""
import pytest
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

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
from agents.deep_audit.dispatcher import (
    WaveDispatcher,
    WavePlan,
    DispatchTask,
)


class TestFoundationContextBuilding:
    """Test building FoundationContext from agent outputs."""

    def test_build_from_valid_json_outputs(self):
        """Foundation context can be built from valid JSON outputs."""
        repo_profile_json = {
            "languages": ["Python", "JavaScript"],
            "frameworks": ["FastAPI", "React"],
            "build_system": "pip",
            "entry_point_files": ["main.py"],
            "total_files": 100,
            "total_lines": 5000,
            "metadata": {"has_tests": True}
        }

        scope_map_json = {
            "security_critical": ["api/", "auth/"],
            "test_code": ["tests/"],
            "vendor_code": ["node_modules/"],
            "generated_code": ["dist/"],
            "module_purposes": {"api/": "REST API"}
        }

        threat_model_json = {
            "trust_boundaries": [
                {"name": "public", "description": "Public internet", "entry_points": ["api/public/"]}
            ],
            "attacker_capabilities": ["network_access", "unauthenticated"],
            "in_scope_paths": ["src/"],
            "out_of_scope_paths": ["internal/"],
            "out_of_scope_reasons": {"internal/": "Admin only"},
            "assumptions": ["Attacker has network access"]
        }

        context = FoundationContext.from_dict({
            "repo_profile": repo_profile_json,
            "scope_map": scope_map_json,
            "threat_model": threat_model_json,
        })

        assert context.repo_profile.languages == ["Python", "JavaScript"]
        assert "api/" in context.scope_map.security_critical
        assert AttackerCapability.NETWORK_ACCESS in context.threat_model.attacker_capabilities
        assert context.is_in_scope("src/handler.py")
        assert not context.is_in_scope("tests/test_handler.py")

    def test_foundation_context_prompt_injection(self):
        """Foundation context can be serialized for prompt injection."""
        context = FoundationContext(
            repo_profile=RepoProfile(
                languages=["Python"],
                frameworks=["FastAPI"],
                build_system="pip",
                entry_point_files=["main.py"],
            ),
            scope_map=ScopeMap(
                security_critical=["api/"],
                test_code=["tests/"],
                vendor_code=[],
                generated_code=[],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS],
                in_scope_paths=["src/"],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        prompt_text = context.to_prompt_context()

        # Should contain key information
        assert "Python" in prompt_text
        assert "FastAPI" in prompt_text
        assert "api/" in prompt_text
        assert "tests/" in prompt_text
        assert "network_access" in prompt_text.lower()

    def test_foundation_context_roundtrip(self):
        """Foundation context survives serialization roundtrip."""
        original = FoundationContext(
            repo_profile=RepoProfile(
                languages=["Go", "Python"],
                frameworks=["gRPC"],
                build_system="go mod",
                entry_point_files=["cmd/server/main.go"],
                total_files=500,
                total_lines=50000,
            ),
            scope_map=ScopeMap(
                security_critical=["internal/auth/", "pkg/crypto/"],
                test_code=["*_test.go"],
                vendor_code=["vendor/"],
                generated_code=["*.pb.go"],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[
                    TrustBoundary(name="grpc", description="gRPC endpoint", entry_points=["api/"])
                ],
                attacker_capabilities=[
                    AttackerCapability.NETWORK_ACCESS,
                    AttackerCapability.AUTHENTICATED_USER,
                ],
                in_scope_paths=["internal/", "pkg/"],
                out_of_scope_paths=["tools/"],
                out_of_scope_reasons={"tools/": "Development only"},
                assumptions=["mTLS required for all connections"],
            ),
        )

        # Serialize and deserialize
        data = original.to_dict()
        restored = FoundationContext.from_dict(data)

        assert restored.repo_profile.languages == original.repo_profile.languages
        assert restored.scope_map.security_critical == original.scope_map.security_critical
        assert len(restored.threat_model.trust_boundaries) == 1
        assert restored.threat_model.trust_boundaries[0].name == "grpc"


class TestCampaignStateWithFoundation:
    """Test CampaignState integration with Foundation Context."""

    def test_campaign_state_with_foundation_context(self):
        """Campaign state can store Foundation Context."""
        context = FoundationContext(
            repo_profile=RepoProfile(languages=["Python"], frameworks=[], build_system="pip", entry_point_files=[]),
            scope_map=ScopeMap(security_critical=[], test_code=[], vendor_code=[], generated_code=[]),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[],
                in_scope_paths=[],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        state = CampaignState(
            project_id="test-project",
            scan_tier="medium",
            deadline=datetime.utcnow().timestamp() + 3600,
            foundation_context=context,
            phase=CampaignPhase.FOUNDATION,
        )

        assert state.foundation_context is not None
        assert state.phase == CampaignPhase.FOUNDATION
        assert state.foundation_context.repo_profile.languages == ["Python"]

    def test_campaign_phase_transitions(self):
        """Campaign can transition through phases."""
        state = CampaignState(
            project_id="test",
            scan_tier="quick",
            deadline=datetime.utcnow().timestamp() + 3600,
        )

        assert state.phase == CampaignPhase.FOUNDATION

        state.phase = CampaignPhase.HUNTING
        assert state.phase == CampaignPhase.HUNTING

        state.phase = CampaignPhase.ROUTING
        assert state.phase == CampaignPhase.ROUTING

    def test_signal_state_tracking(self):
        """Campaign can track signals through the pipeline."""
        signal = SuspiciousSignal(
            signal_id="sig-001",
            category=SignalCategory.SQL_INJECTION,
            severity=SignalSeverity.HIGH,
            file_path="api/users.py",
            line_start=45,
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            why_suspicious="String interpolation in SQL query",
            entry_point_trace=["POST /api/users", "create_user()", "execute()"],
        )

        signal_state = SignalState(
            signal=signal,
            status=SignalStatus.NEW,
        )

        state = CampaignState(
            project_id="test",
            scan_tier="medium",
            deadline=datetime.utcnow().timestamp() + 3600,
        )
        state.signals["sig-001"] = signal_state

        # Update signal status
        state.signals["sig-001"].status = SignalStatus.ROUTED
        state.signals["sig-001"].assigned_family = "INJECTION"

        assert state.signals["sig-001"].status == SignalStatus.ROUTED
        assert state.signals["sig-001"].assigned_family == "INJECTION"


class TestDispatcherFoundationIntegration:
    """Test WaveDispatcher Foundation phase integration."""

    @pytest.fixture
    def mock_filesystem(self):
        """Create a mock filesystem."""
        fs = MagicMock()
        fs.project_id = "test-project"
        fs.read_file = AsyncMock()
        fs.write_file = AsyncMock()
        return fs

    def test_dispatcher_has_foundation_agent_types(self):
        """Dispatcher knows about Foundation phase agent types."""
        from agents.deep_audit.dispatcher import AGENT_TOOL_SUBSETS

        assert "RepoProfiler" in AGENT_TOOL_SUBSETS
        assert "ScopeMapper" in AGENT_TOOL_SUBSETS
        assert "ThreatModeler" in AGENT_TOOL_SUBSETS
        assert "Decider" in AGENT_TOOL_SUBSETS
        assert "FamilyCoordinator" in AGENT_TOOL_SUBSETS
        assert "Specialist" in AGENT_TOOL_SUBSETS
        assert "Arbiter" in AGENT_TOOL_SUBSETS

    def test_dispatcher_injects_foundation_context(self, mock_filesystem):
        """Dispatcher can inject Foundation Context into tasks."""
        dispatcher = WaveDispatcher(
            repo_path="/test/repo",
            filesystem=mock_filesystem,
        )

        context = FoundationContext(
            repo_profile=RepoProfile(languages=["Python"], frameworks=[], build_system="pip", entry_point_files=[]),
            scope_map=ScopeMap(security_critical=["api/"], test_code=[], vendor_code=[], generated_code=[]),
            threat_model=ThreatModel(
                trust_boundaries=[],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS],
                in_scope_paths=[],
                out_of_scope_paths=[],
                out_of_scope_reasons={},
            ),
        )

        task = DispatchTask(
            agent_type="SinkHunter",
            objective="Find sinks",
            scope="/test/repo/api",
            deliverable="/memories/sinks.json",
        )

        updated_task = dispatcher.inject_foundation_context(task, context)

        assert "FOUNDATION_CONTEXT" in updated_task.constraints
        assert "Python" in updated_task.constraints
        assert "api/" in updated_task.constraints

    def test_gas_town_prompt_embedding(self, mock_filesystem):
        """Gas Town: Foundation Context is embedded directly in system prompt.

        This verifies the Gas Town architecture fix where Foundation Context
        is prepended to the system prompt so subagents (which run as separate
        processes) receive the full context without needing to read files.
        """
        dispatcher = WaveDispatcher(
            repo_path="/test/repo",
            filesystem=mock_filesystem,
        )

        context = FoundationContext(
            repo_profile=RepoProfile(
                languages=["Python", "Go"],
                frameworks=["FastAPI", "gRPC"],
                build_system="pip",
                entry_point_files=["main.py"],
            ),
            scope_map=ScopeMap(
                security_critical=["api/auth/", "pkg/crypto/"],
                test_code=["tests/"],
                vendor_code=["vendor/"],
                generated_code=["*.pb.go"],
            ),
            threat_model=ThreatModel(
                trust_boundaries=[
                    TrustBoundary(name="public", description="Public API", entry_points=["api/"])
                ],
                attacker_capabilities=[AttackerCapability.NETWORK_ACCESS],
                in_scope_paths=["src/"],
                out_of_scope_paths=["internal/admin/"],
                out_of_scope_reasons={"internal/admin/": "Admin only"},
            ),
        )

        task = DispatchTask(
            agent_type="SinkHunter",
            objective="Find SQL injection sinks",
            scope="/test/repo/api",
            deliverable="/memories/sinks.json",
        )

        # Get the prompt WITH Foundation Context embedded
        prompt_with_context = dispatcher._get_subagent_prompt(task, context)

        # Verify Foundation Context is at the TOP of the prompt
        assert prompt_with_context.startswith("## Foundation Context (Pre-loaded)")

        # Verify all key Foundation Context elements are in the prompt
        assert "Python" in prompt_with_context
        assert "Go" in prompt_with_context
        assert "FastAPI" in prompt_with_context
        assert "api/auth/" in prompt_with_context
        assert "tests/" in prompt_with_context
        assert "NETWORK_ACCESS" in prompt_with_context

        # Verify the base prompt is also included AFTER the context
        # The separator "---" should appear between context and base prompt
        assert "---" in prompt_with_context

    def test_gas_town_no_context_fallback(self, mock_filesystem):
        """Without Foundation Context, prompt is just the base template."""
        dispatcher = WaveDispatcher(
            repo_path="/test/repo",
            filesystem=mock_filesystem,
        )

        task = DispatchTask(
            agent_type="RepoProfiler",
            objective="Profile the repository",
            scope="/test/repo",
            deliverable="/memories/repo_profile.json",
        )

        # Get prompt WITHOUT Foundation Context
        prompt_without_context = dispatcher._get_subagent_prompt(task, None)

        # Should NOT have Foundation Context header
        assert not prompt_without_context.startswith("## Foundation Context")

        # Should still have the base prompt content
        assert len(prompt_without_context) > 0


class TestSignalRouting:
    """Test signal routing through the pipeline."""

    def test_signal_category_to_family_mapping(self):
        """Signal categories map to correct specialist families."""
        from agents.deep_audit.specialists.registry import (
            get_family_for_signal,
            SpecialistFamily,
        )

        assert get_family_for_signal(SignalCategory.SQL_INJECTION) == SpecialistFamily.INJECTION
        assert get_family_for_signal(SignalCategory.BUFFER_OVERFLOW) == SpecialistFamily.MEMORY_SAFETY
        assert get_family_for_signal(SignalCategory.XSS) == SpecialistFamily.BROWSER_CLIENT
        assert get_family_for_signal(SignalCategory.SSRF) == SpecialistFamily.WEB_EDGE_CASES
        assert get_family_for_signal(SignalCategory.PATH_TRAVERSAL) == SpecialistFamily.FILE_SYSTEM

    def test_signal_to_specialists_lookup(self):
        """Signals can be routed to specific specialists."""
        from agents.deep_audit.specialists.registry import get_specialists_for_signal

        sql_specialists = get_specialists_for_signal(SignalCategory.SQL_INJECTION)
        assert "sql_injection_auditor" in sql_specialists

        xss_specialists = get_specialists_for_signal(SignalCategory.XSS)
        assert "xss_auditor" in xss_specialists

    def test_signal_state_lifecycle(self):
        """Signal state transitions through expected lifecycle."""
        signal = SuspiciousSignal(
            signal_id="sig-test",
            category=SignalCategory.COMMAND_INJECTION,
            severity=SignalSeverity.CRITICAL,
            file_path="api/exec.py",
            line_start=100,
            code_snippet="os.system(cmd)",
            why_suspicious="User input to os.system",
            entry_point_trace=["POST /run", "execute()"],
        )

        state = SignalState(signal=signal)
        assert state.status == SignalStatus.NEW

        # Route to family
        state.status = SignalStatus.ROUTED
        state.assigned_family = "INJECTION"
        assert state.status == SignalStatus.ROUTED

        # Assign to specialists
        state.status = SignalStatus.ASSIGNED
        state.assigned_specialists = ["command_injection_auditor"]
        assert state.status == SignalStatus.ASSIGNED

        # Specialist analyzes
        state.status = SignalStatus.ANALYZING

        # Specialist verifies
        state.status = SignalStatus.VERIFIED
        state.specialist_reports["command_injection_auditor"] = {
            "verdict": "VULNERABLE",
            "confidence": 95,
        }

        # Final triage
        state.status = SignalStatus.TRIAGED
        state.final_disposition = "VALID_SECURITY_ISSUE"

        assert state.final_disposition == "VALID_SECURITY_ISSUE"
