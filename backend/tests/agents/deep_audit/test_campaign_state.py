"""Tests for CampaignState model."""

import time
from datetime import datetime
import pytest
from agents.deep_audit.state import (
    CampaignState,
    Hypothesis,
    HypothesisStatus,
    ScopeStatus,
    ScopeDepth,
    Entrypoint,
    Dismissal,
    WaveRecord,
    WaveTask,
    Severity,
    Confidence,
)


class TestCampaignState:
    """Tests for CampaignState class."""

    def test_create_campaign_state(self):
        """Test basic creation of CampaignState."""
        state = CampaignState(
            project_id="test-project",
            scan_tier="quick",
            deadline=time.time() + 300,
        )

        assert state.project_id == "test-project"
        assert state.scan_tier == "quick"
        assert state.current_wave == 0
        assert state.hypotheses == []
        assert state.confirmed_findings == []
        assert state.dismissed == []
        assert state.scopes == {}
        assert state.entrypoints == []

    def test_time_remaining(self):
        """Test time_remaining calculation."""
        from datetime import datetime as dt

        # Create state with deadline 10 seconds from now using same timestamp source
        now = dt.utcnow().timestamp()
        deadline = now + 10
        state = CampaignState(
            project_id="test",
            scan_tier="quick",
            deadline=deadline,
        )

        remaining = state.time_remaining()
        # Should be approximately 10 seconds (allow for timing variance)
        assert 5 <= remaining <= 15  # Wide margin for timing variance

        # Test with expired deadline
        state.deadline = dt.utcnow().timestamp() - 10
        assert state.time_remaining() == 0

    def test_add_hypothesis(self):
        """Test adding hypotheses."""
        state = CampaignState(
            project_id="test",
            scan_tier="quick",
            deadline=time.time() + 300,
        )

        h1 = Hypothesis(
            id="h1",
            signal_type="sql_injection",
            location="services/user.py:45",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
        state.hypotheses.append(h1)

        assert len(state.hypotheses) == 1
        assert state.hypotheses[0].id == "h1"
        assert state.hypotheses[0].status == HypothesisStatus.NEW

    def test_get_pending_hypotheses(self):
        """Test filtering pending hypotheses."""
        state = CampaignState(
            project_id="test",
            scan_tier="quick",
            deadline=time.time() + 300,
        )

        # Add hypotheses with different statuses
        state.hypotheses = [
            Hypothesis(id="h1", signal_type="sqli", location="a.py:1", severity=Severity.HIGH, confidence=Confidence.HIGH, status=HypothesisStatus.NEW),
            Hypothesis(id="h2", signal_type="xss", location="b.py:2", severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, status=HypothesisStatus.TRIAGED),
            Hypothesis(id="h3", signal_type="ssrf", location="c.py:3", severity=Severity.HIGH, confidence=Confidence.HIGH, status=HypothesisStatus.CONFIRMED),
            Hypothesis(id="h4", signal_type="cmd", location="d.py:4", severity=Severity.CRITICAL, confidence=Confidence.MEDIUM, status=HypothesisStatus.DISMISSED),
            Hypothesis(id="h5", signal_type="path", location="e.py:5", severity=Severity.LOW, confidence=Confidence.LOW, status=HypothesisStatus.TRACING),
        ]

        pending = state.get_pending_hypotheses()

        # Should include NEW, TRIAGED, TRACING, AUDITING but not CONFIRMED or DISMISSED
        assert len(pending) == 3
        pending_ids = {h.id for h in pending}
        assert "h1" in pending_ids  # NEW
        assert "h2" in pending_ids  # TRIAGED
        assert "h5" in pending_ids  # TRACING
        assert "h3" not in pending_ids  # CONFIRMED
        assert "h4" not in pending_ids  # DISMISSED


class TestHypothesis:
    """Tests for Hypothesis model."""

    def test_hypothesis_defaults(self):
        """Test Hypothesis default values."""
        h = Hypothesis(
            id="test",
            signal_type="sql_injection",
            location="file.py:10",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )

        assert h.status == HypothesisStatus.NEW
        assert h.created_at is not None
        assert h.updated_at is not None
        assert h.evidence_paths == []

    def test_hypothesis_status_transition(self):
        """Test hypothesis status can be updated."""
        h = Hypothesis(
            id="test",
            signal_type="sql_injection",
            location="file.py:10",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )

        assert h.status == HypothesisStatus.NEW

        h.status = HypothesisStatus.TRIAGED
        assert h.status == HypothesisStatus.TRIAGED

        h.status = HypothesisStatus.TRACING
        assert h.status == HypothesisStatus.TRACING


class TestScopeStatus:
    """Tests for ScopeStatus model."""

    def test_scope_status_defaults(self):
        """Test ScopeStatus default values."""
        scope = ScopeStatus(
            scope_id="backend",
            path="/backend",
        )

        assert scope.depth == ScopeDepth.UNTOUCHED
        assert scope.summary_path is None
        assert scope.signals_path is None

    def test_scope_status_with_values(self):
        """Test ScopeStatus with explicit values."""
        scope = ScopeStatus(
            scope_id="api",
            path="/backend/api",
            depth=ScopeDepth.HUNTED,
            summary_path="/memories/scopes/api/summary.md",
        )

        assert scope.scope_id == "api"
        assert scope.path == "/backend/api"
        assert scope.depth == ScopeDepth.HUNTED


class TestEntrypoint:
    """Tests for Entrypoint model."""

    def test_entrypoint_creation(self):
        """Test Entrypoint creation."""
        ep = Entrypoint(
            id="ep1",
            type="http_route",
            path="/api/users",
            method="POST",
            handler="create_user",
            file_path="/backend/routers/users.py",
            line_number=45,
        )

        assert ep.id == "ep1"
        assert ep.type == "http_route"
        assert ep.path == "/api/users"
        assert ep.method == "POST"
        assert ep.parameters == []


class TestDismissal:
    """Tests for Dismissal model."""

    def test_dismissal_creation(self):
        """Test Dismissal creation."""
        d = Dismissal(
            hypothesis_id="h1",
            signal_type="sql_injection",
            location="file.py:10",
            reason="Parameterized query used",
        )

        assert d.hypothesis_id == "h1"
        assert d.reason == "Parameterized query used"
        assert d.dismissed_at is not None


class TestWaveRecord:
    """Tests for WaveRecord model."""

    def test_wave_record_creation(self):
        """Test WaveRecord creation."""
        wave = WaveRecord(
            wave_id=1,
            tasks=[
                WaveTask(task_id="t1", agent_type="RepoProfiler", objective="Map repo", scope="/", deliverable="/memories/repo_profile.json"),
                WaveTask(task_id="t2", agent_type="SinkHunter", objective="Find sinks", scope="/backend", deliverable="/memories/signals.json"),
            ],
            started_at=datetime.utcnow(),
            hypotheses_added=5,
            hypotheses_resolved=2,
        )

        assert wave.wave_id == 1
        assert len(wave.tasks) == 2
        assert wave.hypotheses_added == 5
        assert wave.hypotheses_resolved == 2
        assert wave.started_at is not None
        assert wave.completed_at is None

    def test_wave_record_completion(self):
        """Test marking wave as complete."""
        wave = WaveRecord(
            wave_id=1,
            tasks=[],
            started_at=datetime.utcnow(),
            hypotheses_added=0,
            hypotheses_resolved=0,
        )

        assert wave.completed_at is None

        wave.completed_at = datetime.utcnow()
        assert wave.completed_at is not None


class TestCampaignStateSerialization:
    """Tests for CampaignState serialization."""

    def test_model_dump(self):
        """Test CampaignState can be serialized."""
        state = CampaignState(
            project_id="test",
            scan_tier="quick",
            deadline=time.time() + 300,
        )

        state.hypotheses.append(
            Hypothesis(
                id="h1",
                signal_type="sqli",
                location="a.py:1",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
            )
        )

        data = state.model_dump()

        assert data["project_id"] == "test"
        assert data["scan_tier"] == "quick"
        assert len(data["hypotheses"]) == 1
        assert data["hypotheses"][0]["id"] == "h1"

    def test_model_round_trip(self):
        """Test CampaignState can be serialized and deserialized."""
        original = CampaignState(
            project_id="test",
            scan_tier="deep",
            deadline=time.time() + 1800,
        )

        original.hypotheses.append(
            Hypothesis(
                id="h1",
                signal_type="xss",
                location="template.html:5",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
            )
        )

        original.scopes["backend"] = ScopeStatus(
            scope_id="backend",
            path="/backend",
            depth=ScopeDepth.MAPPED,
        )

        # Serialize
        data = original.model_dump()

        # Deserialize
        restored = CampaignState(**data)

        assert restored.project_id == original.project_id
        assert restored.scan_tier == original.scan_tier
        assert len(restored.hypotheses) == 1
        assert restored.hypotheses[0].id == "h1"
        assert "backend" in restored.scopes
