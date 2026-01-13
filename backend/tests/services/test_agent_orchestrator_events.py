"""Tests for agent orchestrator observability events."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from services.agent_orchestrator import AgentOrchestrator
from services.critic_loop import CriticDecision, CriticInput
from models.schemas import Finding, ProofChecklist, Disposition, ChecklistItem, ChecklistStatus, Severity


@pytest.fixture
def mock_observability_service():
    """Mock observability service for testing."""
    with patch('services.agent_orchestrator.observability_service') as mock_obs:
        mock_obs.log_critic_started = Mock()
        mock_obs.log_critic_decision = Mock()
        mock_obs.log_critic_output = Mock()
        mock_obs.log_critic_completed = Mock()
        yield mock_obs


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return Finding(
        id="test-finding-1",
        agent_id="test-agent",
        repo_id="test-repo",
        severity=Severity.HIGH,
        title="SQL Injection in login endpoint",
        description="User input is concatenated into SQL query",
        file_path="/app/auth.py",
        line_start=42,
        vulnerability_type="SQL Injection",
        confidence=0.85,
        created_at=datetime.utcnow(),
    )


@pytest.fixture
def sample_checklist():
    """Create a sample proof checklist."""
    return ProofChecklist(
        source_controlled_input=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Request parameter 'username' is used"
        ),
        sink_present=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="SQL query constructed with string concatenation"
        ),
        dataflow_evidenced=ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="Need to trace dataflow from input to sink"
        ),
        reachable=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Endpoint is publicly accessible"
        ),
        boundary_crossed=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Database query execution"
        ),
        not_only_misconfig=ChecklistItem(
            value=True,
            status=ChecklistStatus.PROVEN,
            reason="Code-level vulnerability"
        ),
        security_control_bypassed=ChecklistItem(
            value=False,
            status=ChecklistStatus.UNKNOWN,
            reason="Need to check for parameterized queries"
        ),
    )


@pytest.fixture
def sample_evidence():
    """Create sample evidence result."""
    # Create a mock EvidenceResult
    mock_evidence = Mock()
    mock_evidence.artifacts = []
    mock_evidence.tool_call_count = 5
    return mock_evidence


def test_critic_events_emitted(mock_observability_service, sample_finding, sample_checklist, sample_evidence):
    """Test that critic loop emits observability events."""
    orchestrator = AgentOrchestrator()

    # Mock the CriticLoop.evaluate method to return a decision
    with patch('services.critic_loop.CriticLoop') as mock_critic_class:
        mock_critic = MagicMock()
        mock_critic_class.return_value = mock_critic

        # Create a mock decision
        mock_decision = CriticDecision(
            decision="CONTINUE",
            blocking_gaps=["dataflow_evidenced", "security_control_bypassed"],
            recommended_tool_calls=["search_code", "read_file"],
            reasoning="Pass 1: 2 blocking gap(s) remain"
        )
        mock_critic.evaluate.return_value = mock_decision

        # Call evaluate_with_critic
        result = orchestrator.evaluate_with_critic(
            agent_id="test-agent",
            finding=sample_finding,
            evidence=sample_evidence,
            checklist=sample_checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="hyp_test_1"
        )

        # Verify critic_started was called
        mock_observability_service.log_critic_started.assert_called_once_with(
            agent_id="test-agent",
            span_id="critic_hyp_test_1_1",
            parent_span_id="hyp_test_1",
            pass_number=1
        )

        # Verify critic_decision was called
        mock_observability_service.log_critic_decision.assert_called_once_with(
            agent_id="test-agent",
            span_id="critic_hyp_test_1_1",
            decision="CONTINUE",
            reasoning="Pass 1: 2 blocking gap(s) remain"
        )

        # Verify critic_output was called
        mock_observability_service.log_critic_output.assert_called_once_with(
            agent_id="test-agent",
            span_id="critic_hyp_test_1_1",
            blocking_gaps=["dataflow_evidenced", "security_control_bypassed"],
            recommended_tool_calls=["search_code", "read_file"],
            disposition_hint=None
        )

        # Verify critic_completed was called
        mock_observability_service.log_critic_completed.assert_called_once_with(
            agent_id="test-agent",
            span_id="critic_hyp_test_1_1"
        )

        # Verify the decision was returned
        assert result == mock_decision


def test_critic_span_linkage(mock_observability_service, sample_finding, sample_checklist, sample_evidence):
    """Test that critic_span_id is child of hypothesis_span_id."""
    orchestrator = AgentOrchestrator()

    # Mock the CriticLoop.evaluate method
    with patch('services.critic_loop.CriticLoop') as mock_critic_class:
        mock_critic = MagicMock()
        mock_critic_class.return_value = mock_critic

        mock_decision = CriticDecision(
            decision="READY_TO_REPORT",
            blocking_gaps=[],
            recommended_tool_calls=[],
            reasoning="All required evidence gathered"
        )
        mock_critic.evaluate.return_value = mock_decision

        # Call with different pass numbers to verify span ID generation
        orchestrator.evaluate_with_critic(
            agent_id="test-agent",
            finding=sample_finding,
            evidence=sample_evidence,
            checklist=sample_checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=2,
            remaining_tool_calls=5,
            hypothesis_span_id="hyp_test_2"
        )

        # Verify the span linkage
        call_args = mock_observability_service.log_critic_started.call_args
        assert call_args[1]['span_id'] == "critic_hyp_test_2_2"
        assert call_args[1]['parent_span_id'] == "hyp_test_2"
        assert call_args[1]['pass_number'] == 2


def test_critic_events_with_filtered_decision(mock_observability_service, sample_finding, sample_checklist, sample_evidence):
    """Test critic events when finding is filtered out."""
    orchestrator = AgentOrchestrator()

    # Mock the CriticLoop to return STOP_FILTERED
    with patch('services.critic_loop.CriticLoop') as mock_critic_class:
        mock_critic = MagicMock()
        mock_critic_class.return_value = mock_critic

        mock_decision = CriticDecision(
            decision="STOP_FILTERED",
            blocking_gaps=[],
            recommended_tool_calls=[],
            disposition_hint="MISCONFIGURATION",
            reasoning="Filtered out: Finding is only a misconfiguration"
        )
        mock_critic.evaluate.return_value = mock_decision

        result = orchestrator.evaluate_with_critic(
            agent_id="test-agent",
            finding=sample_finding,
            evidence=sample_evidence,
            checklist=sample_checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="hyp_test_3"
        )

        # Verify disposition_hint is passed through
        call_args = mock_observability_service.log_critic_output.call_args
        assert call_args[1]['disposition_hint'] == "MISCONFIGURATION"

        # Verify decision is STOP_FILTERED
        decision_call_args = mock_observability_service.log_critic_decision.call_args
        assert decision_call_args[1]['decision'] == "STOP_FILTERED"


def test_critic_events_order(mock_observability_service, sample_finding, sample_checklist, sample_evidence):
    """Test that critic events are emitted in correct order."""
    orchestrator = AgentOrchestrator()

    # Track call order
    call_order = []

    def track_started(*args, **kwargs):
        call_order.append('started')

    def track_decision(*args, **kwargs):
        call_order.append('decision')

    def track_output(*args, **kwargs):
        call_order.append('output')

    def track_completed(*args, **kwargs):
        call_order.append('completed')

    mock_observability_service.log_critic_started.side_effect = track_started
    mock_observability_service.log_critic_decision.side_effect = track_decision
    mock_observability_service.log_critic_output.side_effect = track_output
    mock_observability_service.log_critic_completed.side_effect = track_completed

    with patch('services.critic_loop.CriticLoop') as mock_critic_class:
        mock_critic = MagicMock()
        mock_critic_class.return_value = mock_critic

        mock_decision = CriticDecision(
            decision="CONTINUE",
            blocking_gaps=["dataflow_evidenced"],
            recommended_tool_calls=["search_code"]
        )
        mock_critic.evaluate.return_value = mock_decision

        orchestrator.evaluate_with_critic(
            agent_id="test-agent",
            finding=sample_finding,
            evidence=sample_evidence,
            checklist=sample_checklist,
            preliminary_disposition=Disposition.SPECULATIVE,
            pass_number=1,
            remaining_tool_calls=10,
            hypothesis_span_id="hyp_test_4"
        )

        # Verify events were emitted in correct order
        assert call_order == ['started', 'decision', 'output', 'completed']
