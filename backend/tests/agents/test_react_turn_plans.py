"""Tests for turn plan emission in ReAct agent."""
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime

from agents.react import ReActSecurityAgent
from models.schemas import AgentCreateRequest, AgentType, ProviderConfig
from models.turn_plan import TurnPlan, Hypothesis, HypothesisActivity, FocusGap


class TestReactTurnPlanEmission:
    """Test that ReAct agent emits turn plans correctly."""

    def test_react_emits_turn_plan_before_turn(self):
        """ReAct agent should emit turn plans with correct TurnPlan structure."""
        # Create minimal agent
        request = AgentCreateRequest(
            repo_id="test_repo",
            agent_type=AgentType.CUSTOM,
            provider_config=ProviderConfig(
                provider="anthropic",
                model="claude-sonnet-4-20250514"
            )
        )

        with patch('agents.react_agent.get_provider'):
            agent = ReActSecurityAgent(
                request=request,
                repo_path="/tmp/test_repo"
            )

        # Mock the flow_service.emit_turn_plan method
        with patch('services.flow_service.flow_service.emit_turn_plan') as mock_emit:
            with patch('services.span_service.span_service.create_span') as mock_create_span:
                # Call the helper method
                span_id = agent._emit_turn_plan_for_hypothesis(
                    hypothesis_id="hyp_001",
                    hypothesis_label="Test SQL injection in auth endpoint",
                    turn_id="1",
                    focus_gap="sink_present"
                )

                # Verify span was created for new hypothesis
                assert mock_create_span.called
                mock_create_span.assert_called_once()

                # Verify emit_turn_plan was called
                assert mock_emit.called
                mock_emit.assert_called_once()

                # Get the arguments
                call_args = mock_emit.call_args
                called_agent_id = call_args[0][0]
                called_turn_plan = call_args[0][1]

                # Verify agent_id
                assert called_agent_id == agent.id

                # Verify TurnPlan structure
                assert isinstance(called_turn_plan, TurnPlan)
                assert called_turn_plan.turn_id == "1"
                assert len(called_turn_plan.hypotheses) == 1

                # Verify Hypothesis structure
                hyp = called_turn_plan.hypotheses[0]
                assert hyp.hypothesis_id == "hyp_001"
                assert hyp.label == "Test SQL injection in auth endpoint"
                assert hyp.activity == HypothesisActivity.NEW
                assert hyp.focus_gap == FocusGap.SINK_PRESENT
                assert hyp.span_id is not None
                assert hyp.span_id.startswith("span_")

                # Verify span_id returned
                assert span_id is not None
                assert span_id.startswith("span_")

    def test_react_continuing_hypothesis_reuses_span(self):
        """Continuing a hypothesis should reuse existing span_id."""
        # Create minimal agent
        request = AgentCreateRequest(
            repo_id="test_repo",
            agent_type=AgentType.CUSTOM,
            provider_config=ProviderConfig(
                provider="anthropic",
                model="claude-sonnet-4-20250514"
            )
        )

        with patch('agents.react_agent.get_provider'):
            agent = ReActSecurityAgent(
                request=request,
                repo_path="/tmp/test_repo"
            )

        with patch('services.flow_service.flow_service.emit_turn_plan') as mock_emit:
            with patch('services.span_service.span_service.create_span') as mock_create_span:
                # First turn - new hypothesis
                span_id_1 = agent._emit_turn_plan_for_hypothesis(
                    hypothesis_id="hyp_001",
                    hypothesis_label="Test SQL injection",
                    turn_id="1",
                    focus_gap="sink_present"
                )

                # Second turn - continuing hypothesis
                span_id_2 = agent._emit_turn_plan_for_hypothesis(
                    hypothesis_id="hyp_001",
                    hypothesis_label="Test SQL injection",
                    turn_id="2",
                    focus_gap="dataflow_evidenced"
                )

                # Span should only be created once (for new hypothesis)
                assert mock_create_span.call_count == 1

                # Span IDs should be the same
                assert span_id_1 == span_id_2

                # Check activity status in second call
                second_call_args = mock_emit.call_args_list[1]
                second_turn_plan = second_call_args[0][1]
                assert second_turn_plan.hypotheses[0].activity == HypothesisActivity.CONTINUING

    def test_react_tracks_multiple_hypotheses(self):
        """Agent should track multiple active hypotheses."""
        # Create minimal agent
        request = AgentCreateRequest(
            repo_id="test_repo",
            agent_type=AgentType.CUSTOM,
            provider_config=ProviderConfig(
                provider="anthropic",
                model="claude-sonnet-4-20250514"
            )
        )

        with patch('agents.react_agent.get_provider'):
            agent = ReActSecurityAgent(
                request=request,
                repo_path="/tmp/test_repo"
            )

        with patch('services.flow_service.flow_service.emit_turn_plan'):
            with patch('services.span_service.span_service.create_span'):
                # Create first hypothesis
                agent._emit_turn_plan_for_hypothesis(
                    hypothesis_id="hyp_001",
                    hypothesis_label="SQL injection",
                    turn_id="1",
                    focus_gap="sink_present"
                )

                # Create second hypothesis
                agent._emit_turn_plan_for_hypothesis(
                    hypothesis_id="hyp_002",
                    hypothesis_label="XSS vulnerability",
                    turn_id="2",
                    focus_gap="source_controlled_input"
                )

                # Both should be tracked
                assert len(agent._active_hypotheses) == 2
                assert "hyp_001" in agent._active_hypotheses
                assert "hyp_002" in agent._active_hypotheses
