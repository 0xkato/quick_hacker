"""Tests for Devil's Advocate orchestration logic."""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from agents.deep_audit.dispatcher import (
    WaveDispatcher,
    DispatchTask,
    SubagentResult,
    WavePlan,
)


class TestDevilsAdvocate:
    """Test Devil's Advocate challenge logic."""

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher with mock filesystem."""
        fs = MagicMock()
        fs.project_id = "test"
        return WaveDispatcher(repo_path="/test", filesystem=fs)

    def test_quick_dismissal_triggers_challenge(self, dispatcher):
        """Quick dismissal of critical signal triggers challenge."""
        result = SubagentResult(
            task_id="test-001",
            agent_type="Specialist",
            status="completed",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        should_challenge, challenge_type = dispatcher.should_challenge_result(
            result,
            analysis_time_seconds=15,  # Very quick
            signal_severity="CRITICAL",
        )

        assert should_challenge
        assert challenge_type == "quick_dismissal"

    def test_thorough_analysis_no_challenge(self, dispatcher):
        """Thorough analysis doesn't trigger challenge."""
        result = SubagentResult(
            task_id="test-001",
            agent_type="Specialist",
            status="completed",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        should_challenge, _ = dispatcher.should_challenge_result(
            result,
            analysis_time_seconds=120,  # Took reasonable time
            signal_severity="CRITICAL",
        )

        assert not should_challenge

    def test_low_severity_no_challenge(self, dispatcher):
        """Low severity signals don't trigger challenge even if quick."""
        result = SubagentResult(
            task_id="test-001",
            agent_type="Specialist",
            status="completed",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        should_challenge, _ = dispatcher.should_challenge_result(
            result,
            analysis_time_seconds=10,
            signal_severity="LOW",
        )

        assert not should_challenge

    def test_generate_challenge_prompt(self, dispatcher):
        """Challenge prompts are generated correctly."""
        task = DispatchTask(
            agent_type="Specialist",
            objective="Verify SQL injection",
            scope="api/db.py",
            deliverable="/memories/analysis.json",
        )

        prompt = dispatcher.generate_challenge_prompt("quick_dismissal", task)

        assert "Devil's Advocate" in prompt
        assert "alternative path" in prompt.lower()
        assert task.objective in prompt
        assert task.scope in prompt

    def test_challenge_templates_exist(self, dispatcher):
        """All challenge types have templates."""
        assert "quick_dismissal" in dispatcher.DEVILS_ADVOCATE_CHALLENGES
        assert "incomplete_analysis" in dispatcher.DEVILS_ADVOCATE_CHALLENGES
        assert "missing_context" in dispatcher.DEVILS_ADVOCATE_CHALLENGES

        for challenge_type, questions in dispatcher.DEVILS_ADVOCATE_CHALLENGES.items():
            assert len(questions) >= 3, f"{challenge_type} needs more questions"
