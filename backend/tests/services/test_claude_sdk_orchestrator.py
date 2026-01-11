"""
Tests for ClaudeSDKOrchestrator (Governor).

The orchestrator manages turn-based Claude SDK sessions with budget enforcement,
finding validation, and steering between scanner and analyzer phases.
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from services.claude_sdk_orchestrator import (
    SCAN_TIER_BUDGETS,
    SCAN_TIER_FLOORS,
    ClaudeSDKOrchestrator,
)


class FakeClock:
    """Fake monotonic clock for time-based tests."""

    def __init__(self, now: float = 0.0):
        self.now = now

    def monotonic(self) -> float:
        return self.now


class TestScanTierConstants:
    """Tests for tier budget and floor constants."""

    def test_all_tiers_have_budgets(self):
        expected_tiers = {"quick", "medium", "advanced", "pro", "ultra", "evil"}
        assert set(SCAN_TIER_BUDGETS.keys()) == expected_tiers

    def test_all_tiers_have_floors(self):
        expected_tiers = {"quick", "medium", "advanced", "pro", "ultra", "evil"}
        assert set(SCAN_TIER_FLOORS.keys()) == expected_tiers

    def test_quick_tier_values(self):
        assert SCAN_TIER_BUDGETS["quick"] == 5 * 60  # 5 minutes
        assert SCAN_TIER_FLOORS["quick"] == 2 * 60   # 2 minutes

    def test_medium_tier_values(self):
        assert SCAN_TIER_BUDGETS["medium"] == 15 * 60  # 15 minutes
        assert SCAN_TIER_FLOORS["medium"] == 8 * 60    # 8 minutes

    def test_advanced_tier_values(self):
        assert SCAN_TIER_BUDGETS["advanced"] == 45 * 60   # 45 minutes
        assert SCAN_TIER_FLOORS["advanced"] == 30 * 60    # 30 minutes

    def test_pro_tier_values(self):
        assert SCAN_TIER_BUDGETS["pro"] == 90 * 60    # 90 minutes
        assert SCAN_TIER_FLOORS["pro"] == 60 * 60     # 60 minutes

    def test_ultra_tier_values(self):
        assert SCAN_TIER_BUDGETS["ultra"] == 4 * 60 * 60   # 4 hours
        assert SCAN_TIER_FLOORS["ultra"] == 2 * 60 * 60    # 2 hours

    def test_evil_tier_values(self):
        assert SCAN_TIER_BUDGETS["evil"] == 24 * 60 * 60   # 24 hours
        assert SCAN_TIER_FLOORS["evil"] == 8 * 60 * 60     # 8 hours

    def test_floors_are_less_than_budgets(self):
        for tier in SCAN_TIER_BUDGETS:
            assert SCAN_TIER_FLOORS[tier] < SCAN_TIER_BUDGETS[tier], \
                f"Floor for {tier} should be less than budget"


class TestClaudeSDKOrchestratorInit:
    """Tests for orchestrator initialization."""

    @pytest.fixture
    def mock_provider(self):
        provider = Mock()
        provider.interrupt = Mock()
        return provider

    @pytest.fixture
    def mock_tool_core(self):
        return Mock()

    @pytest.fixture
    def mock_on_ws_event(self):
        return Mock()

    def test_init_sets_budget_from_tier(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )
        assert orchestrator.budget_s == SCAN_TIER_BUDGETS["quick"]

    def test_init_sets_floor_from_tier(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="advanced",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )
        assert orchestrator.time_floor_s == SCAN_TIER_FLOORS["advanced"]

    def test_init_starts_in_scanner_phase(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )
        assert orchestrator.phase == "scanner"

    def test_init_not_cancelled(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )
        assert orchestrator._cancelled is False

    def test_init_stores_provider(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )
        assert orchestrator.provider is mock_provider

    def test_init_stores_tool_core(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )
        assert orchestrator.tool_core is mock_tool_core

    def test_init_stores_ws_event_callback(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )
        assert orchestrator.on_ws_event is mock_on_ws_event


class TestClaudeSDKOrchestratorBudget:
    """Tests for budget and time management."""

    @pytest.fixture
    def mock_provider(self):
        provider = Mock()
        provider.interrupt = Mock()
        return provider

    @pytest.fixture
    def mock_tool_core(self):
        return Mock()

    @pytest.fixture
    def mock_on_ws_event(self):
        return Mock()

    def test_remaining_s_starts_at_budget(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=0.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        assert orchestrator.remaining_s() == SCAN_TIER_BUDGETS["quick"]

    def test_remaining_s_decreases(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=0.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        # Advance time by 60 seconds
        clock.now = 60.0

        remaining = orchestrator.remaining_s()
        assert remaining == SCAN_TIER_BUDGETS["quick"] - 60

    def test_elapsed_s_starts_at_zero(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=100.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        assert orchestrator.elapsed_s() == 0.0

    def test_elapsed_s_increases(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=100.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        # Advance time by 30 seconds
        clock.now = 130.0

        assert orchestrator.elapsed_s() == 30.0

    def test_time_floor_satisfied_false_initially(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=0.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        assert orchestrator.time_floor_satisfied() is False

    def test_time_floor_satisfied_true_after_floor(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=0.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        # Advance time past the floor (2 minutes for quick tier)
        clock.now = SCAN_TIER_FLOORS["quick"] + 1.0

        assert orchestrator.time_floor_satisfied() is True

    def test_make_fresh_limits_has_deadline(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=0.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        limits = orchestrator.make_fresh_limits()

        # Deadline should be at 25% of remaining budget
        expected_deadline = clock.now + (SCAN_TIER_BUDGETS["quick"] * 0.25)
        assert limits.deadline == expected_deadline

    def test_make_fresh_limits_updates_with_time(self, mock_on_ws_event, mock_provider, mock_tool_core, monkeypatch):
        clock = FakeClock(now=0.0)
        monkeypatch.setattr(time, "monotonic", clock.monotonic)

        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        # Advance time by 60 seconds
        clock.now = 60.0

        limits = orchestrator.make_fresh_limits()

        # Remaining budget is now budget - 60
        remaining = SCAN_TIER_BUDGETS["quick"] - 60
        expected_deadline = clock.now + (remaining * 0.25)
        assert limits.deadline == expected_deadline


class TestClaudeSDKOrchestratorCancel:
    """Tests for cancellation functionality."""

    @pytest.fixture
    def mock_provider(self):
        provider = Mock()
        provider.interrupt = Mock()
        return provider

    @pytest.fixture
    def mock_tool_core(self):
        return Mock()

    @pytest.fixture
    def mock_on_ws_event(self):
        return Mock()

    def test_cancel_sets_cancelled_flag(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        orchestrator.cancel()

        assert orchestrator._cancelled is True

    def test_cancel_calls_provider_interrupt(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        orchestrator.cancel()

        mock_provider.interrupt.assert_called_once()


class TestClaudeSDKOrchestratorPhases:
    """Tests for phase management."""

    @pytest.fixture
    def mock_provider(self):
        provider = Mock()
        provider.interrupt = Mock()
        return provider

    @pytest.fixture
    def mock_tool_core(self):
        return Mock()

    @pytest.fixture
    def mock_on_ws_event(self):
        return Mock()

    def test_get_scanner_policy_returns_string(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        policy = orchestrator._get_scanner_policy()

        assert isinstance(policy, str)
        assert len(policy) > 0

    def test_get_analyzer_policy_returns_string(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        policy = orchestrator._get_analyzer_policy()

        assert isinstance(policy, str)
        assert len(policy) > 0


class TestClaudeSDKOrchestratorPrompts:
    """Tests for prompt building methods."""

    @pytest.fixture
    def mock_provider(self):
        provider = Mock()
        provider.interrupt = Mock()
        return provider

    @pytest.fixture
    def mock_tool_core(self):
        return Mock()

    @pytest.fixture
    def mock_on_ws_event(self):
        return Mock()

    def test_build_continue_prompt_returns_string(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        prompt = orchestrator._build_continue_prompt()

        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_build_steering_prompt_returns_string(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        prompt = orchestrator._build_steering_prompt()

        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_build_analyzer_prompt_returns_string(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        prompt = orchestrator._build_analyzer_prompt()

        assert isinstance(prompt, str)
        assert len(prompt) > 0


class TestClaudeSDKOrchestratorValidation:
    """Tests for finding validation."""

    @pytest.fixture
    def mock_provider(self):
        provider = Mock()
        provider.interrupt = Mock()
        return provider

    @pytest.fixture
    def mock_tool_core(self):
        return Mock()

    @pytest.fixture
    def mock_on_ws_event(self):
        return Mock()

    def test_validate_findings_returns_dict(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        # Initialize with empty findings for test
        orchestrator._findings = []

        result = orchestrator._validate_findings()

        assert isinstance(result, dict)
        assert "valid" in result or "is_valid" in result

    def test_should_handoff_returns_bool(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        result = orchestrator._should_handoff()

        assert isinstance(result, bool)

    def test_claude_says_done_returns_bool(self, mock_on_ws_event, mock_provider, mock_tool_core):
        orchestrator = ClaudeSDKOrchestrator(
            scan_tier="quick",
            on_ws_event=mock_on_ws_event,
            provider=mock_provider,
            tool_core=mock_tool_core,
        )

        # Test with empty response
        result = orchestrator._claude_says_done("")

        assert isinstance(result, bool)
