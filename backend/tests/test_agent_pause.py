"""Tests for agent pause functionality."""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from agents.base_agent import BaseAgent
from models.schemas import (
    AgentCreateRequest,
    AgentStatus,
    AgentType,
    ProviderConfig,
    ProviderType,
)


class TestableAgent(BaseAgent):
    """Concrete implementation for testing."""
    agent_type = AgentType.QUICK_AUDIT

    async def analyze(self):
        """Simulate analysis with pausable loop."""
        self.test_files = ["a.py", "b.py", "c.py"]
        self.processed_files = []
        self.pending_files = list(self.test_files)

        for file in self.test_files:
            # Check pause before each file
            if self._pause_requested:
                self.status = AgentStatus.PAUSED
                return

            self.current_file = file
            await asyncio.sleep(0.01)  # Simulate work
            self.processed_files.append(file)
            self.pending_files.remove(file)
            self.current_file = None


@pytest.fixture
def agent_request():
    """Create a basic agent request."""
    return AgentCreateRequest(
        repo_id="test-repo",
        agent_type=AgentType.QUICK_AUDIT,
        provider_config=ProviderConfig(
            provider=ProviderType.ANTHROPIC,
            model="claude-3-haiku-20240307",
        ),
    )


@pytest.mark.asyncio
async def test_pause_request_flag(agent_request):
    """Test that pause request sets the flag."""
    agent = TestableAgent(agent_request, "/tmp/repo")

    assert agent._pause_requested is False
    agent.request_pause()
    assert agent._pause_requested is True


@pytest.mark.asyncio
async def test_pause_stops_analysis(agent_request):
    """Test that pause stops analysis between files."""
    agent = TestableAgent(agent_request, "/tmp/repo")
    agent.on_message = MagicMock()

    # Start analysis in background
    task = asyncio.create_task(agent.analyze())

    # Wait a bit then request pause
    await asyncio.sleep(0.02)
    agent.request_pause()

    # Wait for completion
    await task

    # Should have processed some but not all files
    assert agent.status == AgentStatus.PAUSED
    assert len(agent.processed_files) > 0
    assert len(agent.processed_files) < 3


@pytest.mark.asyncio
async def test_get_pause_state(agent_request):
    """Test getting pausable state for snapshot."""
    agent = TestableAgent(agent_request, "/tmp/repo")
    agent.processed_files = ["a.py"]
    agent.pending_files = ["b.py", "c.py"]
    agent.current_file = "b.py"

    state = agent.get_pause_state()

    assert state["processed_files"] == ["a.py"]
    assert state["pending_files"] == ["b.py", "c.py"]
    assert state["current_file"] == "b.py"


@pytest.mark.asyncio
async def test_is_pausable(agent_request):
    """Test pausable status check."""
    agent = TestableAgent(agent_request, "/tmp/repo")

    agent.status = AgentStatus.RUNNING
    assert agent.is_pausable() is True

    agent.status = AgentStatus.COMPLETED
    assert agent.is_pausable() is False

    agent.status = AgentStatus.PAUSED
    assert agent.is_pausable() is False
