import pytest
from unittest.mock import AsyncMock
from evidence.minimization import minimize_artifact, _estimate_size


class TestMinimization:
    @pytest.mark.asyncio
    async def test_returns_not_minimized_without_candidate(self):
        result = await minimize_artifact("art_1")
        assert result["minimized"] is False

    @pytest.mark.asyncio
    async def test_returns_not_minimized_without_replay_fn(self):
        result = await minimize_artifact("art_1", artifact_candidate={"type": "crash"})
        assert result["minimized"] is False

    def test_estimate_size(self):
        assert _estimate_size({"key": "value"}) > 0
        assert _estimate_size({}) > 0


class TestReportGeneration:
    pass  # Reports tested via API integration
