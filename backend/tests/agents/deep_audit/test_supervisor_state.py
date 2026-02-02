# backend/tests/agents/deep_audit/test_supervisor_state.py
"""
Tests for the legacy SupervisorState model.

NOTE: These tests are for the old SupervisorState interface which has been
replaced by CampaignState. The SupervisorState alias points to CampaignState
but the field names have changed. See test_campaign_state.py for tests of
the new interface.
"""
import pytest
from datetime import datetime, timedelta
from agents.deep_audit.state import CampaignState, ScopeDepth


@pytest.mark.skip(reason="Tests legacy SupervisorState interface - see test_campaign_state.py for current tests")
def test_supervisor_state_initialization():
    """Test SupervisorState can be created with required fields."""
    pass


@pytest.mark.skip(reason="Tests legacy SupervisorState interface - see test_campaign_state.py for current tests")
def test_supervisor_state_tracks_scopes():
    """Test SupervisorState can track scope completion."""
    pass


@pytest.mark.skip(reason="Tests legacy SupervisorState interface - see test_campaign_state.py for current tests")
def test_supervisor_state_tracks_coverage():
    """Test SupervisorState tracks file coverage."""
    pass


@pytest.mark.skip(reason="Tests legacy SupervisorState interface - see test_campaign_state.py for current tests")
def test_supervisor_state_serialization():
    """Test SupervisorState can be serialized/deserialized."""
    pass


# New tests for CampaignState (backward compatibility alias)
def test_campaign_state_alias():
    """Test that SupervisorState is an alias for CampaignState."""
    from agents.deep_audit.state import SupervisorState
    assert SupervisorState is CampaignState


def test_campaign_state_coverage_map():
    """Test CampaignState tracks file coverage with ScopeDepth enum."""
    import time

    state = CampaignState(
        project_id="test_proj",
        scan_tier="medium",
        deadline=time.time() + 900,
        coverage_map={
            "/repo/auth/db.py": ScopeDepth.AUDITED,
            "/repo/api/routes.py": ScopeDepth.HUNTED,
            "/repo/utils/helpers.py": ScopeDepth.UNTOUCHED,
        }
    )

    assert state.coverage_map["/repo/auth/db.py"] == ScopeDepth.AUDITED
    assert state.coverage_map["/repo/utils/helpers.py"] == ScopeDepth.UNTOUCHED

    # Calculate coverage by depth
    covered = sum(1 for v in state.coverage_map.values() if v >= ScopeDepth.HUNTED)
    total = len(state.coverage_map)
    coverage_pct = (covered / total * 100) if total > 0 else 0
    assert coverage_pct == pytest.approx(66.67, rel=0.1)
