"""Tests for BehaviorTreeService — cursor isolation with concurrent sub-agents."""

import pytest
from services.behavior_tree_service import BehaviorTreeService, SubCursor, BTCursor
from models.behavior_tree import BTNodeType, BTNodeStatus


@pytest.fixture
def bts():
    """Fresh BehaviorTreeService with broadcast disabled."""
    svc = BehaviorTreeService()
    svc.set_broadcast_callback(lambda msg: None)
    return svc


@pytest.fixture
def agent_id():
    return "overseer_123"


class TestSubCursor:
    def test_get_leaf_fallback(self):
        """Without subagent_id, get_leaf returns top-level fields."""
        cursor = BTCursor(agent_node_id="a1", turn_id="t1", last_tool_call_id="tc1")
        leaf = cursor.get_leaf()
        assert leaf.agent_node_id == "a1"
        assert leaf.turn_id == "t1"
        assert leaf.last_tool_call_id == "tc1"

    def test_get_leaf_with_subagent(self):
        """With registered subagent_id, get_leaf returns sub-cursor."""
        cursor = BTCursor()
        sub = cursor.ensure_sub_cursor("sub_a")
        sub.agent_node_id = "sa1"
        sub.turn_id = "st1"

        leaf = cursor.get_leaf("sub_a")
        assert leaf.agent_node_id == "sa1"
        assert leaf.turn_id == "st1"

    def test_get_leaf_unknown_subagent_falls_back(self):
        """Unknown subagent_id falls back to top-level."""
        cursor = BTCursor(agent_node_id="a1", turn_id="t1")
        leaf = cursor.get_leaf("nonexistent")
        assert leaf.agent_node_id == "a1"
        assert leaf.turn_id == "t1"

    def test_ensure_sub_cursor_creates_once(self):
        """ensure_sub_cursor creates on first call, reuses on second."""
        cursor = BTCursor()
        sub1 = cursor.ensure_sub_cursor("x")
        sub1.turn_id = "set_by_sub1"
        sub2 = cursor.ensure_sub_cursor("x")
        assert sub2.turn_id == "set_by_sub1"
        assert sub1 is sub2


class TestCursorIsolation:
    """Two concurrent sub-agents should not clobber each other's leaf state."""

    def test_parallel_subagents_independent_turns(self, bts, agent_id):
        """Two sub-agents can track independent turns under the same parent."""
        bts.initialize_tree(agent_id)
        bts.start_phase(agent_id, "foundation")
        bts.start_wave(agent_id, 1, "test-wave")

        # Start two sub-agents
        node_a = bts.start_agent(agent_id, "RepoProfiler_001", "RepoProfiler", "claude-sonnet-4-5-20250929", "profile repo")
        node_b = bts.start_agent(agent_id, "ScopeMapper_002", "ScopeMapper", "claude-sonnet-4-5-20250929", "map scope")

        assert node_a is not None
        assert node_b is not None

        # Start turns for each — should be independent
        turn_a = bts.start_turn(agent_id, 1, subagent_id="RepoProfiler_001")
        turn_b = bts.start_turn(agent_id, 1, subagent_id="ScopeMapper_002")

        assert turn_a is not None
        assert turn_b is not None
        assert turn_a.id != turn_b.id

        # turn_a parent should be node_a, turn_b parent should be node_b
        assert turn_a.parent_id == node_a.id
        assert turn_b.parent_id == node_b.id

    def test_subagent_tool_calls_isolated(self, bts, agent_id):
        """Tool calls from different sub-agents attach to correct turns."""
        bts.initialize_tree(agent_id)

        bts.start_phase(agent_id, "foundation")
        bts.start_wave(agent_id, 1, "test-wave")

        bts.start_agent(agent_id, "RepoProfiler_001", "RepoProfiler", "claude-sonnet-4-5-20250929", "profile")
        bts.start_agent(agent_id, "ScopeMapper_002", "ScopeMapper", "claude-sonnet-4-5-20250929", "scope")

        turn_a = bts.start_turn(agent_id, 1, subagent_id="RepoProfiler_001")
        turn_b = bts.start_turn(agent_id, 1, subagent_id="ScopeMapper_002")

        # Add tool calls to each sub-agent
        tool_a = bts.add_tool_call(agent_id, "read_file", {"path": "a.py"}, subagent_id="RepoProfiler_001")
        tool_b = bts.add_tool_call(agent_id, "grep_search", {"pattern": "auth"}, subagent_id="ScopeMapper_002")

        assert tool_a is not None
        assert tool_b is not None
        assert tool_a.parent_id == turn_a.id
        assert tool_b.parent_id == turn_b.id

    def test_subagent_llm_responses_isolated(self, bts, agent_id):
        """LLM responses from different sub-agents attach to correct turns."""
        bts.initialize_tree(agent_id)

        bts.start_phase(agent_id, "foundation")
        bts.start_wave(agent_id, 1, "test-wave")

        bts.start_agent(agent_id, "Agent_A", "TypeA", "model", "obj_a")
        bts.start_agent(agent_id, "Agent_B", "TypeB", "model", "obj_b")

        turn_a = bts.start_turn(agent_id, 1, subagent_id="Agent_A")
        turn_b = bts.start_turn(agent_id, 1, subagent_id="Agent_B")

        resp_a = bts.add_llm_response(agent_id, "Response from A", subagent_id="Agent_A")
        resp_b = bts.add_llm_response(agent_id, "Response from B", subagent_id="Agent_B")

        assert resp_a is not None
        assert resp_b is not None
        assert resp_a.parent_id == turn_a.id
        assert resp_b.parent_id == turn_b.id

    def test_tool_result_clears_correct_subcursor(self, bts, agent_id):
        """add_tool_result clears last_tool_call_id only for the correct sub-agent."""
        bts.initialize_tree(agent_id)

        bts.start_phase(agent_id, "foundation")
        bts.start_wave(agent_id, 1, "test-wave")

        bts.start_agent(agent_id, "A", "TypeA", "model", "obj")
        bts.start_agent(agent_id, "B", "TypeB", "model", "obj")

        bts.start_turn(agent_id, 1, subagent_id="A")
        bts.start_turn(agent_id, 1, subagent_id="B")

        tool_a = bts.add_tool_call(agent_id, "tool1", {}, subagent_id="A")
        tool_b = bts.add_tool_call(agent_id, "tool2", {}, subagent_id="B")

        # Complete tool A's result — should not affect B's last_tool_call_id
        bts.add_tool_result(agent_id, "ext_id_a", "result_a", False, subagent_id="A")

        cursor = bts._cursors[agent_id]
        leaf_a = cursor.get_leaf("A")
        leaf_b = cursor.get_leaf("B")
        assert leaf_a.last_tool_call_id is None  # cleared
        assert leaf_b.last_tool_call_id == tool_b.id  # still set


class TestBackwardCompat:
    """Existing callers without subagent_id should still work (agent_orchestrator path)."""

    def test_no_subagent_id_uses_toplevel(self, bts, agent_id):
        """Without subagent_id, methods use top-level cursor fields."""
        bts.initialize_tree(agent_id)

        bts.start_phase(agent_id, "phase1")
        bts.start_wave(agent_id, 1, "wave1")
        bts.start_agent(agent_id, "sub1", "type1", "model", "obj")

        # These calls omit subagent_id — should use top-level cursor
        turn = bts.start_turn(agent_id, 1)
        assert turn is not None

        resp = bts.add_llm_response(agent_id, "hello")
        assert resp is not None
        assert resp.parent_id == turn.id

        tool = bts.add_tool_call(agent_id, "read_file", {"path": "x"})
        assert tool is not None
        assert tool.parent_id == turn.id

    def test_start_agent_sets_toplevel_for_backward_compat(self, bts, agent_id):
        """start_agent writes both sub-cursor AND top-level fields."""
        bts.initialize_tree(agent_id)

        bts.start_phase(agent_id, "phase1")
        bts.start_wave(agent_id, 1, "wave1")

        node = bts.start_agent(agent_id, "sub1", "type1", "model", "obj")
        cursor = bts._cursors[agent_id]

        # Top-level should be set (backward compat)
        assert cursor.agent_node_id == node.id
        # Sub-cursor should also be set
        leaf = cursor.get_leaf("sub1")
        assert leaf.agent_node_id == node.id


class TestErrorHandling:
    """Error methods should work with subagent_id."""

    def test_add_error_with_subagent(self, bts, agent_id):
        bts.initialize_tree(agent_id)

        bts.start_phase(agent_id, "phase1")
        bts.start_wave(agent_id, 1, "wave1")
        bts.start_agent(agent_id, "sub1", "type1", "model", "obj")
        bts.start_turn(agent_id, 1, subagent_id="sub1")

        err = bts.add_error(agent_id, "something broke", subagent_id="sub1")
        assert err is not None
        assert err.node_type == BTNodeType.ERROR

    def test_add_error_without_turn_uses_agent_node(self, bts, agent_id):
        """Error before any turn should attach to agent node."""
        bts.initialize_tree(agent_id)

        bts.start_phase(agent_id, "phase1")
        bts.start_wave(agent_id, 1, "wave1")
        bts.start_agent(agent_id, "sub1", "type1", "model", "obj")

        err = bts.add_error(agent_id, "early error", subagent_id="sub1")
        assert err is not None
