"""Behavior Tree Service — tracks every LLM action for real-time visualization.

Manages per-agent behavior trees with cursor-tracked positions.
Broadcasts INCREMENTAL updates (single node add/update) via WebSocket,
NOT full graph dumps like FlowService.
"""

import asyncio
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from models.behavior_tree import BTNode, BTNodeStatus, BTNodeType, BTNodeUpdate
from models.schemas import WSMessage, WSMessageType


@dataclass
class SubCursor:
    """Per-subagent leaf state for concurrent sub-agent isolation."""
    agent_node_id: Optional[str] = None
    turn_id: Optional[str] = None
    last_tool_call_id: Optional[str] = None


@dataclass
class BTCursor:
    """Tracks the current position in a behavior tree for an agent.

    Structural fields (session, phase, wave, signal) are shared across
    all concurrent sub-agents.  Leaf fields (agent_node, turn, tool_call)
    are per-subagent via _sub_cursors to avoid race conditions when
    multiple sub-agents run in parallel under the same parent agent_id.
    """
    # Structural (shared across concurrent subagents)
    session_id: Optional[str] = None
    phase_id: Optional[str] = None
    wave_id: Optional[str] = None
    signal_id: Optional[str] = None
    # Legacy leaf fields — used when subagent_id is not provided
    agent_node_id: Optional[str] = None
    turn_id: Optional[str] = None
    last_tool_call_id: Optional[str] = None
    # Map subagent CLI ID → agent node ID (for concurrent subagents)
    subagent_map: dict[str, str] = field(default_factory=dict)
    # Per-subagent leaf cursors for concurrent isolation
    _sub_cursors: dict[str, SubCursor] = field(default_factory=dict)

    def get_leaf(self, subagent_id: Optional[str] = None) -> SubCursor:
        """Get leaf state for a subagent, or top-level fallback."""
        if subagent_id and subagent_id in self._sub_cursors:
            return self._sub_cursors[subagent_id]
        return SubCursor(
            agent_node_id=self.agent_node_id,
            turn_id=self.turn_id,
            last_tool_call_id=self.last_tool_call_id,
        )

    def ensure_sub_cursor(self, subagent_id: str) -> SubCursor:
        """Get or create a per-subagent leaf cursor."""
        if subagent_id not in self._sub_cursors:
            self._sub_cursors[subagent_id] = SubCursor()
        return self._sub_cursors[subagent_id]


def _gen_id() -> str:
    return str(uuid.uuid4())[:10]


class BehaviorTreeService:
    """Manages per-agent behavior trees with incremental WebSocket broadcasts."""

    MAX_NODES_PER_AGENT = 10_000

    def __init__(self):
        self._trees: dict[str, dict[str, BTNode]] = {}
        self._cursors: dict[str, BTCursor] = {}
        self._broadcast_callback: Optional[Callable[[WSMessage], None]] = None

    def set_broadcast_callback(self, callback: Callable[[WSMessage], None]) -> None:
        self._broadcast_callback = callback

    # ── Tree lifecycle ────────────────────────────────────────────

    def initialize_tree(self, agent_id: str) -> BTNode:
        """Create root SESSION node for an agent. Returns the root."""
        self._trees[agent_id] = {}
        cursor = BTCursor()
        self._cursors[agent_id] = cursor

        root = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            node_type=BTNodeType.SESSION,
            label=f"Session {agent_id}",
            status=BTNodeStatus.ACTIVE,
            depth=0,
        ))
        cursor.session_id = root.id
        return root

    def clear_agent(self, agent_id: str) -> None:
        """Remove all tree data for an agent."""
        self._trees.pop(agent_id, None)
        self._cursors.pop(agent_id, None)

    # ── Phase / Wave / Signal ─────────────────────────────────────

    def start_phase(self, agent_id: str, name: str) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor or not cursor.session_id:
            return None
        node = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=cursor.session_id,
            node_type=BTNodeType.PHASE,
            label=f"Phase: {name}",
            status=BTNodeStatus.ACTIVE,
            depth=1,
            data={"phase_name": name},
        ))
        cursor.phase_id = node.id
        cursor.wave_id = None
        cursor.signal_id = None
        cursor.agent_node_id = None
        cursor.turn_id = None
        return node

    def complete_phase(self, agent_id: str) -> None:
        cursor = self._cursors.get(agent_id)
        if not cursor or not cursor.phase_id:
            return
        self._update_node(agent_id, cursor.phase_id, status=BTNodeStatus.COMPLETED)

    def start_wave(self, agent_id: str, wave_num: int, focus: str = "") -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor or not cursor.phase_id:
            return None
        label = f"Wave {wave_num}"
        if focus:
            label += f": {focus}"
        node = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=cursor.phase_id,
            node_type=BTNodeType.WAVE,
            label=label,
            status=BTNodeStatus.ACTIVE,
            depth=2,
            data={"wave_num": wave_num, "focus": focus},
        ))
        cursor.wave_id = node.id
        cursor.signal_id = None
        cursor.agent_node_id = None
        cursor.turn_id = None
        return node

    def complete_wave(self, agent_id: str) -> None:
        cursor = self._cursors.get(agent_id)
        if not cursor or not cursor.wave_id:
            return
        self._update_node(agent_id, cursor.wave_id, status=BTNodeStatus.COMPLETED)

    def start_signal(self, agent_id: str, title: str, severity: str = "") -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        parent_id = cursor.wave_id or cursor.phase_id or cursor.session_id
        if not parent_id:
            return None
        parent_depth = self._get_depth(agent_id, parent_id)
        label = f"Signal: {title[:60]}"
        if severity:
            label = f"[{severity.upper()}] {label}"
        node = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=parent_id,
            node_type=BTNodeType.SIGNAL,
            label=label,
            status=BTNodeStatus.ACTIVE,
            depth=parent_depth + 1,
            data={"title": title, "severity": severity},
        ))
        cursor.signal_id = node.id
        cursor.agent_node_id = None
        cursor.turn_id = None
        return node

    def complete_signal(self, agent_id: str) -> None:
        cursor = self._cursors.get(agent_id)
        if not cursor or not cursor.signal_id:
            return
        self._update_node(agent_id, cursor.signal_id, status=BTNodeStatus.COMPLETED)

    # ── Agent (subagent invocations) ──────────────────────────────

    def start_agent(
        self,
        agent_id: str,
        subagent_id: str,
        subagent_type: str,
        model: str = "",
        objective: str = "",
    ) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        # Attach under signal if routing, else under wave/phase/session
        parent_id = cursor.signal_id or cursor.wave_id or cursor.phase_id or cursor.session_id
        if not parent_id:
            return None
        parent_depth = self._get_depth(agent_id, parent_id)
        label = f"Agent: {subagent_type}"
        if model:
            label += f" [{model}]"
        node = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=parent_id,
            node_type=BTNodeType.AGENT,
            label=label,
            status=BTNodeStatus.ACTIVE,
            depth=parent_depth + 1,
            data={
                "subagent_id": subagent_id,
                "subagent_type": subagent_type,
                "model": model,
                "objective": objective[:200],
            },
        ))
        # Create per-subagent cursor for concurrent isolation
        sub = cursor.ensure_sub_cursor(subagent_id)
        sub.agent_node_id = node.id
        sub.turn_id = None
        sub.last_tool_call_id = None
        cursor.subagent_map[subagent_id] = node.id
        # Also write top-level for callers that don't pass subagent_id
        cursor.agent_node_id = node.id
        cursor.turn_id = None
        cursor.last_tool_call_id = None
        return node

    def complete_agent(
        self,
        agent_id: str,
        subagent_id: str = "",
        cost_usd: Optional[float] = None,
        duration_ms: Optional[int] = None,
    ) -> None:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return
        # Find the correct agent node
        node_id = cursor.subagent_map.get(subagent_id) or cursor.agent_node_id
        if not node_id:
            return
        data_merge: dict[str, Any] = {}
        if cost_usd is not None:
            data_merge["cost_usd"] = cost_usd
        if duration_ms is not None:
            data_merge["duration_ms"] = duration_ms
        self._update_node(agent_id, node_id, status=BTNodeStatus.COMPLETED, data_merge=data_merge)

    # ── Turn-level events ─────────────────────────────────────────

    def start_turn(self, agent_id: str, turn_num: int, subagent_id: Optional[str] = None) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.agent_node_id:
            return None
        parent_depth = self._get_depth(agent_id, leaf.agent_node_id)
        node = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=leaf.agent_node_id,
            node_type=BTNodeType.TURN,
            label=f"Turn {turn_num}",
            status=BTNodeStatus.ACTIVE,
            depth=parent_depth + 1,
            data={"turn_num": turn_num},
        ))
        if subagent_id:
            sub = cursor.ensure_sub_cursor(subagent_id)
            sub.turn_id = node.id
            sub.last_tool_call_id = None
        else:
            cursor.turn_id = node.id
            cursor.last_tool_call_id = None
        return node

    def complete_turn(self, agent_id: str, cost_usd: Optional[float] = None, subagent_id: Optional[str] = None) -> None:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.turn_id:
            return
        data_merge = {"cost_usd": cost_usd} if cost_usd is not None else None
        self._update_node(agent_id, leaf.turn_id, status=BTNodeStatus.COMPLETED, data_merge=data_merge)

    def add_llm_request(self, agent_id: str, prompt: str, model: str = "", subagent_id: Optional[str] = None) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.turn_id:
            return None
        parent_depth = self._get_depth(agent_id, leaf.turn_id)
        return self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=leaf.turn_id,
            node_type=BTNodeType.LLM_REQUEST,
            label=f"> {prompt[:70]}",
            status=BTNodeStatus.COMPLETED,
            depth=parent_depth + 1,
            data={"prompt": prompt, "model": model},
        ))

    def add_llm_response(
        self, agent_id: str, text: str, tokens: Optional[int] = None, subagent_id: Optional[str] = None
    ) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.turn_id:
            return None
        parent_depth = self._get_depth(agent_id, leaf.turn_id)
        label = f"< {text[:70]}"
        if tokens:
            label += f" ({tokens} tok)"
        return self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=leaf.turn_id,
            node_type=BTNodeType.LLM_RESPONSE,
            label=label,
            status=BTNodeStatus.COMPLETED,
            depth=parent_depth + 1,
            data={"text": text, "tokens": tokens},
        ))

    def add_llm_thinking(self, agent_id: str, text: str, subagent_id: Optional[str] = None) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.turn_id:
            return None
        parent_depth = self._get_depth(agent_id, leaf.turn_id)
        return self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=leaf.turn_id,
            node_type=BTNodeType.LLM_THINKING,
            label=f"... {text[:65]}",
            status=BTNodeStatus.COMPLETED,
            depth=parent_depth + 1,
            data={"text": text},
        ))

    def add_tool_call(
        self, agent_id: str, tool_name: str, args: dict[str, Any], subagent_id: Optional[str] = None
    ) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.turn_id:
            return None
        parent_depth = self._get_depth(agent_id, leaf.turn_id)
        # Build concise args summary
        args_summary = ", ".join(
            f"{k}={str(v)[:30]}" for k, v in list(args.items())[:3]
        )
        label = f"▶ {tool_name}({args_summary})"[:80]
        node = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=leaf.turn_id,
            node_type=BTNodeType.TOOL_CALL,
            label=label,
            status=BTNodeStatus.ACTIVE,
            depth=parent_depth + 1,
            data={"tool_name": tool_name, "arguments": args},
        ))
        if subagent_id:
            cursor.ensure_sub_cursor(subagent_id).last_tool_call_id = node.id
        else:
            cursor.last_tool_call_id = node.id
        return node

    def add_tool_result(
        self,
        agent_id: str,
        tool_use_id: str,
        result: str,
        is_error: bool = False,
        subagent_id: Optional[str] = None,
    ) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.turn_id:
            return None
        # Attach under the tool_call node if available, else under turn
        parent_id = leaf.last_tool_call_id or leaf.turn_id
        parent_depth = self._get_depth(agent_id, parent_id)
        # Complete the tool_call node
        if leaf.last_tool_call_id:
            self._update_node(
                agent_id,
                leaf.last_tool_call_id,
                status=BTNodeStatus.FAILED if is_error else BTNodeStatus.COMPLETED,
            )
        label = f"◀ {'ERROR: ' if is_error else ''}{result[:65]}"
        node = self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=parent_id,
            node_type=BTNodeType.TOOL_RESULT,
            label=label,
            status=BTNodeStatus.FAILED if is_error else BTNodeStatus.COMPLETED,
            depth=parent_depth + 1,
            data={"result": result, "is_error": is_error, "tool_use_id": tool_use_id},
        ))
        if subagent_id:
            cursor.ensure_sub_cursor(subagent_id).last_tool_call_id = None
        else:
            cursor.last_tool_call_id = None
        return node

    def add_finding(self, agent_id: str, finding_data: dict[str, Any], subagent_id: Optional[str] = None) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        if not leaf.turn_id:
            return None
        parent_depth = self._get_depth(agent_id, leaf.turn_id)
        severity = finding_data.get("severity", "")
        title = finding_data.get("title", "Finding")
        label = f"★ [{severity.upper()}] {title}"[:80]
        return self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=leaf.turn_id,
            node_type=BTNodeType.FINDING,
            label=label,
            status=BTNodeStatus.COMPLETED,
            depth=parent_depth + 1,
            data=finding_data,
        ))

    def add_error(self, agent_id: str, error_msg: str, subagent_id: Optional[str] = None) -> Optional[BTNode]:
        cursor = self._cursors.get(agent_id)
        if not cursor:
            return None
        leaf = cursor.get_leaf(subagent_id)
        # Attach under the most specific current context
        parent_id = (
            leaf.turn_id
            or leaf.agent_node_id
            or cursor.signal_id
            or cursor.wave_id
            or cursor.phase_id
            or cursor.session_id
        )
        if not parent_id:
            return None
        parent_depth = self._get_depth(agent_id, parent_id)
        return self._add_node(agent_id, BTNode(
            id=_gen_id(),
            agent_id=agent_id,
            parent_id=parent_id,
            node_type=BTNodeType.ERROR,
            label=f"✗ {error_msg[:70]}",
            status=BTNodeStatus.FAILED,
            depth=parent_depth + 1,
            data={"error": error_msg},
        ))

    def complete_session(
        self, agent_id: str, total_cost: Optional[float] = None
    ) -> None:
        cursor = self._cursors.get(agent_id)
        if not cursor or not cursor.session_id:
            return
        data_merge = {"total_cost": total_cost} if total_cost is not None else None
        self._update_node(agent_id, cursor.session_id, status=BTNodeStatus.COMPLETED, data_merge=data_merge)

    # ── Retrieval ─────────────────────────────────────────────────

    def get_tree(self, agent_id: str) -> list[dict[str, Any]]:
        """Get all nodes for an agent as dicts (for REST/WS).

        If tree has >500 nodes, returns only top 3 levels to avoid
        large payloads. Use get_subtree() for deeper nodes.
        """
        tree = self._trees.get(agent_id, {})
        if len(tree) > 500:
            return [
                node.model_dump(mode="json")
                for node in tree.values()
                if node.depth <= 3
            ]
        return [node.model_dump(mode="json") for node in tree.values()]

    def get_subtree(
        self, agent_id: str, node_id: str, max_depth: int = 3
    ) -> list[dict[str, Any]]:
        """Get nodes under a specific parent, limited depth."""
        tree = self._trees.get(agent_id, {})
        root = tree.get(node_id)
        if not root:
            return []
        root_depth = root.depth
        result = []
        for node in tree.values():
            if node.id == node_id or (
                node.depth > root_depth
                and node.depth <= root_depth + max_depth
                and self._is_descendant(tree, node.id, node_id)
            ):
                result.append(node.model_dump(mode="json"))
        return result

    # ── Internal helpers ──────────────────────────────────────────

    def _get_depth(self, agent_id: str, node_id: str) -> int:
        tree = self._trees.get(agent_id, {})
        node = tree.get(node_id)
        return node.depth if node else 0

    def _is_descendant(self, tree: dict[str, BTNode], node_id: str, ancestor_id: str) -> bool:
        """Check if node_id is a descendant of ancestor_id."""
        current = node_id
        visited = set()
        while current and current not in visited:
            visited.add(current)
            node = tree.get(current)
            if not node:
                return False
            if node.parent_id == ancestor_id:
                return True
            current = node.parent_id
        return False

    def _add_node(self, agent_id: str, node: BTNode) -> BTNode:
        """Store node, increment parent children_count, broadcast."""
        tree = self._trees.get(agent_id)
        if tree is None:
            tree = {}
            self._trees[agent_id] = tree

        # Evict oldest if over limit
        if len(tree) >= self.MAX_NODES_PER_AGENT:
            return node  # Silently drop — don't overwhelm

        tree[node.id] = node

        # Increment parent's children_count
        if node.parent_id and node.parent_id in tree:
            parent = tree[node.parent_id]
            parent.children_count += 1
            # Broadcast parent update for children_count
            self._broadcast_update(BTNodeUpdate(
                id=parent.id,
                agent_id=agent_id,
                children_count=parent.children_count,
            ))
            self._schedule_persist_update(agent_id, parent.id, children_count=parent.children_count)

        # Broadcast the new node
        self._broadcast_add(node)
        self._schedule_persist_node(node)
        return node

    def _update_node(
        self,
        agent_id: str,
        node_id: str,
        status: Optional[BTNodeStatus] = None,
        label: Optional[str] = None,
        data_merge: Optional[dict[str, Any]] = None,
    ) -> None:
        """Update node fields and broadcast."""
        tree = self._trees.get(agent_id, {})
        node = tree.get(node_id)
        if not node:
            return

        if status is not None:
            node.status = status
        if label is not None:
            node.label = label
        if data_merge:
            node.data.update(data_merge)

        self._broadcast_update(BTNodeUpdate(
            id=node_id,
            agent_id=agent_id,
            status=status,
            label=label,
            data_merge=data_merge,
        ))
        self._schedule_persist_update(agent_id, node_id, status=status, label=label, data_merge=data_merge)

    def _broadcast_add(self, node: BTNode) -> None:
        if not self._broadcast_callback:
            return
        try:
            self._broadcast_callback(WSMessage(
                type=WSMessageType.BT_NODE_ADD,
                agent_id=node.agent_id,
                data=node.model_dump(mode="json"),
            ))
        except Exception as e:
            print(f"[BehaviorTree] Broadcast add error: {e}")

    def _broadcast_update(self, update: BTNodeUpdate) -> None:
        if not self._broadcast_callback:
            return
        try:
            self._broadcast_callback(WSMessage(
                type=WSMessageType.BT_NODE_UPDATE,
                agent_id=update.agent_id,
                data=update.model_dump(mode="json", exclude_none=True),
            ))
        except Exception as e:
            print(f"[BehaviorTree] Broadcast update error: {e}")

    # ── DB Persistence (write-through) ────────────────────────────

    def _schedule_persist_node(self, node: BTNode) -> None:
        """Schedule async DB write for a node. Fire-and-forget."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._persist_node(node))
        except RuntimeError:
            pass  # No event loop — skip DB write

    async def _persist_node(self, node: BTNode) -> None:
        """Write a single BT node to the database."""
        try:
            from database.connection import get_session
            from database.models import DBBTNode

            async with get_session() as session:
                db_row = DBBTNode(
                    id=node.id,
                    agent_id=node.agent_id,
                    parent_id=node.parent_id,
                    node_type=node.node_type.value if hasattr(node.node_type, 'value') else str(node.node_type),
                    label=node.label,
                    status=node.status.value if hasattr(node.status, 'value') else str(node.status),
                    timestamp=node.timestamp,
                    data=node.data,
                    children_count=node.children_count,
                    depth=node.depth,
                )
                await session.merge(db_row)
        except Exception as e:
            print(f"[BehaviorTree] DB persist node error: {e}")

    def _schedule_persist_update(
        self,
        agent_id: str,
        node_id: str,
        status: Optional[BTNodeStatus] = None,
        label: Optional[str] = None,
        data_merge: Optional[dict[str, Any]] = None,
        children_count: Optional[int] = None,
    ) -> None:
        """Schedule async DB update for a node. Fire-and-forget."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._persist_update(agent_id, node_id, status, label, data_merge, children_count))
        except RuntimeError:
            pass

    async def _persist_update(
        self,
        agent_id: str,
        node_id: str,
        status: Optional[BTNodeStatus] = None,
        label: Optional[str] = None,
        data_merge: Optional[dict[str, Any]] = None,
        children_count: Optional[int] = None,
    ) -> None:
        """Update a BT node in the database."""
        try:
            from database.connection import get_session
            from database.models import DBBTNode
            from sqlalchemy import select

            async with get_session() as session:
                result = await session.execute(
                    select(DBBTNode).where(DBBTNode.id == node_id)
                )
                db_row = result.scalar_one_or_none()
                if not db_row:
                    return
                if status is not None:
                    db_row.status = status.value if hasattr(status, 'value') else str(status)
                if label is not None:
                    db_row.label = label
                if data_merge and db_row.data:
                    merged = dict(db_row.data)
                    merged.update(data_merge)
                    db_row.data = merged
                elif data_merge:
                    db_row.data = data_merge
                if children_count is not None:
                    db_row.children_count = children_count
        except Exception as e:
            print(f"[BehaviorTree] DB persist update error: {e}")

    # ── DB Retrieval ──────────────────────────────────────────────

    async def load_tree_from_db(self, agent_id: str) -> list[dict[str, Any]]:
        """Load behavior tree from database when not in memory."""
        try:
            from database.connection import get_session
            from database.models import DBBTNode
            from sqlalchemy import select

            async with get_session() as session:
                result = await session.execute(
                    select(DBBTNode)
                    .where(DBBTNode.agent_id == agent_id)
                    .order_by(DBBTNode.timestamp)
                )
                rows = result.scalars().all()
                if not rows:
                    return []

                nodes = []
                for row in rows:
                    nodes.append({
                        "id": row.id,
                        "agent_id": row.agent_id,
                        "parent_id": row.parent_id,
                        "node_type": row.node_type,
                        "label": row.label,
                        "status": row.status,
                        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                        "data": row.data or {},
                        "children_count": row.children_count,
                        "depth": row.depth,
                    })
                return nodes
        except Exception as e:
            print(f"[BehaviorTree] DB load error: {e}")
            return []


# Singleton instance
behavior_tree_service = BehaviorTreeService()
