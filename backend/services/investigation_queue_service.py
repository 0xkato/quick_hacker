"""In-memory investigation queue for interactive deep-dives.

This supports:
- UI-initiated "queue investigation" actions on flow nodes.
- Agent-initiated auto-queueing from the initial scan/triage phase.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Optional

logger = logging.getLogger(__name__)

# Lock acquisition timeout to prevent deadlocks
LOCK_TIMEOUT_SECONDS = 5.0

QueueSource = Literal["user", "auto"]


@dataclass(frozen=True)
class InvestigationTask:
    id: str
    agent_id: str
    flow_node_id: str
    source: QueueSource
    created_at: datetime
    prompt: str
    metadata: dict[str, Any]


class InvestigationQueueService:
    def __init__(self) -> None:
        self._queues: dict[str, deque[InvestigationTask]] = defaultdict(deque)
        self._dedupe: dict[str, set[str]] = defaultdict(set)  # agent_id -> flow_node_ids
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def _acquire_lock(self, operation: str = "operation"):
        """Acquire lock with timeout to prevent deadlocks."""
        try:
            await asyncio.wait_for(self._lock.acquire(), timeout=LOCK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            logger.error(f"Lock acquisition timeout during {operation} after {LOCK_TIMEOUT_SECONDS}s")
            raise RuntimeError(f"Investigation queue lock timeout during {operation}")
        try:
            yield
        finally:
            self._lock.release()

    async def enqueue(self, task: InvestigationTask) -> bool:
        async with self._acquire_lock("enqueue"):
            if task.flow_node_id in self._dedupe[task.agent_id]:
                return False
            self._queues[task.agent_id].append(task)
            self._dedupe[task.agent_id].add(task.flow_node_id)
            return True

    async def dequeue(self, agent_id: str) -> Optional[InvestigationTask]:
        async with self._acquire_lock("dequeue"):
            if not self._queues.get(agent_id):
                return None
            if not self._queues[agent_id]:
                return None
            task = self._queues[agent_id].popleft()
            self._dedupe[agent_id].discard(task.flow_node_id)
            return task

    async def size(self, agent_id: str) -> int:
        async with self._acquire_lock("size"):
            return len(self._queues.get(agent_id, deque()))

    @staticmethod
    def new_task(
        *,
        agent_id: str,
        flow_node_id: str,
        source: QueueSource,
        prompt: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> InvestigationTask:
        return InvestigationTask(
            id=str(uuid.uuid4())[:12],
            agent_id=agent_id,
            flow_node_id=flow_node_id,
            source=source,
            created_at=datetime.utcnow(),
            prompt=prompt,
            metadata=metadata or {},
        )


investigation_queue_service = InvestigationQueueService()

