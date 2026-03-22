"""Dramatiq Redis broker configuration.

Provides a singleton RedisBroker wired to the project's Redis instance
with named queues for each job category.
"""

from __future__ import annotations

import os
import threading

import dramatiq
from dramatiq.brokers.redis import RedisBroker

REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6380")

QUEUE_NAMES: dict[str, str] = {
    "control": "qh_control",
    "package": "qh_package",
    "fuzz": "qh_fuzz",
    "replay": "qh_replay",
}

_broker: RedisBroker | None = None
_lock = threading.Lock()


def get_broker() -> RedisBroker:
    """Get or create the Dramatiq Redis broker singleton.

    The broker is created once and reused for the lifetime of the process.
    It is also set as the global Dramatiq broker so that ``@dramatiq.actor``
    decorators pick it up automatically.
    """
    global _broker
    if _broker is not None:
        return _broker

    with _lock:
        # Double-check after acquiring lock
        if _broker is not None:
            return _broker

        broker = RedisBroker(url=REDIS_URL)

        for queue_name in QUEUE_NAMES.values():
            broker.declare_queue(queue_name)

        dramatiq.set_broker(broker)
        _broker = broker

    return _broker
