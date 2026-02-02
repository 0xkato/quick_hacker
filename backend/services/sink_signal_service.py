"""Persistent sink/signal registry (per project).

Signals are investigation leads (sinks/sources/hotspots) and are intentionally separate
from validated findings. They are stored per project so one codebase never pollutes another.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from models.sink_signals import SinkSignal, SinkSignalStatus


SIGNALS_FILENAME = "sink_signals.json"
MAX_LOCKS = 500  # Maximum number of project locks to prevent unbounded memory growth


def compute_signal_fingerprint(
    *,
    kind: str,
    file_path: str,
    line_number: Optional[int],
    label: str,
) -> str:
    """Compute a deterministic fingerprint for a signal."""
    payload = f"{kind}|{file_path}|{line_number or ''}|{label}".strip()
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _merge_status(existing: SinkSignalStatus, incoming: SinkSignalStatus) -> SinkSignalStatus:
    """Do not allow a write to downgrade a signal's lifecycle status."""
    order = {
        SinkSignalStatus.UNREVIEWED: 0,
        SinkSignalStatus.QUEUED: 1,
        SinkSignalStatus.REVIEWED: 2,
        SinkSignalStatus.DISMISSED: 3,
        SinkSignalStatus.PROMOTED: 4,
    }
    return existing if order.get(existing, 0) >= order.get(incoming, 0) else incoming


class SinkSignalService:
    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, project_id: str) -> asyncio.Lock:
        lock = self._locks.get(project_id)
        if lock is None:
            # LRU cleanup: remove oldest locks when exceeding MAX_LOCKS
            if len(self._locks) >= MAX_LOCKS:
                # Remove first (oldest) entry that isn't locked
                for old_id in list(self._locks.keys()):
                    old_lock = self._locks[old_id]
                    if not old_lock.locked():
                        del self._locks[old_id]
                        break
            lock = asyncio.Lock()
            self._locks[project_id] = lock
        return lock

    def _project_dir(self, project_id: str) -> Path:
        base = (Path(os.environ.get("DATA_DIR", "data")) / "projects").resolve()
        candidate = (base / project_id).resolve()
        try:
            candidate.relative_to(base)
        except Exception as e:
            raise ValueError("Invalid project_id (path traversal)") from e
        return candidate

    def _signals_path(self, project_id: str) -> Path:
        return self._project_dir(project_id) / SIGNALS_FILENAME

    def _load_sync(self, project_id: str) -> dict[str, SinkSignal]:
        signals_path = self._signals_path(project_id)
        if not signals_path.exists():
            return {}

        try:
            raw = json.loads(signals_path.read_text())
        except Exception:
            return {}

        items = raw.get("signals", []) if isinstance(raw, dict) else []
        loaded: dict[str, SinkSignal] = {}
        for item in items:
            try:
                signal = SinkSignal(**item)
            except Exception:
                continue
            loaded[signal.fingerprint] = signal
        return loaded

    def _save_sync(self, project_id: str, signals: dict[str, SinkSignal]) -> None:
        project_dir = self._project_dir(project_id)
        project_dir.mkdir(parents=True, exist_ok=True)

        signals_path = self._signals_path(project_id)
        payload = {
            "version": 1,
            "updated_at": datetime.utcnow().isoformat(),
            "signals": [s.model_dump(mode="json") for s in signals.values()],
        }
        signals_path.write_text(json.dumps(payload, indent=2, default=str))

    async def list_signals(
        self,
        *,
        project_id: str,
        status: Optional[SinkSignalStatus] = None,
        limit: Optional[int] = None,
    ) -> list[SinkSignal]:
        lock = self._get_lock(project_id)
        async with lock:
            signals = await asyncio.to_thread(self._load_sync, project_id)

        values = list(signals.values())
        if status is not None:
            values = [s for s in values if s.status == status]

        values.sort(key=lambda s: s.updated_at, reverse=True)
        # Apply max limit validation to prevent excessive memory usage
        limit = min(int(limit), 10000) if limit else 10000
        values = values[:limit]
        return values

    async def upsert_signals(
        self,
        *,
        project_id: str,
        signals: Iterable[SinkSignal],
    ) -> list[SinkSignal]:
        lock = self._get_lock(project_id)
        async with lock:
            existing = await asyncio.to_thread(self._load_sync, project_id)

            now = datetime.utcnow()
            updated: list[SinkSignal] = []
            for signal in signals:
                prev = existing.get(signal.fingerprint)
                if prev is None:
                    signal.created_at = now
                    signal.updated_at = now
                    existing[signal.fingerprint] = signal
                    updated.append(signal)
                    continue

                merged = prev.model_copy(deep=True)
                merged.updated_at = now
                merged.status = _merge_status(prev.status, signal.status)

                # Merge fields (prefer incoming non-empty values).
                for field in (
                    "kind",
                    "label",
                    "file_path",
                    "line_number",
                    "source",
                    "system_risk_tier",
                    "system_score",
                    "system_reasoning",
                    "llm_risk_tier",
                    "llm_score",
                    "llm_reasoning",
                ):
                    incoming = getattr(signal, field)
                    if incoming is None:
                        continue
                    if isinstance(incoming, str) and not incoming.strip():
                        continue
                    setattr(merged, field, incoming)

                merged.metadata.update(signal.metadata or {})
                existing[signal.fingerprint] = merged
                updated.append(merged)

            await asyncio.to_thread(self._save_sync, project_id, existing)

        return updated

    async def set_status(
        self,
        *,
        project_id: str,
        fingerprint: str,
        status: SinkSignalStatus,
    ) -> SinkSignal:
        lock = self._get_lock(project_id)
        async with lock:
            existing = await asyncio.to_thread(self._load_sync, project_id)

            signal = existing.get(fingerprint)
            if signal is None:
                raise ValueError("Signal not found")

            signal.status = _merge_status(signal.status, status)
            signal.updated_at = datetime.utcnow()
            existing[fingerprint] = signal

            await asyncio.to_thread(self._save_sync, project_id, existing)

        return signal


sink_signal_service = SinkSignalService()
