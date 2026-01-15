"""Services for quick_hack backend.

This package intentionally avoids importing heavy submodules at import-time to
prevent circular-import issues (e.g. `models.schemas` importing a lightweight
service utility).

Access submodules directly (recommended):
  - `from services.git_service import ...`
  - `from services.tool_core import ToolCore`

Or via these lazy exports:
  - `from services import git_service, file_service`
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = ["git_service", "file_service", "ToolCore", "ClaudeSDKOrchestrator", "SCAN_TIER_BUDGETS"]


def __getattr__(name: str) -> Any:  # pragma: no cover - exercised indirectly
    if name in ("git_service", "file_service"):
        return import_module(f"{__name__}.{name}")
    if name == "ToolCore":
        return getattr(import_module(f"{__name__}.tool_core"), name)
    if name in ("ClaudeSDKOrchestrator", "SCAN_TIER_BUDGETS"):
        mod = import_module(f"{__name__}.claude_sdk_orchestrator")
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
