"""Security auditing agents for quick_hack."""

from .base_agent import BaseAgent
from .deep_audit import DeepAuditSupervisor

__all__ = [
    "BaseAgent",
    "DeepAuditSupervisor",
]
