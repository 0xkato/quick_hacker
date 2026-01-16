"""
Tool execution context for First-Party Focus.

Provides scope filtering and budget management without changing tool schemas.
Keeps tool schemas unchanged (preserves Claude SDK compatibility).
"""

from typing import TYPE_CHECKING
from pydantic import BaseModel
from models.schemas import ProjectScope

if TYPE_CHECKING:
    from services.tool_budget_manager import ToolBudgetManager


class ToolExecutionContext(BaseModel):
    """
    Context passed to all tools for scope filtering and budget attribution.

    This keeps tool schemas unchanged (preserves Claude SDK compatibility).
    Tools can access project scope and budget manager through this context.
    """
    project_id: str
    repo_root: str
    project_scope: ProjectScope | None = None
    budget_manager: "ToolBudgetManager | None" = None

    class Config:
        arbitrary_types_allowed = True
