"""Backward compatibility shim for tool_core module.

DEPRECATED: This module is deprecated. Import directly from services.tool_core package instead.

The monolithic tool_core.py has been split into focused modules:
- services/tool_core/file_operations.py: File and directory operations
- services/tool_core/ast_analysis.py: AST parsing and dataflow tracing
- services/tool_core/security_scanning.py: Security scanning operations
- services/tool_core/sink_signals.py: Sink signal management
- services/tool_core/finding_management.py: Finding reporting and triaging
- services/tool_core/flow_tracking.py: Investigation flow tracking
- services/tool_core/validity.py: Validity checklists and finalization

Usage:
    # Old (still works but deprecated):
    from services.tool_core import ToolCore

    # New (recommended):
    from services.tool_core import ToolCore  # Same import, refactored implementation
"""
import warnings

# Emit deprecation warning
warnings.warn(
    "Importing from services.tool_core is deprecated. "
    "The module has been refactored into services.tool_core package. "
    "Update imports to: from services.tool_core import ToolCore",
    DeprecationWarning,
    stacklevel=2
)

# Re-export from new location for backward compatibility
from services.tool_core import ToolCore

__all__ = ["ToolCore"]
