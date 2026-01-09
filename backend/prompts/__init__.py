"""Security prompts for quick_hack agents.

Three-layer prompt architecture:
1. hard_rules.py - System prompt with safety rules + output contract (stable)
2. workflow_engine.py - Developer prompt with workflow + depth/coverage (editable)
3. run_config.py - User prompt template per audit run (changes per run)
"""

# Legacy exports (keep for backwards compatibility)
from .system_prompts import get_system_prompt, LANGUAGE_PATTERNS, FRAMEWORK_PATTERNS

# New 3-layer architecture
from .hard_rules import get_system_prompt as get_hard_rules_prompt, SYSTEM_PROMPT_V2
from .workflow_engine import (
    get_developer_prompt,
    get_sink_families,
    DEVELOPER_PROMPT_V2,
    SINK_FAMILIES,
)
from .run_config import (
    RunConfig,
    generate_run_prompt,
    create_run_config_from_project,
)
from .classification_gate import (
    CLASSIFICATION_RULES,
    CLASSIFICATION_GATE_TEMPLATE,
    get_classification_gate_prompt,
)

__all__ = [
    # Legacy
    "get_system_prompt",
    "LANGUAGE_PATTERNS",
    "FRAMEWORK_PATTERNS",
    # Layer 1: Hard Rules
    "get_hard_rules_prompt",
    "SYSTEM_PROMPT_V2",
    # Layer 2: Workflow Engine
    "get_developer_prompt",
    "get_sink_families",
    "DEVELOPER_PROMPT_V2",
    "SINK_FAMILIES",
    # Layer 3: Run Config
    "RunConfig",
    "generate_run_prompt",
    "create_run_config_from_project",
    # Classification Gate
    "CLASSIFICATION_RULES",
    "CLASSIFICATION_GATE_TEMPLATE",
    "get_classification_gate_prompt",
]
