"""
Prompt router for modular prompt composition.

Routes to appropriate prompt modules based on:
- Vulnerability category (SQL injection, SSRF, etc.)
- DeepAudit stage (identify_entrypoints, trace_dataflow, etc.)
- Framework context (Django, FastAPI, etc.)
"""

from dataclasses import dataclass
from typing import Optional

from prompting_loader import load_prompt


@dataclass
class PromptModules:
    """Container for prompt module paths."""
    base_prompt: str
    validity_checklist: Optional[str] = None
    stage_module: Optional[str] = None
    context_module: Optional[str] = None


class PromptRouter:
    """
    Routes to appropriate prompt modules based on context.

    Composition model: BASE_PROMPT + SELECTED_MODULES + TASK
    """

    # Mapping from vulnerability categories to validity checklist modules
    VALIDITY_CHECKLIST_MAP = {
        "SQL_INJECTION": "validity_checklists/sql_injection.md",
        "SSRF": "validity_checklists/ssrf.md",
        "CODE_INJECTION": "validity_checklists/code_injection.md",
        "COMMAND_INJECTION": "validity_checklists/command_injection.md",
        "XSS": "validity_checklists/xss.md",
        "DESERIALIZATION": "validity_checklists/deserialization.md",
        "PATH_TRAVERSAL": "validity_checklists/path_traversal.md",
        "AUTH_BYPASS": "validity_checklists/auth_idor.md",
        "IDOR": "validity_checklists/auth_idor.md",
        "MEMORY_SAFETY": "validity_checklists/memory_safety.md",
    }

    # Mapping from stage names to stage module paths
    STAGE_MODULE_MAP = {
        "identify_entrypoints": "stages/identify_entrypoints.md",
        "trace_dataflow": "stages/trace_dataflow.md",
        "validate_exploitability": "stages/validate_exploitability.md",
        "triage": "stages/triage.md",
    }

    # Mapping from framework names to context module paths
    CONTEXT_MODULE_MAP = {
        "django": "contexts/django.md",
        "fastapi": "contexts/fastapi.md",
        "flask": "contexts/flask.md",
        "express": "contexts/express.md",
    }

    # Confidence threshold for loading context modules (hard gate)
    FRAMEWORK_CONFIDENCE_THRESHOLD = 0.8

    def route(
        self,
        category: Optional[str] = None,
        stage: Optional[str] = None,
        framework: Optional[str] = None,
        framework_confidence: float = 0.0
    ) -> PromptModules:
        """
        Route to appropriate prompt modules based on context.

        Args:
            category: Vulnerability category (e.g., "SQL_INJECTION")
            stage: DeepAudit stage (e.g., "trace_dataflow")
            framework: Framework name (e.g., "django")
            framework_confidence: Confidence score for framework detection (0.0-1.0)

        Returns:
            PromptModules with paths to selected modules
        """
        # Base prompt is always included
        base_prompt = "base/base_prompt.md"

        # Validity checklist based on category
        validity_checklist = None
        if category:
            validity_checklist = self.VALIDITY_CHECKLIST_MAP.get(category)

        # Stage module for DeepAudit
        stage_module = None
        if stage:
            stage_module = self.STAGE_MODULE_MAP.get(stage)

        # Context module for framework (gated by confidence)
        context_module = None
        if framework and framework_confidence >= self.FRAMEWORK_CONFIDENCE_THRESHOLD:
            context_module = self.CONTEXT_MODULE_MAP.get(framework.lower())

        return PromptModules(
            base_prompt=base_prompt,
            validity_checklist=validity_checklist,
            stage_module=stage_module,
            context_module=context_module
        )

    def assemble_prompt(
        self,
        base_prompt: str,
        validity_checklist: Optional[str] = None,
        stage_module: Optional[str] = None,
        context_module: Optional[str] = None,
        task: str = ""
    ) -> str:
        """
        Assemble final prompt from modules using template concatenation.

        Args:
            base_prompt: Content of base prompt
            validity_checklist: Content of validity checklist (optional)
            stage_module: Content of stage module (optional)
            context_module: Content of context module (optional)
            task: Task description

        Returns:
            Final assembled prompt string
        """
        parts = [base_prompt.rstrip("\n")]

        if validity_checklist:
            parts.append(validity_checklist.rstrip("\n"))

        if stage_module:
            parts.append(stage_module.rstrip("\n"))

        if context_module:
            parts.append(context_module.rstrip("\n"))

        if task:
            parts.append(task.rstrip("\n"))

        return "\n\n".join(parts) + "\n"

    def assemble_from_paths(
        self,
        modules: PromptModules,
        task: str = ""
    ) -> str:
        """
        Load and assemble prompt from module paths.

        Args:
            modules: PromptModules with paths to load
            task: Task description

        Returns:
            Final assembled prompt string
        """
        base_content = load_prompt(modules.base_prompt)

        validity_content = None
        if modules.validity_checklist:
            validity_content = load_prompt(modules.validity_checklist)

        stage_content = None
        if modules.stage_module:
            stage_content = load_prompt(modules.stage_module)

        context_content = None
        if modules.context_module:
            context_content = load_prompt(modules.context_module)

        return self.assemble_prompt(
            base_prompt=base_content,
            validity_checklist=validity_content,
            stage_module=stage_content,
            context_module=context_content,
            task=task
        )
