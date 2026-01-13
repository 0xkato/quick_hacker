# Agent Prompt Integration Guide

## Overview

This document explains how agents use the prompting system (PromptRouter, validity checklists) to generate category-specific prompts for vulnerability analysis.

## Architecture

```
Agent detects category (SQL_INJECTION, XSS, etc.)
  ↓
PromptRouter.route(category="SQL_INJECTION", stage="trace_dataflow")
  ↓
Returns PromptModules(base, validity_checklist, stage, context)
  ↓
PromptRouter.assemble_from_paths(modules, task="...")
  ↓
Returns assembled prompt: base + validity_checklist + stage + task
  ↓
Agent sends to LLM
  ↓
StrictClassifier evaluates response
  ↓
Returns ProofChecklist with tri-state status for each item
  ↓
UI displays detailed checklist with visual indicators
```

## Adding a New Agent Type

1. Import PromptRouter:
   ```python
   from services.prompt_router import PromptRouter
   ```

2. Detect or receive category:
   ```python
   category = self._detect_category()  # or passed as parameter
   ```

3. Assemble prompt:
   ```python
   router = PromptRouter()
   modules = router.route(category=category, stage="identify_entrypoints")
   prompt = router.assemble_from_paths(modules, task="Find entry points")
   ```

4. Use prompt with LLM:
   ```python
   response = llm.complete(prompt)
   ```

## Supported Categories

- SQL_INJECTION
- SSRF
- CODE_INJECTION
- COMMAND_INJECTION
- XSS
- DESERIALIZATION
- PATH_TRAVERSAL
- AUTH_BYPASS
- IDOR
- MEMORY_SAFETY

See `backend/services/prompt_router.py` for complete mapping.
