# Threat Model Profile Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement per-project `ThreatModelProfile` + deterministic “attacker-controlled” semantics (UNTRUSTED ≠ attacker-controlled), including API + UI + prompt injection block + enforcement in tools + triage, without breaking existing frontend API shapes.

**Architecture:** Persist a structured threat model profile on each project (file-backed `data/projects.json`) with stable preset mappings (A/AB/ABC), provenance (`profile_source`, `profile_review_status`), and version stamps. Generate a `profile_hash` (optimistic concurrency) and inject a server-generated Threat Model Prompt Block (summary + authoritative JSON) into scanner/analyzer prompts. Enforce “attacker-controlled” via a deterministic `input_channel` enum + capability binding table; when capability is disabled, force `source_controlled_input=DISPROVEN` with reason `disabled_by_profile` and default disposition `HARDENING`.

**Tech Stack:** FastAPI + Pydantic (backend), Next.js App Router + TypeScript (frontend), existing PromptingLoader + StrictClassifier + FindingTriageService + ToolCore.

---

## Task 1: Add ThreatModelProfile schema + hashing utilities (backend)

**Files:**
- Create: `backend/models/threat_model_profile.py`
- Test: `backend/tests/models/test_threat_model_profile.py`

**Step 1: Write failing tests for preset mapping + canonical hashing**

Create `backend/tests/models/test_threat_model_profile.py`:

```python
from models.threat_model_profile import (
    ThreatModelPreset,
    ThreatModelProfile,
    preset_to_profile,
    compute_profile_hash,
)


def test_preset_mapping_ab_does_not_enable_untrusted_repo_content():
    profile = preset_to_profile(ThreatModelPreset.AB)
    assert "untrusted_repo_content" not in profile.attacker_capabilities


def test_profile_hash_changes_when_profile_source_changes():
    profile = ThreatModelProfile(
        execution_contexts=["product_runtime"],
        attacker_capabilities=["remote_network"],
        assets=["user_data"],
    )
    h1 = compute_profile_hash(
        threat_model_preset="A",
        profile_source="preset",
        profile_mapping_version=1,
        input_channel_semantics_version=1,
        prompt_threat_model_block_version=1,
        threat_model_profile=profile,
    )
    h2 = compute_profile_hash(
        threat_model_preset="A",
        profile_source="custom",
        profile_mapping_version=1,
        input_channel_semantics_version=1,
        prompt_threat_model_block_version=1,
        threat_model_profile=profile,
    )
    assert h1 != h2
```

**Step 2: Run the tests and confirm they fail**

Run: `cd backend && python -m pytest tests/models/test_threat_model_profile.py -q`
Expected: FAIL (module doesn’t exist yet).

**Step 3: Implement `backend/models/threat_model_profile.py` (minimal to satisfy tests)**

Create `backend/models/threat_model_profile.py`:

```python
from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


ThreatModelPreset = Literal["A", "AB", "ABC"]
ProfileSource = Literal["preset", "custom", "migrated"]
ProfileReviewStatus = Literal["unreviewed", "reviewed"]

ExecutionContext = Literal[
    "product_runtime",
    "server_runtime",
    "dev_tooling",
    "ci_pipeline",
    "test_harness",
    "test_code",
    "build_release",
]

AttackerCapability = Literal[
    "remote_network",
    "remote_web_content",
    "untrusted_file_input",
    "untrusted_repo_content",
    "untrusted_ci_artifact",
    "local_unprivileged_user",
]

Asset = Literal[
    "user_data",
    "credentials_secrets",
    "availability",
    "integrity_of_build",
    "integrity_of_release_artifacts",
    "developer_machine_integrity",
]


class ThreatModelProfile(BaseModel):
    execution_contexts: list[ExecutionContext] = Field(default_factory=list)
    attacker_capabilities: list[AttackerCapability] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)


def preset_to_profile(preset: ThreatModelPreset) -> ThreatModelProfile:
    if preset == "A":
        return ThreatModelProfile(
            execution_contexts=["product_runtime", "server_runtime"],
            attacker_capabilities=["remote_network", "remote_web_content", "untrusted_file_input"],
            assets=["user_data", "credentials_secrets", "availability"],
        )
    if preset == "AB":
        return ThreatModelProfile(
            execution_contexts=["product_runtime", "server_runtime", "dev_tooling", "ci_pipeline"],
            attacker_capabilities=["remote_network", "remote_web_content", "untrusted_file_input"],
            assets=["user_data", "credentials_secrets", "availability", "integrity_of_build"],
        )
    return ThreatModelProfile(
        execution_contexts=["product_runtime", "server_runtime", "dev_tooling", "ci_pipeline", "build_release", "test_harness"],
        attacker_capabilities=[
            "remote_network",
            "remote_web_content",
            "untrusted_file_input",
            "untrusted_repo_content",
            "untrusted_ci_artifact",
            "local_unprivileged_user",
        ],
        assets=[
            "user_data",
            "credentials_secrets",
            "availability",
            "integrity_of_build",
            "integrity_of_release_artifacts",
            "developer_machine_integrity",
        ],
    )


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_profile_hash(
    *,
    threat_model_preset: ThreatModelPreset,
    profile_source: ProfileSource,
    profile_mapping_version: int,
    input_channel_semantics_version: int,
    prompt_threat_model_block_version: int,
    threat_model_profile: ThreatModelProfile,
) -> str:
    payload = {
        "prompt_threat_model_block_version": int(prompt_threat_model_block_version),
        "profile_mapping_version": int(profile_mapping_version),
        "input_channel_semantics_version": int(input_channel_semantics_version),
        "threat_model_preset": threat_model_preset,
        "profile_source": profile_source,
        "threat_model_profile": {
            "execution_contexts": sorted(threat_model_profile.execution_contexts),
            "attacker_capabilities": sorted(threat_model_profile.attacker_capabilities),
            "assets": sorted(threat_model_profile.assets),
        },
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
```

**Step 4: Run tests**

Run: `cd backend && python -m pytest tests/models/test_threat_model_profile.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add backend/models/threat_model_profile.py backend/tests/models/test_threat_model_profile.py
git commit -m "feat(threat-model): add profile schema + canonical hash"
```

---

## Task 2: Persist profile on projects + migrate existing records (backend)

**Files:**
- Modify: `backend/services/project_service.py`
- Test: `backend/tests/services/test_project_service_threat_model_profile.py`

**Step 1: Write failing migration/autopopulate tests**

Create `backend/tests/services/test_project_service_threat_model_profile.py`:

```python
import json
from pathlib import Path

import pytest

from services.project_service import ProjectService


@pytest.mark.asyncio
async def test_create_project_autopopulates_threat_model_profile(tmp_path: Path):
    svc = ProjectService(data_dir=str(tmp_path))
    await svc.initialize()
    project = await svc.create_project(name="x")
    assert project.threat_model_preset == project.threat_model
    assert project.threat_model_profile is not None
    assert project.profile_review_status == "unreviewed"


@pytest.mark.asyncio
async def test_load_projects_migrates_missing_profile_fields(tmp_path: Path):
    data_dir = tmp_path
    projects_file = data_dir / "projects.json"
    projects_file.write_text(
        json.dumps({"projects": [{"id": "p1", "name": "p", "threat_model": "AB", "path": str(tmp_path / "projects" / "p1")}]})
    )
    svc = ProjectService(data_dir=str(data_dir))
    await svc.initialize()
    proj = await svc.get_project("p1")
    assert proj is not None
    assert proj.threat_model_preset == "AB"
    assert proj.threat_model_profile is not None
```

**Step 2: Run tests**

Run: `cd backend && python -m pytest tests/services/test_project_service_threat_model_profile.py -q`
Expected: FAIL (fields don’t exist yet).

**Step 3: Update `Project` model to include new fields + migration on load**

In `backend/services/project_service.py`:
- Add new optional fields to `Project`:
  - `threat_model_preset`
  - `threat_model_profile`
  - `profile_source`
  - `profile_review_status`
  - `profile_reviewed_at`
  - `profile_mapping_version`
  - `input_channel_semantics_version`
  - `prompt_threat_model_block_version`
- In `_load_projects()`: if fields missing, compute via preset mapping and set:
  - `profile_source="migrated"`
  - `profile_review_status="unreviewed"`
- In `create_project()` / `clone_into_project()` / `quick_clone`: auto-populate from preset mapping and set `profile_source="preset"`.
- Keep hard invariant: `threat_model == threat_model_preset` (write both together).

**Step 4: Run tests**

Run: `cd backend && python -m pytest tests/services/test_project_service_threat_model_profile.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add backend/services/project_service.py backend/tests/services/test_project_service_threat_model_profile.py
git commit -m "feat(threat-model): persist + migrate per-project profiles"
```

---

## Task 3: Add canonical API endpoint with optimistic concurrency (backend)

**Files:**
- Modify: `backend/routers/projects.py`
- Test: `backend/tests/routers/test_project_threat_model_profile_api.py`

**Step 1: Add failing API tests (400 on missing hash, 409 on mismatch)**

Create `backend/tests/routers/test_project_threat_model_profile_api.py` with a minimal FastAPI TestClient boot using dependency overrides (pattern exists in `backend/tests/integration/*`).

Key assertions:
- `GET /api/projects/{id}/threat-model-profile` returns `profile_hash`.
- `PUT ... {action:"mark_reviewed"}` without `expected_profile_hash` → `400` with `error_code="MISSING_EXPECTED_PROFILE_HASH"`.
- `PUT ...` with wrong hash → `409` with `error_code="PROFILE_HASH_MISMATCH"` and includes `current_profile_hash`.

**Step 2: Implement endpoints**

In `backend/routers/projects.py`:
- Add:
  - `GET /projects/{project_id}/threat-model-profile`
  - `PUT /projects/{project_id}/threat-model-profile`
- Implement action union:
  - `reset_to_preset` (requires preset + expected hash)
  - `save_custom` (requires preset + profile object + expected hash)
  - `mark_reviewed` (requires expected hash)
- Compute/return `profile_hash` using `compute_profile_hash(...)`.
- Return structured errors:
  - 400: `{ "error_code": "MISSING_EXPECTED_PROFILE_HASH", "retryable": true }`
  - 409: `{ "error_code": "PROFILE_HASH_MISMATCH", "retryable": true, "current_profile": {...}, "current_profile_hash": "..." }`
- Log legacy `PUT /projects/{id}` writes as “unversioned write” when `threat_model` changes without the canonical endpoint.

**Step 3: Run tests**

Run: `cd backend && python -m pytest tests/routers/test_project_threat_model_profile_api.py -q`
Expected: PASS.

**Step 4: Commit**

```bash
git add backend/routers/projects.py backend/tests/routers/test_project_threat_model_profile_api.py
git commit -m "feat(api): add threat-model-profile endpoint with hash concurrency"
```

---

## Task 4: Generate Threat Model Prompt Block and inject into prompts (backend)

**Files:**
- Create: `backend/services/threat_model_prompt_block.py`
- Modify: `backend/services/agent_orchestrator.py`
- Modify: `prompting/base/base_prompt.md`
- Test: `backend/tests/services/test_threat_model_prompt_block.py`

**Step 1: Add tests for summary↔JSON consistency + derived channels**

Create `backend/tests/services/test_threat_model_prompt_block.py`:

```python
import json

from services.threat_model_prompt_block import build_threat_model_prompt_block


def test_prompt_block_contains_authoritative_json_and_summary():
    block = build_threat_model_prompt_block(
        threat_model_preset="AB",
        profile_source="preset",
        profile_review_status="unreviewed",
        execution_contexts=["product_runtime"],
        attacker_capabilities=["remote_network", "untrusted_file_input"],
        assets=["user_data"],
    )
    assert "=== THREAT MODEL (AUTHORITATIVE) ===" in block
    assert "```json" in block
    json_start = block.index("```json") + len("```json")
    json_end = block.index("```", json_start)
    payload = json.loads(block[json_start:json_end])
    assert "derived" in payload
    assert "file_input" in payload["derived"]["attacker_controlled_input_channels"]
```

**Step 2: Implement `build_threat_model_prompt_block()`**

Create `backend/services/threat_model_prompt_block.py`:
- Accept the effective profile + provenance + versions.
- Compute `derived.attacker_controlled_input_channels` via binding table:
  - remote_network → network
  - remote_web_content → web_content
  - untrusted_file_input → file_input
  - untrusted_repo_content → repo_checkout
  - untrusted_ci_artifact → ci_artifact
  - local_unprivileged_user → env/config/ipc/file_input
- Generate:
  - minimal summary (1 screen)
  - fenced JSON blob (authoritative)

**Step 3: Inject into prompts**

In `backend/services/agent_orchestrator.py`:
- When building prompts (scanner/analyzer, codex_cli and legacy providers), inject the block near the top (after base prompt) so models can’t miss the semantics.
- Ensure scanner uses it for tagging (not filtering discovery).
- Ensure analyzer does “step 0” (early discard) guidance is present.

In `prompting/base/base_prompt.md`:
- Update definition of `source_controlled_input`:
  - PROVEN_FALSE includes “not attacker-controlled under enabled ThreatModelProfile for this input_channel”.
  - Add explicit line: “UNTRUSTED for prompt safety ≠ attacker-controlled”.

**Step 4: Run tests**

Run: `cd backend && python -m pytest tests/services/test_threat_model_prompt_block.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add backend/services/threat_model_prompt_block.py backend/services/agent_orchestrator.py prompting/base/base_prompt.md backend/tests/services/test_threat_model_prompt_block.py
git commit -m "feat(prompting): inject authoritative threat model block into turns"
```

---

## Task 5: Enforce input_channel + capability gate in triage + tool validation (backend)

**Files:**
- Create: `backend/models/threat_context.py`
- Modify: `backend/services/tool_core.py`
- Modify: `backend/services/finding_triage_service.py`
- Modify: `backend/services/strict_classifier.py`
- Test: `backend/tests/services/test_input_channel_inference_and_gates.py`

**Step 1: Add failing tests for “repo_checkout gated unless untrusted_repo_content”**

Create `backend/tests/services/test_input_channel_inference_and_gates.py`:

Assertions:
- A finding about `docker-compose.yml` (workspace-root path) must be treated as `repo_checkout` deterministically.
- Under preset AB (no `untrusted_repo_content`), `source_controlled_input` becomes DISPROVEN with reason containing `disabled_by_profile`.
- Disposition defaults to HARDENING (not BY_DESIGN).

**Step 2: Add strict typed context schema**

Create `backend/models/threat_context.py` with:
- `InputChannel` enum (locked)
- `ExecutionContext` enum (locked)
- `ThreatContextMetadata` Pydantic model with:
  - `context.execution_context`
  - `context.input_channel`
  - `context.activation_path` (prefix + length constrained)
  - `validation_status`, `validation_warning`, `provided_input_channel`, `inferred_input_channel` (optional)

**Step 3: Update ToolCore report_finding/upsert_sink_signal**

In `backend/services/tool_core.py`:
- Add optional `metadata: dict | None` parameter to `report_finding`.
- Validate `metadata.context.*` for `report_finding`:
  - hard fail with structured error payload on missing/invalid fields
  - hard fail when deterministic input_channel inference disagrees (retryable `INPUT_CHANNEL_MISMATCH`)
- For `upsert_sink_signal`:
  - if deterministic inference disagrees, override to inferred + warn (persist provided vs inferred)
- v1 deterministic inference triggers only on trusted provenance:
  - paths under workspace root + repo-embedded sensitive material artifacts: `.env*`, `docker-compose*`, `*.pem`, `*.key`
  - never based on LLM prose

**Step 4: Wire capability gate into triage**

Update `FindingTriageService.triage_findings(...)` to accept `project_id` (or to fetch profile from project_service via `repo_id`) and pass effective profile into `StrictClassifier`.

Update `StrictClassifier._evaluate_source_controlled_input(...)`:
- If `metadata.context.input_channel` is deterministically classified and the profile does not enable the capability for that channel:
  - return DISPROVEN with reason “disabled_by_profile”
- Otherwise keep existing evidence-based logic.

Rule: only force DISPROVEN when channel deterministic; if channel is unknown, keep UNKNOWN.

**Step 5: Run tests**

Run: `cd backend && python -m pytest tests/services/test_input_channel_inference_and_gates.py -q`
Expected: PASS.

**Step 6: Commit**

```bash
git add backend/models/threat_context.py backend/services/tool_core.py backend/services/finding_triage_service.py backend/services/strict_classifier.py backend/tests/services/test_input_channel_inference_and_gates.py
git commit -m "feat(triage): gate attacker-control by input_channel + profile caps"
```

---

## Task 6: Implement per-project Threat Model modal + non-destructive header control (frontend)

**Files:**
- Create: `frontend/components/ThreatModel/ThreatModelModal.tsx`
- Modify: `frontend/app/page.tsx`
- Modify: `frontend/lib/api.ts`
- Modify: `frontend/types/index.ts` (or local types)

**Step 1: Add API client for threat-model-profile**

In `frontend/lib/api.ts` add:
- `projects.getThreatModelProfile(projectId)`
- `projects.updateThreatModelProfile(projectId, payload)` for actions:
  - reset_to_preset
  - save_custom
  - mark_reviewed

Include `expected_profile_hash` on every PUT action.

**Step 2: Build modal UI (visual editor + advanced JSON editor)**

Implement `ThreatModelModal` with:
- preset preview radio (non-destructive)
- “Reset to preset” (destructive confirm, calls reset_to_preset)
- checkbox multi-select for contexts/caps/assets
- optional JSON editor with schema validation
- “Mark reviewed” button (non-destructive) that calls mark_reviewed with current hash
- 409 handling: refresh current + keep user edits (rebase UI)

**Step 3: Wire header control to open modal (preview mode)**

In `frontend/app/page.tsx`:
- Replace destructive `<select onChange=handleThreatModelChange>` with:
  - selecting a preset opens modal with that preset selected as preview
  - no write happens until “Reset to preset”
- Show “Unreviewed” badge next to control when profile_review_status==unreviewed (click opens modal).
- Keep Start Agent warning banner (in start flow) when unreviewed.

**Step 4: Manual verification**

Run:
- `cd frontend && npm run lint`

**Step 5: Commit**

```bash
git add frontend/lib/api.ts frontend/app/page.tsx frontend/components/ThreatModel/ThreatModelModal.tsx frontend/types/index.ts
git commit -m "feat(ui): add per-project threat model modal + unreviewed badge"
```

---

## Task 7: Update existing integration tests + run full verification

**Files:**
- Modify: `backend/tests/integration/test_codex_cli_agent_api_integration.py`
- Modify/Add: any unit tests broken by strict report_finding metadata

**Step 1: Update Codex CLI integration test to include required metadata.context**

In `backend/tests/integration/test_codex_cli_agent_api_integration.py`, when calling `tool_core.report_finding(...)`, include:

```python
metadata={
  "context": {
    "execution_context": "server_runtime",
    "input_channel": "network",
    "activation_path": "route:/api/..."
  }
}
```

**Step 2: Run backend tests**

Run: `cd backend && python -m pytest -q`
Expected: PASS.

**Step 3: Run frontend lint/build**

Run:
- `cd frontend && npm run lint`
- `cd frontend && npm run build`

**Step 4: Final commit (if any)**

```bash
git status
git add -A
git commit -m "test: update codex integration for threat model metadata"
```

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-01-16-threat-model-profile-implementation-plan.md`.

Two execution options:

1. **Subagent-Driven (this session)** — not available in Codex yet; I can still execute tasks sequentially in this session with review checkpoints.
2. **Parallel Session** — open a new session and use `superpowers:executing-plans` to run task-by-task.

Which approach do you want?

