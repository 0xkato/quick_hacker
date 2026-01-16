# Threat Model Profile + Attacker-Controlled Anchoring (Design)

**Goal:** Stop “attacker-controlled inflation” (e.g., “repo content ⇒ attacker-controlled”) while preserving offline-first, evidence-based triage and keeping the UI compatible. This is primarily a **deterministic semantics + enforcement** upgrade (not a DB shape change).

---

## Problem Statement

Today, prompts correctly treat repo content/tool outputs as **UNTRUSTED** (prompt-injection safety), but the system lacks a hard contract for when “UNTRUSTED” becomes **attacker-controlled at runtime**. This causes:
- Noise (“shell=True everywhere”, “malicious PR ⇒ command injection” style reports).
- Wasted analysis budget (deep tracing for paths that cannot be attacker-controlled under the intended threat model).
- Unclear reviewer semantics (“what did we assume about repo checkout inputs?”).

---

## Definitions (Locked Semantics)

### 1) UNTRUSTED ≠ attacker-controlled
- **UNTRUSTED**: repo content + tool outputs are adversarial for prompt-injection safety.
- **attacker-controlled**: determined **only** by `input_channel` + enabled capabilities in the project’s `ThreatModelProfile`.

### 2) `input_channel` vocabulary
`input_channel` is required for sink signals + findings (stored in `metadata.context.input_channel`).

Enum:
`network | web_content | file_input | repo_checkout | ci_artifact | env | config | cli_args | ipc | unknown`

Deterministic split (critical):
- `repo_checkout`: repo paths + file contents + git metadata + directory listings **under the project workspace root**.
- `file_input`: external files/payloads (uploads, downloads, attachments, IPC payloads), **not** “a file in the repo”.

### 3) Execution contexts enum (strict)
`product_runtime | server_runtime | dev_tooling | ci_pipeline | test_harness | test_code | build_release`

Default policy:
- `test_code` excluded from presets by default.
- `test_harness` treated like tooling (where expected-vs-unsafe policies apply).

---

## ThreatModelProfile (Per-Project)

### Canonical stored object
Persist on the project record (file-backed: `data/projects.json`) as:
- `threat_model` (existing preset label, kept for backward compat)
- `threat_model_preset` (canonical preset label; **hard-invariant** with `threat_model`)
- `threat_model_profile` (structured sets)
- provenance + versioning fields

#### `threat_model_profile`
```json
{
  "execution_contexts": ["server_runtime", "product_runtime"],
  "attacker_capabilities": ["remote_network", "remote_web_content", "untrusted_file_input"],
  "assets": ["user_data", "credentials_secrets", "availability"]
}
```

#### Provenance + versioning
- `profile_source`: `preset | custom | migrated`
- `profile_review_status`: `unreviewed | reviewed`
- `profile_reviewed_at`: timestamp (nullable)
- `profile_mapping_version`: int (preset mapping version)
- `input_channel_semantics_version`: int (repo_checkout/file_input semantics version)
- `prompt_threat_model_block_version`: int (prompt block schema version)

### Preset mappings (A / AB / ABC)
Mappings are **stable** and never retroactively applied to existing projects. They are used only on:
- create/clone autopopulate
- explicit “Reset to preset”
- first-load migration when profile missing

Mapping:
- **A**:
  - contexts: `product_runtime`, `server_runtime`
  - caps: `remote_network`, `remote_web_content`, `untrusted_file_input`
  - assets: `user_data`, `credentials_secrets`, `availability`
- **AB**:
  - A + contexts: `dev_tooling`, `ci_pipeline`
  - assets + `integrity_of_build`
  - (still **no** `untrusted_repo_content`)
- **ABC**:
  - AB + contexts: `build_release`, `test_harness`
  - caps + `untrusted_repo_content`, `untrusted_ci_artifact`, `local_unprivileged_user`
  - assets + `integrity_of_release_artifacts`, `developer_machine_integrity`

---

## API: Canonical Endpoint + Optimistic Concurrency

### Endpoints
- `GET /api/projects/{project_id}/threat-model-profile`
  - returns the full object + `profile_hash`
- `PUT /api/projects/{project_id}/threat-model-profile`
  - tagged-union actions:
    - `reset_to_preset`
    - `save_custom`
    - `mark_reviewed`

### `expected_profile_hash` requirement (all actions)
All state-mutating actions **require** `expected_profile_hash`:
- missing → `400` (`MISSING_EXPECTED_PROFILE_HASH`, retryable)
- mismatch → `409` (`PROFILE_HASH_MISMATCH`, retryable, includes `current_profile` + `current_hash`)

Legacy compatibility:
- `PUT /api/projects/{id}` with `threat_model` remains best-effort for old clients (treated internally as `reset_to_preset` without a hash), but is logged as an **unversioned write**.

### `profile_hash` definition (authoritative “exact state reviewed”)
`profile_hash = sha256(canonical_json_bytes).hexdigest()`

Canonical hash input includes (arrays sorted, stable key order):
- `prompt_threat_model_block_version`
- `profile_mapping_version`
- `input_channel_semantics_version`
- `threat_model_preset`
- `profile_source` (LOCKED: included)
- `threat_model_profile.execution_contexts`
- `threat_model_profile.attacker_capabilities`
- `threat_model_profile.assets`

Excludes:
- `profile_review_status`
- `profile_reviewed_at`
- timestamps/UI-only fields

### `mark_reviewed`
Body:
```json
{ "action": "mark_reviewed", "expected_profile_hash": "..." }
```
Server only sets `profile_review_status="reviewed"` and `profile_reviewed_at=now()`.

Audit log (recommended): `{project_id, user_id, action, old_hash, new_hash, versions}`.

---

## UI: Per-Project Threat Model Modal

### Placement
- Per-project modal (not in global Settings).
- Header “Threat model” control is **non-destructive**:
  - selecting a different preset opens the modal in **preview mode**
  - only “Reset to preset” performs the destructive overwrite

### Header indicators
- Show an **Unreviewed** badge next to the Threat Model control when `profile_review_status=="unreviewed"`.
  - click badge → opens modal
- Keep Start Agent banner warning when unreviewed (moment-of-action reminder).

### Modal editor design
- Visual editor (default): preset preview radio + “Reset to preset” button; checkbox multi-selects; live summary.
- Advanced JSON editor (optional): strict schema validation; can only save valid JSON.
- Preset radio does **not** apply; it only changes preview selection until Reset.

### Actions
- `Reset to preset` (destructive): confirm + diff preview; sets `profile_source="preset"`, `profile_review_status="unreviewed"`.
- `Save custom` (non-destructive): validates enums; sets `profile_source="custom"`, `profile_review_status="reviewed"`.
- `Mark reviewed` (non-destructive): only available when editor is not dirty; calls `mark_reviewed`.

### Deep link (optional)
Support `?modal=threat-model` to open modal for support/debugging.

---

## Prompt Injection Block (Authoritative JSON + Server Summary)

Inject into scanner + analyzer system prompts:
1) One-screen summary (server-generated, policy-oriented)
2) Full authoritative JSON (schema-stable) in a fenced block

JSON (prompt-optimized full object):
```json
{
  "prompt_threat_model_block_version": 1,
  "profile_mapping_version": 1,
  "input_channel_semantics_version": 1,
  "threat_model_preset": "AB",
  "profile_source": "preset",
  "profile_review_status": "unreviewed",
  "threat_model_profile": {
    "execution_contexts": ["product_runtime", "server_runtime"],
    "attacker_capabilities": ["remote_network", "remote_web_content", "untrusted_file_input"],
    "assets": ["user_data", "credentials_secrets", "availability"]
  },
  "derived": {
    "attacker_controlled_input_channels": ["network", "web_content", "file_input"],
    "repo_checkout_rule": "repo_checkout attacker-controlled ONLY if untrusted_repo_content enabled; else DISPROVEN when deterministically repo_checkout"
  }
}
```

Rules:
- JSON is authoritative; the summary is generated from it (no drift).
- Scanner: **must not filter discovery** using the profile; it uses it to tag `execution_context`, `input_channel`, `activation_path`.
- Analyzer: step 0 applies capability gate; if DISPROVEN(disabled_by_profile) → stop deep tracing; record HARDENING debt.

---

## Tool Metadata Contract + Validation (Metadata-Only, Strict Schema)

Canonical metadata path:
`Finding.metadata.context.*` and `SinkSignal.metadata.context.*`

Required:
- `metadata.context.execution_context` (enum; or `"unknown"`)
- `metadata.context.input_channel` (enum; or `"unknown"`)
- `metadata.context.activation_path` (`route:|cli:|ci:|import:` prefix; bounded; no newlines; or `"unknown"`)

### Strictness by tool
- `report_finding`: **strict** (submission artifact)
  - missing/invalid context → error (retryable), especially enforced for `provider=="codex_cli"` immediately
- `upsert_sink_signal`: transitional
  - auto-fill `"unknown"` or server-infer when deterministic
  - always return + persist a warning when coerced

### Deterministic inference wins (anti-bypass)
If server can deterministically infer `input_channel` and it disagrees with caller:
- `report_finding`: hard-fail (retryable) with `INPUT_CHANNEL_MISMATCH`
- `upsert_sink_signal`: override + warn; persist both provided + inferred for audit

### v1 deterministic `repo_checkout` inference scope
Deterministic `repo_checkout` inference is enabled for high-volume repo-artifact classes where provenance can be proved from trusted inputs:
- embedded secret material in repo files/code (`HARDCODED_SECRET`-class behavior)
- repo-embedded artifacts: `.env*`, `docker-compose*`, `*.pem`, `*.key`

Constraint: determinism must be based on trusted provenance (validated workspace-root paths / tool params / WorkspacePolicy-checked reads), not LLM prose.

---

## Triage Enforcement: Capability Gate (No Wiggle)

Define a server-side binding table:
- `remote_network` → `network`
- `remote_web_content` → `web_content`
- `untrusted_file_input` → `file_input` (optionally also `ipc` if treated as file-like)
- `untrusted_repo_content` → `repo_checkout`
- `untrusted_ci_artifact` → `ci_artifact`
- `local_unprivileged_user` → `env`, `config`, `ipc`, `file_input` (explicit mapping)

Hard rule:
If `input_channel` is deterministically classified and required capability is **not** enabled:
- `source_controlled_input.status = DISPROVEN`
- `source_controlled_input.value = False`
- `source_controlled_input.reason = "Not attacker-controlled under profile (capability disabled): …"`
- disposition defaults to **HARDENING** (not BY_DESIGN)

Nuance:
- Only force DISPROVEN when `input_channel` is deterministically classified.
- If `input_channel=="unknown"`, leave checklist item UNKNOWN.

UI separation (derived, no new disposition):
`out_of_threat_model = (source_controlled_reason == "disabled_by_profile")`

---

## Observability + Tests (Minimum Set)

Metrics to track:
- `% invalid metadata` by provider/tool
- `% input_channel mismatch` (provided vs inferred) and retry success rate
- `% unversioned writes` (legacy endpoint)
- `% findings hardening(out-of-threat-model)` via `disabled_by_profile`
- time-to-review after first agent run

Tests (unit):
- profile hashing (canonicalization + includes profile_source)
- endpoint concurrency: 400/409 behaviors; 409 payload includes current profile/hash
- prompt block: summary derived from JSON; derived channels match binding table
- metadata schema validation + activation_path constraints
- deterministic inference for `.env*`, `docker-compose*`, `*.pem`, `*.key` with workspace-root provenance
