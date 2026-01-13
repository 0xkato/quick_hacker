# External Scanner Tools Design

## Goal

Add a scalable “external scanners” subsystem that runs best-in-class security tools (Semgrep/Trivy/Gitleaks/CodeQL/etc.) as sandboxed Docker jobs, persists results as **signals** (not findings), and integrates those signals into the existing agent + flow UI as a real **tree** (branching investigations).

Key requirements:
- **Scalable for more tools** over time (registry-based, generic tool-call interface).
- **LLM/agent-driven** by default (the system decides when to scan; UI can still manually trigger).
- **Offline by default** (no network in scan containers unless explicitly updating caches).
- **Signals-first** semantics (LLM promotes verified signals into Findings via classification gates).
- **Async** job model (tool calls return quickly with `run_id`).

Non-goals:
- Hardware-local execution (no Ollama-centric tool path).
- Auto-promoting scanner output into Findings without verification.

---

## High-Level Architecture

### Core components

- **ExternalToolRegistry**
  - Defines allowlisted tools: pinned image, argv template, expected output format, parser, cache config, and network policy.
  - Adding a new scanner should not require new endpoints or new agent tools.

- **ExternalScanRunner**
  - Launches ephemeral Docker containers with strict safety defaults (no network, read-only repo mount, resource limits).
  - Writes raw artifacts (logs + SARIF/JSON) to disk and normalizes outputs into DB “signals.”

- **Parsers**
  - Convert raw tool outputs into a normalized `ExternalScanSignal` shape with stable fingerprinting and severity mapping.
  - Prefer generic parsers when possible (e.g., SARIF) to reduce per-tool code.

- **ExternalScanService**
  - Orchestrates run lifecycle: create DB run record, start job, stream logs/events, parse results, compute scores, apply triage threshold, persist signals.

### LLM-facing tool surface (generic)

Instead of per-tool function names, expose a single generic interface:
- `run_external_scan(tool_key, project_id, triage_threshold?, options?) -> run_id`
- `get_scan_status(run_id) -> status/progress`
- `get_scan_results(run_id, triage_only=true) -> summary + pagination`

This keeps the agent’s tool schema stable as more scanners are added.

---

## Persistence Model

Persist scan metadata + normalized signals in Postgres, and store raw artifacts on disk.

### Table: `external_scan_runs`

One row per scan invocation:
- `id` (UUID PK)
- `user_id` (UUID FK → `users.id`)
- `project_id` (string; aligns with `ProjectService` IDs)
- `agent_id` (string, optional)
- `tool` (string; registry key)
- `status` (`queued|running|succeeded|failed|canceled`)
- `triage_mode` (initially fixed to `threshold`)
- `triage_threshold` (float)
- `threat_model` (`A|AB|ABC`) copied at run time
- `created_at`, `started_at`, `finished_at`
- `exit_code`, `error_message` (optional)
- `artifact_dir` (relative path under `DATA_DIR`)
- `tool_version` and/or `image_digest` (reproducibility)

### Table: `external_scan_signals`

Normalized outputs (many per run):
- `id` (UUID PK)
- `run_id` (UUID FK, cascade delete)
- `rule_id`, `title`, `message`, `category`, `severity`
- `file_path`, `start_line`, `end_line`
- `fingerprint` (stable dedupe key; indexable)
- `score` (float), `triage_passed` (bool)
- `evidence_ref` (pointer into artifact file + JSON path/log offsets)

### Artifact store layout

Under `DATA_DIR/external_scans/<run_id>/`:
- `meta.json` (tool/image/command/options/threat_model/repo head sha)
- `stdout.log`, `stderr.log`
- `raw.sarif` or `raw.json`
- optional: `normalized_signals.json`

This keeps DB query-friendly while enabling reproducibility and debugging.

---

## Docker Execution & Safety Contract

Scans execute as ephemeral Docker jobs with strict defaults:
- `network_mode=none` (default); only enable network for explicit cache update jobs.
- Mount repo read-only (`/work:ro`).
- Mount artifacts dir read-write (`/out`).
- Optional cache mount (`/cache`) backed by a named Docker volume per tool.
- Deny privileged mode/capabilities by default.
- Run non-root when possible.
- Enforce resource/time limits (reuse existing sandbox settings where appropriate; add scan-specific timeouts as needed).
- Allowlist only registry-defined image + argv (no arbitrary shell).

Run lifecycle:
1) Insert `external_scan_runs` (`queued`).
2) Launch container → update run (`running`, `started_at`).
3) Stream logs; write raw outputs to `/out`.
4) Parse + normalize → insert `external_scan_signals`.
5) Score + triage (threshold) → update signals and run status.

---

## Scoring, Triage (Mode B), and Promotion

### Signals-first semantics

Tool outputs become **signals**. Nothing becomes a `Finding` automatically.

### Scoring model

Each signal receives a numeric `score` used for triage:
- `base_score`: deterministic mapping from tool severity → numeric baseline.
- `context_score`: lightweight heuristics from file path and content patterns; reuse `backend/services/relevance_scorer.py` patterns to boost auth/crypto/SQL/exec/input hotspots.
- `threat_model_adjust`: bias based on project threat model (A favors public entrypoints/routes; ABC allows more insider/privilege-requiring issues to pass).
- optional `llm_score`: only for borderline candidates near the threshold (cost-controlled), asking: “is this likely exploitable under threat model X, and what concrete next validation step should run?”

Final `score` is clamped and stored. Triage mode **B**:
- `triage_passed = (score >= triage_threshold)`

### Promotion workflow

1) Agent fetches triage-passed signals for a run.
2) Agent chooses a subset to verify using internal tools (read/search/trace).
3) If verified, agent creates a real `Finding` and must run classification gates (security_issue vs misconfiguration/hardening) before persisting.

---

## Agent + UI Integration (Tree, Click-to-Investigate)

### REST API

- `POST /api/external-scans` → start scan, returns `{run_id}` immediately.
- `GET /api/external-scans?project_id=...` → list runs for current user/project.
- `GET /api/external-scans/{run_id}` → status + metadata.
- `GET /api/external-scans/{run_id}/signals` → paginated signals (default filter `triage_passed=true`).

### WebSocket + Flow tree

To fix the “continuous line” issue and make the tree meaningful:
- Create a `FlowNode(type="scan")` when a scan starts.
- When results arrive, create **child nodes** per triage-passed signal (type `investigation`) using `parent_id`.
- Clicking a node enqueues an `InvestigationTask` via `investigation_queue_service` (source=`user`).
- Agents may also auto-enqueue investigations (source=`auto`) based on their scan plan.

This makes scans a branching root with signal-driven investigative branches, not a single unchanging line.

---

## Tool Registry, Cache Updates, and Rollout

### Registry-driven tooling

Each tool entry defines:
- `key`, `image` (pinned), `argv_template`
- `parser` / `output_schema`
- `default_options`
- `network_policy` (default none)
- `cache` (volume name + mount path)

### Offline-by-default caching

Scan runs are offline. For tools needing fresh rule/vuln DBs, provide an explicit cache update job:
- `POST /api/external-scans/cache/update?tool=...`
- Runs with network enabled (explicit), updates `/cache`, records update metadata.

### Recommended initial rollout

Start with three high-value tools:
1) Semgrep (code patterns)
2) Gitleaks (secrets)
3) Trivy filesystem (deps + known vulns)

Then expand via registry entries (CodeQL, OSV, pip-audit, npm audit, language-specific linters) once runner/parsers are stable.

