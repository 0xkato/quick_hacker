# Campaign Platform Steps 5-9 — Execution, Evidence, Steering, Issues, Frontend

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the campaign platform: run Schemathesis lanes against live targets, bucket/replay/minimize artifacts, gate issues with proof checklists, add steering, and build the frontend views.

**Architecture:** Dramatiq workers pull jobs from Redis queues. Fuzz worker launches target from repo Compose into a per-campaign Docker network, runs Schemathesis harness. Bucketer deduplicates raw failures. Replay worker reproduces and minimizes. Issue gating enforces proof checklist. Steering monitors metrics and revises lanes. Frontend gets new views for Targets, Campaigns, Coverage, Failures, Findings, Steering.

**Tech Stack:** Dramatiq workers, Docker SDK (docker-py), Schemathesis CLI, Python 3.12, Next.js/React/TypeScript

**Worktree:** `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot`

---

## STEP 5: Execution Path

### Task 1: Run Lane Service

**Files:**
- Create: `backend/services/run_lane_service.py`
- Test: `backend/tests/services/test_run_lane_service.py`

CRUD for run_lane records. Methods: `create_run(lane_spec_id, execution_bundle_id, resource_profile, timeout_seconds, ...) -> RunLaneResponse`, `get_run(run_id)`, `list_runs(lane_spec_id)`, `update_run_status(run_id, status, **kwargs)`. Same mocked-DB pattern as other services. Import `RunLane as DBRunLane` from `database.campaign_models`.

Commit: `feat: add run lane service`

---

### Task 2: Coverage Service

**Files:**
- Create: `backend/services/coverage_service.py`
- Test: `backend/tests/services/test_coverage_service.py`

Store and query API-surface coverage snapshots. Methods: `record_snapshot(run_lane_id, snapshot_data: dict)`, `get_campaign_coverage(campaign_id) -> dict` (aggregate across all runs), `get_lane_coverage(lane_spec_id) -> dict`. snapshot_data contains: `operations_hit`, `parameters_exercised`, `status_classes`, `sequence_depth`, `validity_ratio`, `requests_per_sec`. Import `CoverageSnapshot as DBCoverageSnapshot` from campaign models.

Commit: `feat: add coverage service`

---

### Task 3: Schemathesis Engine Adapter

**Files:**
- Create: `backend/execution/engines/__init__.py`
- Create: `backend/execution/engines/engine_interface.py`
- Create: `backend/execution/engines/schemathesis_engine.py`
- Test: `backend/tests/execution/test_schemathesis_engine.py`

`EngineInterface` abstract base: `run(harness_path, base_url, timeout_seconds, **kwargs) -> EngineResult`. `EngineResult` dataclass: `success: bool`, `metrics: dict`, `artifact_candidates: list[dict]`, `corpus_path: str | None`, `errors: list[str]`.

`SchemathesisEngine(EngineInterface)`: Runs Schemathesis via `subprocess.run` with the compiled harness module. Parses stdout/stderr for failures. Collects coverage metrics from Schemathesis output. Returns `EngineResult`.

For v1: uses `schemathesis run` CLI command with `--hypothesis-seed` for reproducibility, `--stateful=links` for stateful targets. Captures exit code (0=pass, 1=failures found, 2=errors).

Tests mock subprocess.run. Test: success case returns metrics, failure case returns artifact candidates, error case returns errors.

Commit: `feat: add Schemathesis engine adapter`

---

### Task 4: Docker Network Manager

**Files:**
- Create: `backend/execution/docker_manager.py`
- Test: `backend/tests/execution/test_docker_manager.py`

Manages per-campaign Docker networks and target stack lifecycle.

`DockerNetworkManager`:
- `create_campaign_network(campaign_id) -> str` (network name)
- `launch_target_stack(campaign_id, compose_path, env_vars=None) -> TargetStackInfo` (base_url, container_ids)
- `wait_for_healthy(base_url, timeout=30) -> bool`
- `teardown_target_stack(campaign_id)`
- `teardown_network(campaign_id)`

`TargetStackInfo` dataclass: `base_url`, `network_name`, `container_ids`, `compose_path`.

For v1: uses `docker` Python SDK to create network `qh_{campaign_id}`, run `docker compose up -d` in the network, poll health endpoint. Internet egress blocked by default (network internal=True).

Tests mock the docker client. Test: network creation, target launch, health check polling, teardown.

Add `docker>=7.0.0` to requirements.txt if not present.

Commit: `feat: add Docker network manager for campaign isolation`

---

### Task 5: Fuzz Worker (Dramatiq Actor)

**Files:**
- Create: `backend/execution/workers/fuzz_worker.py`
- Test: `backend/tests/execution/test_fuzz_worker.py`

Dramatiq actor that processes `RunLaneJob`:

```python
@dramatiq.actor(queue_name=QUEUE_FUZZ)
def run_lane_job(job_data: dict):
    """Execute a methodology lane against a live target.

    1. Fetch execution bundle from DB
    2. Download harness code from artifact store
    3. Create campaign Docker network (if not exists)
    4. Launch target stack from Compose
    5. Wait for target healthy
    6. Run Schemathesis engine with harness
    7. Collect metrics, stream coverage snapshots
    8. For each failure: create raw artifact candidate
    9. Upload corpus to artifact store
    10. Update run_lane status to completed/failed
    """
```

Tests mock everything (no real Docker or Schemathesis). Test: happy path creates run + updates status, target unhealthy → run fails, engine failure → run fails with error.

Commit: `feat: add fuzz worker Dramatiq actor`

---

### Task 6: Extend Controller — Execute Phase

**Files:**
- Modify: `backend/campaigns/controller.py`
- Test: `backend/tests/campaigns/test_controller.py` (add tests)

Add `execute_campaign(campaign_id)` that:
1. Gets all validated execution bundles for the campaign
2. For each bundle: creates a RunLane record (status=queued), enqueues `RunLaneJob` via Dramatiq
3. Updates campaign status to RUNNING

Also extend `start_campaign` to chain: plan → compile → execute.

For v1: jobs are enqueued but actual worker execution happens separately (workers must be running).

Tests mock Dramatiq message sending. Test: execute creates run records, enqueues jobs, transitions status.

Commit: `feat: extend controller with execute phase`

---

## STEP 6: Evidence

### Task 7: Artifact Service

**Files:**
- Create: `backend/services/artifact_service.py`
- Test: `backend/tests/services/test_artifact_service.py`

CRUD for artifacts and artifact buckets. Methods: `create_artifact(run_lane_id, type, bucket_key, ...) -> ArtifactResponse`, `get_artifact(artifact_id)`, `list_artifacts(campaign_id)`, `update_classification(artifact_id, classification, analysis_outcome)`, `create_or_update_bucket(campaign_id, bucket_key, artifact_type)`, `list_buckets(campaign_id)`.

Commit: `feat: add artifact and bucket service`

---

### Task 8: Artifact Bucketer

**Files:**
- Create: `backend/evidence/__init__.py`
- Create: `backend/evidence/bucketer.py`
- Test: `backend/tests/evidence/test_bucketer.py`

Takes raw artifact candidates from fuzz worker, normalizes them, computes bucket keys, deduplicates.

`compute_bucket_key(artifact_candidate: dict) -> str`: Hash based on error type + endpoint + status code (or stack trace pattern for crashes). Similar artifacts get the same bucket.

`should_replay(bucket_key, existing_bucket) -> bool`: New bucket = always replay. Existing bucket with < 3 artifacts = replay. Existing bucket with 3+ = skip unless stability_score is low.

`process_raw_artifact(campaign_id, run_lane_id, candidate: dict) -> Artifact | None`: Create artifact record, update bucket, decide if replay needed, return artifact or None.

Tests: same endpoint + same error → same bucket key, different errors → different buckets, dedup threshold works.

Commit: `feat: add artifact bucketer with deduplication`

---

### Task 9: Replay Service

**Files:**
- Create: `backend/services/replay_service.py`
- Create: `backend/evidence/replayer.py`
- Test: `backend/tests/evidence/test_replayer.py`

`ReplayService`: CRUD for replay_runs table. `create_replay_run(artifact_id, status)`, `update_replay_run(replay_id, status, stability_score, result)`.

`Replayer`:
- `replay_artifact(artifact, execution_bundle, base_url) -> ReplayResult`
- `ReplayResult` dataclass: `reproduced: bool`, `stability_score: float`, `attempts: int`, `errors: list[str]`
- Logic: re-send the request/input from the artifact against the target, check if same failure occurs. Run 3 times for initial gate, then N times for stability score.

Tests mock HTTP calls. Test: reproduced=True when same error, reproduced=False when different response, stability scoring.

Commit: `feat: add replay service and replayer`

---

### Task 10: Issue Gating

**Files:**
- Create: `backend/issues/__init__.py`
- Create: `backend/issues/gating.py`
- Test: `backend/tests/issues/test_gating.py`

Implements the proof checklist enforcement from the design doc.

```python
def evaluate_proof(checklist: ProofChecklist) -> IssueGatingResult:
    """Apply core evidence gates + classification gates.

    Returns: disposition, reasoning
    """
```

`IssueGatingResult` dataclass: `disposition: str`, `reasoning: list[str]`, `is_issue: bool`.

Logic (from design doc):
- Core gates (7): target_real, harness_validated, real_code_reached, reproduced_cleanly, artifact_minimization_attempted, not_harness_artifact, not_test_only
- Classification gates (3): external_input_controlled, oracle_triggered_or_sanitizer_hit, security_impact_confirmed
- Core pass + security → CONFIRMED_SECURITY_ISSUE
- Core pass + no security → CONFIRMED_NON_SECURITY_BUG
- Core pass + low exploitability → HARDENING_OBSERVATION
- Core fail → RESEARCH_LEAD

Tests: all gates pass → security issue, security_impact_confirmed=False → non-security bug, core gate fails → research lead, each individual core gate failure tested.

Commit: `feat: add issue gating with proof checklist enforcement`

---

### Task 11: Issue Service

**Files:**
- Create: `backend/services/issue_service.py`
- Test: `backend/tests/services/test_issue_service.py`

CRUD for issues. Methods: `create_issue(artifact_id, severity, title, description, category, cwe_id, disposition, proof, root_cause, recommended_fix) -> IssueResponse`, `get_issue(issue_id)`, `list_issues(campaign_id)`, `revalidate_issue(issue_id)`.

Also: `RegressionTestService` in same file or separate: `create_regression_test(issue_id, file_ref)`, `get_regression_test(reg_id)`.

Commit: `feat: add issue and regression test services`

---

## STEP 7: Steering

### Task 12: Steering Engine

**Files:**
- Create: `backend/campaigns/steering.py`
- Test: `backend/tests/campaigns/test_steering.py`

Deterministic steering for v1 (no LM calls).

`detect_plateau(coverage_snapshots: list[dict], window_seconds: int) -> bool`: True if no new operations covered in the last `window_seconds`.

`generate_steering_decision(campaign_id, lane_metrics, coverage, artifact_counts) -> SteeringDecision | None`: Returns decision if action needed, None if lanes are healthy.

Triggers: coverage plateau → seed injection recommendation. Low validity → schema refinement. Target starvation → rebalance.

`SteeringDecision`: `campaign_id`, `triggering_metrics`, `decision_type`, `recommendation`, `affected_lane_ids`.

Tests: plateau detection with mock snapshots, decision generation for stalled lanes, no decision for healthy lanes.

Commit: `feat: add steering engine with plateau detection`

---

### Task 13: Steering Service + Scheduler Integration

**Files:**
- Create: `backend/services/steering_service.py`
- Modify: `backend/campaigns/controller.py` (add steering method)
- Test: `backend/tests/services/test_steering_service.py`

`SteeringService`: CRUD for steering_decisions table. `record_decision(decision)`, `list_decisions(campaign_id)`.

Add `check_steering(campaign_id)` to controller: fetch metrics, call steering engine, record decision, enqueue new compilation if needed. Enforce: one active steering check per campaign.

Commit: `feat: add steering service and controller integration`

---

## STEP 8: API Expansion + WebSocket Events

### Task 14: Remaining API Endpoints

**Files:**
- Create: `backend/routers/runs.py`
- Create: `backend/routers/artifacts.py`
- Create: `backend/routers/issues.py`
- Modify: `backend/main.py` (register new routers)
- Test: `backend/tests/routers/test_new_routers.py`

Runs router (`/api/runs`): `GET /{id}`, `GET /{id}/logs`, `GET /{id}/metrics`, `POST /{id}/cancel`.

Artifacts router (`/api/artifacts`): `GET /{id}`, `GET /{id}/evidence`, `POST /{id}/replay`, `POST /{id}/minimize`, `POST /{id}/classify`. Also: `GET /api/campaigns/{id}/artifacts`, `GET /api/campaigns/{id}/artifact-buckets`.

Issues router (`/api/issues`): `GET /{id}`, `GET /{id}/regression-test`, `POST /{id}/revalidate`. Also: `GET /api/campaigns/{id}/issues`.

Campaign extras: `GET /api/campaigns/{id}/coverage`, `GET /api/campaigns/{id}/steering`, `GET /api/campaigns/{id}/plan`, `GET /api/campaigns/{id}/graph`.

Register all in main.py.

Commit: `feat: add runs, artifacts, issues routers`

---

### Task 15: WebSocket Event Broadcasting

**Files:**
- Create: `backend/observability/campaign_events.py`
- Modify: `backend/routers/websocket.py` (add new event types)
- Test: `backend/tests/observability/test_campaign_events.py`

Event types: `campaign_status`, `target_upsert`, `lane_upsert`, `run_upsert`, `lane_metrics`, `coverage_update`, `artifact_bucket_opened`, `artifact_bucket_updated`, `artifact_classified`, `replay_update`, `issue_upsert`, `steering_decision`, `harness_validation_result`, `lane_retired`, `report_ready`.

`CampaignEventBroadcaster`: wraps existing WebSocket manager, adds campaign-specific event emission with throttling rules from design doc.

Commit: `feat: add campaign WebSocket event broadcasting`

---

## STEP 9: Delete Old Pipeline

### Task 16: Remove Deep Audit Pipeline

**Files:**
- Delete: `backend/agents/deep_audit/` (entire directory)
- Delete: `backend/agents/base_agent.py`
- Delete: `backend/services/agent_orchestrator.py`
- Delete: `backend/services/agents/`
- Delete: `backend/routers/agents.py` (replace with campaigns router already exists)
- Delete: `backend/services/scan_service.py`
- Delete: `backend/services/scan_tier_service.py`
- Delete: `backend/services/claude_sdk_orchestrator.py`
- Delete: `backend/services/behavior_tree_service.py` (or keep if repurposed)
- Delete: `backend/services/flow_service.py`
- Delete: All tests for deleted code
- Modify: `backend/main.py` (remove old router registrations)
- Modify: `backend/database/__init__.py` (remove old model imports if needed)

IMPORTANT: Only delete after the new campaign system achieves parity. Verify all campaign endpoints work before removing old code. Keep: project_service, auth_service, settings_service, file_service, git_service.

Commit: `refactor: remove old deep audit pipeline`

---

### Task 17: Full Stack Verification

Run all tests. Verify app imports. Verify all campaign endpoints respond. Verify no orphaned imports.

```bash
cd backend && python -m pytest tests/ -q --tb=short
python -c "import main; print('OK')"
```

Commit: `chore: verify complete campaign platform`
