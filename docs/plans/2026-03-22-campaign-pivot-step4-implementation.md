# Campaign Platform Step 4 — Planner, Compiler, Validator

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build lane planning (assign methodology per target), harness/oracle compilation (generate Schemathesis configs from oracle packs), validation (smoke test harnesses), and execution bundle creation — completing Phases C-E of the pipeline.

**Architecture:** For v1, planning and compilation are synchronous LM-free operations (deterministic Schemathesis config generation from OpenAPI targets). LM-assisted planning is the target architecture but not the first milestone. The planner assigns one schema-property lane per API target. The compiler generates a Schemathesis test module + oracle checks. The validator runs a dry-run. Execution bundles pin all revisions.

**Tech Stack:** Python 3.12, SQLAlchemy async, Schemathesis config generation, Dramatiq job definitions (enqueue only, workers not executed yet)

**Worktree:** `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot`

---

### Task 1: Lane Service (CRUD)

**Files:**
- Create: `backend/services/lane_service.py`
- Test: `backend/tests/services/test_lane_service.py`

**What it does:** CRUD for lane_specs within a campaign. Same pattern as target_service.

**Methods:**
- `create_lane_spec(target_id, engine, structure_model, input_producer, feedback_models, oracle_packs, **kwargs) -> LaneSpecResponse`
- `create_lane_specs_batch(target_id, specs: list[dict]) -> list[LaneSpecResponse]`
- `get_lane_spec(lane_spec_id) -> LaneSpecResponse | None`
- `list_lane_specs(campaign_id: str | None = None, target_id: str | None = None) -> list[LaneSpecResponse]`
- `update_lane_spec_status(lane_spec_id, status) -> LaneSpecResponse | None`

**Tests (mocked DB):**
- create_lane_spec returns correct fields + 8-char id
- create_lane_specs_batch returns correct count
- get_lane_spec returns None for missing
- list_lane_specs by campaign_id
- update_lane_spec_status to "compiled"

Run: `cd backend && python -m pytest tests/services/test_lane_service.py -v`
Commit: `feat: add lane spec service`

---

### Task 2: Harness + Oracle Pack + Seed Set Services

**Files:**
- Create: `backend/services/harness_service.py`
- Create: `backend/services/oracle_pack_service.py`
- Create: `backend/services/seed_set_service.py`
- Test: `backend/tests/services/test_harness_service.py`
- Test: `backend/tests/services/test_oracle_pack_service.py`

**What they do:** Thin CRUD services for harnesses, oracle packs, and seed sets. Each is versioned (revision field).

**HarnessService methods:**
- `create_harness(lane_spec_id, code_ref, validation_results=None) -> dict`
- `get_harness(harness_id) -> dict | None`
- `get_latest_for_lane(lane_spec_id) -> dict | None`

**OraclePackService methods:**
- `create_oracle_pack(lane_spec_id, config: dict) -> dict`
- `get_oracle_pack(oracle_pack_id) -> dict | None`

**SeedSetService methods:**
- `create_seed_set(lane_spec_id, sources: list[str], item_count: int = 0) -> dict`
- `get_seed_set(seed_set_id) -> dict | None`

All return plain dicts (not Pydantic models — keep it simple for internal use).

**Tests:** Basic CRUD with mocked DB for each service. 3-4 tests per service.

Run: `cd backend && python -m pytest tests/services/test_harness_service.py tests/services/test_oracle_pack_service.py -v`
Commit: `feat: add harness, oracle pack, and seed set services`

---

### Task 3: Deterministic Lane Planner (v1)

**Files:**
- Create: `backend/campaigns/planner.py`
- Test: `backend/tests/campaigns/test_planner.py`

**What it does:** For v1, deterministic planning — no LM needed. Given targets extracted from OpenAPI, assign one Schemathesis lane per target.

```python
def plan_lanes_for_targets(targets: list[TargetResponse], campaign_preset: str) -> list[dict]:
    """Generate lane spec definitions for each target.

    v1: One schema-property lane per API route target using Schemathesis.
    Returns list of lane spec dicts ready for lane_service.create_lane_specs_batch.
    """
```

For each target with `kind == "api_route"`:
```python
{
    "target_id": target.id,
    "engine": "schemathesis",
    "structure_model": "schema",
    "input_producer": "generation",
    "feedback_models": ["api_surface"],
    "oracle_packs": ["status_code", "schema_conformance"],
    "budget_seconds": budget_for_preset(campaign_preset),
    "seed_sources": ["openapi_examples"],
    "status": "planned",
}
```

If target is stateful (has auth/security), add `"state_depth"` to feedback_models and `"authz_diff"` to oracle_packs.

Budget per preset:
- quick: 60s per lane
- medium: 180s
- advanced: 600s
- pro: 1800s
- ultra: 3600s
- evil: 7200s

**Tests:**
- Plans one lane per API route target
- Stateful targets get extra feedback_models and oracle_packs
- Budget scales with preset
- Non-api_route targets get no lanes (v1 skip)
- Empty target list returns empty

Run: `cd backend && python -m pytest tests/campaigns/test_planner.py -v`
Commit: `feat: add deterministic lane planner for v1`

---

### Task 4: Schemathesis Harness Compiler

**Files:**
- Create: `backend/lanes/__init__.py`
- Create: `backend/lanes/compiler.py`
- Test: `backend/tests/lanes/__init__.py`
- Test: `backend/tests/lanes/test_compiler.py`

**What it does:** Generate a Schemathesis test configuration for a lane spec. For v1, this produces a Python module string that configures Schemathesis with custom checks from oracle packs.

```python
def compile_schemathesis_config(
    lane_spec: dict,
    target: dict,
    openapi_path: str,
    base_url: str = "http://target:8080",
) -> str:
    """Generate a Schemathesis test module as a Python string.

    The module:
    - Imports schemathesis
    - Loads the OpenAPI schema
    - Registers custom checks from oracle_packs
    - Configures auth if target is stateful
    - Returns the module source code as a string
    """
```

Output looks like:
```python
# Auto-generated Schemathesis harness for GET /api/users
import schemathesis

schema = schemathesis.from_url("{base_url}/openapi.json")

@schema.parametrize()
def test_{safe_name}(case):
    response = case.call()
    case.validate_response(response)
    # Custom oracle checks
    assert response.status_code < 500, f"Server error: {response.status_code}"
```

For stateful targets, add:
```python
schema = schemathesis.from_url("{base_url}/openapi.json", stateful=schemathesis.Stateful.links)
```

**Tests:**
- Generates valid Python source for a basic lane spec
- Source contains schemathesis import
- Source contains schema loading with correct base_url
- Stateful targets get stateful=Stateful.links
- Oracle packs "status_code" adds status code assertion
- Oracle packs "schema_conformance" adds validate_response call
- Oracle packs "authz_diff" adds auth header configuration

Run: `cd backend && python -m pytest tests/lanes/test_compiler.py -v`
Commit: `feat: add Schemathesis harness compiler`

---

### Task 5: Harness Validator

**Files:**
- Create: `backend/lanes/validators.py`
- Test: `backend/tests/lanes/test_validators.py`

**What it does:** Validate a compiled harness by checking it meets the 6 gates. For v1, validation is a syntax check + import check (no live target needed yet).

```python
@dataclass
class ValidationResult:
    passed: bool
    gates: dict[str, bool]  # gate_name -> pass/fail
    errors: list[str]       # error messages for failed gates

def validate_harness(harness_code: str) -> ValidationResult:
    """Validate a compiled harness.

    v1 gates (offline only):
    - builds_successfully: code compiles (ast.parse succeeds)
    - calls_real_code: contains schemathesis import
    - reaches_intended_target: contains schema loading (from_url or from_path)
    - produces_useful_execution: contains test function with parametrize
    - no_fake_stubs: does not contain unittest.mock imports

    Gates deferred to runtime (v2):
    - resets_reliably: requires running target
    """
```

**Tests:**
- Valid harness passes all gates
- Syntax error fails builds_successfully
- Missing schemathesis import fails calls_real_code
- Missing schema loading fails reaches_intended_target
- Missing test function fails produces_useful_execution
- Mock import fails no_fake_stubs
- Partial failures: some gates pass, some fail

Run: `cd backend && python -m pytest tests/lanes/test_validators.py -v`
Commit: `feat: add harness validator with gate checks`

---

### Task 6: Execution Bundle Service

**Files:**
- Create: `backend/services/execution_bundle_service.py`
- Test: `backend/tests/services/test_execution_bundle_service.py`

**What it does:** Create execution bundles that pin all revisions for a run.

```python
class ExecutionBundleService:
    async def create_bundle(
        campaign_id: str,
        campaign_plan_revision: int,
        lane_spec_id: str,
        lane_spec_revision: int,
        harness_id: str,
        harness_revision: int,
        oracle_pack_id: str | None = None,
        oracle_pack_revision: int | None = None,
        seed_set_id: str | None = None,
        build_artifact_ref: str | None = None,
        env_snapshot_id: str | None = None,
    ) -> ExecutionBundleResponse

    async def get_bundle(bundle_id: str) -> ExecutionBundleResponse | None

    async def list_bundles(campaign_id: str) -> list[ExecutionBundleResponse]
```

**Tests (mocked DB):**
- create_bundle returns response with all revision fields
- get_bundle returns None for missing
- list_bundles by campaign_id

Run: `cd backend && python -m pytest tests/services/test_execution_bundle_service.py -v`
Commit: `feat: add execution bundle service`

---

### Task 7: Extend Campaign Controller — Compile Phase

**Files:**
- Modify: `backend/campaigns/controller.py`
- Test: `backend/tests/campaigns/test_controller.py` (add tests)

**What it does:** Add `compile_campaign(campaign_id)` to the controller that:
1. Gets campaign + targets
2. Plans lanes via planner.plan_lanes_for_targets
3. Creates lane specs via lane_service
4. For each lane spec: compiles harness, validates, creates harness record
5. If validation passes: creates oracle pack, seed set, execution bundle
6. If validation fails: track failure count. After max_compilation_failures_per_lane, mark lane as retired
7. Updates campaign status to COMPILING then RUNNING (or FAILED if all lanes retired)

```python
async def compile_campaign(self, campaign_id: str) -> CampaignResponse:
    """Run planning + compilation for a campaign.

    1. Get targets from target_service
    2. Plan lanes (deterministic for v1)
    3. Create lane specs
    4. For each lane: compile harness, validate, create bundle
    5. Track failures, retire lanes that exceed max_compilation_failures
    6. Transition status
    """
```

**Tests:**
- compile_campaign with valid targets creates lane specs and bundles
- compile_campaign retires lanes after max failures
- compile_campaign fails campaign if ALL lanes retired
- compile_campaign transitions status to COMPILING

Run: `cd backend && python -m pytest tests/campaigns/test_controller.py -v`
Commit: `feat: extend controller with compile phase`

---

### Task 8: Expand Router — Lanes and Compilation

**Files:**
- Modify: `backend/routers/campaigns.py`
- Test: `backend/tests/routers/test_campaigns.py` (add tests)

**What it does:** Add endpoints:
- `POST /api/campaigns/{id}/start` — runs plan + compile + transitions to running
- `GET /api/campaigns/{id}/lanes` — list lane specs
- `GET /api/lanes/{id}` — get lane spec detail
- `GET /api/lanes/{id}/harnesses` — list harnesses for lane

Create a separate lanes router:
- Create: `backend/routers/lanes.py`
- Register in `main.py` at prefix `/api/lanes`

**Tests:**
- start endpoint registered
- lanes endpoint registered
- lane detail endpoint registered

Run: `cd backend && python -m pytest tests/routers/test_campaigns.py -v`
Commit: `feat: add start, lanes, and harness endpoints`

---

### Task 9: Full Stack Verification

**Step 1:** Run all tests:
```bash
cd backend && python -m pytest tests/ --ignore=tests/agents/test_deep_audit_integration.py --ignore=tests/agents/deep_audit/test_foundation_integration.py --ignore=tests/integration -q --tb=short
```
Expected: All pass, same 4 pre-existing failures.

**Step 2:** Verify imports:
```bash
python -c "import main; print('OK')"
```

**Step 3:** Smoke test the full pipeline:
```python
python -c "
from campaigns.planner import plan_lanes_for_targets
from lanes.compiler import compile_schemathesis_config
from lanes.validators import validate_harness

# Simulate a target
target = type('T', (), {'id': 't1', 'kind': 'api_route', 'entrypoint': 'GET /api/users', 'stateful': False})()

# Plan
lanes = plan_lanes_for_targets([target], 'quick')
print(f'Planned {len(lanes)} lanes')

# Compile
code = compile_schemathesis_config(lanes[0], {'entrypoint': 'GET /api/users'}, '/tmp/openapi.json')
print(f'Compiled {len(code)} bytes of harness code')

# Validate
result = validate_harness(code)
print(f'Validation: passed={result.passed}, gates={result.gates}')
"
```

Commit: `chore: verify step 4 full stack`
