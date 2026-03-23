# Campaign Platform Step 3 — Intake, Surface Extraction, Target Registry

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the control plane intake pipeline: validate repo support contract, detect capabilities, extract API targets from OpenAPI specs, and store them in the target registry.

**Architecture:** Deterministic-first intake (file detection, schema parsing) with LM fallback for ambiguous cases. Campaign orchestrator manages phase transitions (created → planning → extracting). Target registry is a thin async service over the targets table. v1 only supports repos with docker-compose.yml + OpenAPI spec.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async, pyyaml (OpenAPI parsing), Dramatiq (job enqueue — not executed yet, just wired)

**Design doc:** `docs/plans/2026-03-22-campaign-platform-pivot-design.md` (Phase A + Phase B)

**Worktree:** `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot`

---

### Task 1: Intake — v1 Support Contract Validator

**Files:**
- Create: `backend/campaigns/__init__.py`
- Create: `backend/campaigns/intake.py`
- Test: `backend/tests/campaigns/test_intake.py`

**What it does:** Given a repo path, validate the v1 support contract:
1. Has `docker-compose.yml` or `compose.yaml`
2. Has an OpenAPI spec (`.json` or `.yaml` file containing `openapi:` or `swagger:`)
3. Has a health check indicator (Dockerfile HEALTHCHECK, or compose healthcheck, or `/health` route in spec)
4. Has a reset strategy (compose can be restarted = implicit reset)

Returns a `ContractValidation` dataclass with `valid: bool`, `reasons: list[str]` (why it failed), and `compose_path: str`, `openapi_path: str` (detected paths).

**Step 1: Write the failing test**

```python
# backend/tests/campaigns/test_intake.py
import pytest
from pathlib import Path
from campaigns.intake import validate_support_contract, ContractValidation


class TestSupportContractValidation:
    def test_valid_repo(self, tmp_path):
        """Repo with compose + openapi passes."""
        (tmp_path / "docker-compose.yml").write_text("version: '3'\nservices:\n  app:\n    build: .")
        (tmp_path / "openapi.json").write_text('{"openapi": "3.0.0", "info": {"title": "test"}, "paths": {}}')
        result = validate_support_contract(str(tmp_path))
        assert result.valid is True
        assert result.compose_path == "docker-compose.yml"
        assert result.openapi_path == "openapi.json"

    def test_missing_compose(self, tmp_path):
        """Repo without docker-compose fails."""
        (tmp_path / "openapi.json").write_text('{"openapi": "3.0.0"}')
        result = validate_support_contract(str(tmp_path))
        assert result.valid is False
        assert any("docker-compose" in r.lower() or "compose" in r.lower() for r in result.reasons)

    def test_missing_openapi(self, tmp_path):
        """Repo without OpenAPI spec fails."""
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        result = validate_support_contract(str(tmp_path))
        assert result.valid is False
        assert any("openapi" in r.lower() for r in result.reasons)

    def test_compose_yaml_variant(self, tmp_path):
        """compose.yaml is also accepted."""
        (tmp_path / "compose.yaml").write_text("version: '3'\nservices:\n  app:\n    build: .")
        (tmp_path / "openapi.yaml").write_text("openapi: '3.0.0'\ninfo:\n  title: test\npaths: {}")
        result = validate_support_contract(str(tmp_path))
        assert result.valid is True
        assert result.compose_path == "compose.yaml"

    def test_openapi_in_subdirectory(self, tmp_path):
        """OpenAPI spec found in docs/ or api/ subdirectory."""
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "api.yaml").write_text("openapi: '3.0.0'\ninfo:\n  title: test\npaths: {}")
        result = validate_support_contract(str(tmp_path))
        assert result.valid is True
        assert "docs/api.yaml" in result.openapi_path

    def test_swagger_2_detected(self, tmp_path):
        """Swagger 2.0 specs are also accepted."""
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        (tmp_path / "swagger.json").write_text('{"swagger": "2.0", "info": {"title": "test"}, "paths": {}}')
        result = validate_support_contract(str(tmp_path))
        assert result.valid is True

    def test_empty_repo(self, tmp_path):
        """Empty repo fails with both reasons."""
        result = validate_support_contract(str(tmp_path))
        assert result.valid is False
        assert len(result.reasons) >= 2
```

**Step 2:** Run test → FAIL (no module)

**Step 3:** Implement `campaigns/intake.py`:
- `ContractValidation` dataclass: `valid`, `reasons`, `compose_path`, `openapi_path`
- `validate_support_contract(repo_path: str) -> ContractValidation`
- Walk repo looking for compose files (root only) and OpenAPI specs (root + 2 levels deep)
- Check file content for `openapi:` or `swagger:` markers
- Return validation result

**Step 4:** Run test → PASS

**Step 5:** Commit: `feat: add v1 support contract validator for intake`

---

### Task 2: Intake — Capability Profile Detection

**Files:**
- Modify: `backend/campaigns/intake.py`
- Test: `backend/tests/campaigns/test_intake.py` (add tests)

**What it does:** Detect repo capabilities beyond the minimum contract:
- `has_openapi_spec: bool`
- `has_graphql_schema: bool`
- `has_tests: bool` (tests/ or *_test.py exist)
- `has_docker: bool`
- `has_health_check: bool`
- `openapi_path: str | None`
- `compose_path: str | None`
- `languages: list[str]` (detected from file extensions)
- `framework: str | None` (FastAPI, Django, Flask, Express — detected from imports/deps)

Returns a `CapabilityProfile` dataclass.

**Step 1: Write the failing test**

```python
class TestCapabilityProfile:
    def test_detects_python_fastapi(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn\n")
        (tmp_path / "main.py").write_text("from fastapi import FastAPI")
        (tmp_path / "openapi.json").write_text('{"openapi": "3.0.0", "paths": {}}')
        profile = detect_capability_profile(str(tmp_path))
        assert profile.has_openapi_spec is True
        assert profile.has_docker is True
        assert "python" in profile.languages
        assert profile.framework == "fastapi"

    def test_detects_tests(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_api.py").write_text("def test_foo(): pass")
        profile = detect_capability_profile(str(tmp_path))
        assert profile.has_tests is True

    def test_detects_node_express(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("version: '3'")
        (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4.0"}}')
        profile = detect_capability_profile(str(tmp_path))
        assert "javascript" in profile.languages or "typescript" in profile.languages
        assert profile.framework == "express"

    def test_no_framework_detected(self, tmp_path):
        (tmp_path / "main.go").write_text("package main")
        profile = detect_capability_profile(str(tmp_path))
        assert "go" in profile.languages
        assert profile.framework is None
```

**Step 2:** Run test → FAIL

**Step 3:** Implement `detect_capability_profile(repo_path: str) -> CapabilityProfile`:
- Check for docker-compose, OpenAPI, GraphQL schema files
- Check for test directories/files
- Detect languages from file extensions (`.py`, `.js`, `.ts`, `.go`, `.rs`, `.java`)
- Detect framework from dependency files (`requirements.txt` → fastapi/django/flask, `package.json` → express/next)
- Return CapabilityProfile dataclass

**Step 4:** Run test → PASS

**Step 5:** Commit: `feat: add capability profile detection for repo intake`

---

### Task 3: Target Registry Service

**Files:**
- Create: `backend/services/target_service.py`
- Test: `backend/tests/services/test_target_service.py`

**What it does:** CRUD for targets within a campaign. Thin async service over the `targets` DB table.

**Methods:**
- `create_target(campaign_id, kind, entrypoint, language, **kwargs) -> TargetResponse`
- `create_targets_batch(campaign_id, targets: list[dict]) -> list[TargetResponse]`
- `get_target(target_id) -> TargetResponse | None`
- `list_targets(campaign_id) -> list[TargetResponse]`
- `update_target_priority(target_id, priority_score) -> TargetResponse | None`

**Step 1: Write the failing test**

```python
class TestTargetService:
    @pytest.mark.asyncio
    async def test_create_target(self):
        service = TargetService()
        with patch("services.target_service.get_session") as mock_ctx:
            # mock session setup
            target = await service.create_target(
                campaign_id="camp_1",
                kind="api_route",
                entrypoint="/api/users",
                language="python",
            )
        assert target.campaign_id == "camp_1"
        assert target.kind == "api_route"
        assert target.id is not None

    @pytest.mark.asyncio
    async def test_create_targets_batch(self):
        service = TargetService()
        targets_data = [
            {"kind": "api_route", "entrypoint": "/api/users", "language": "python"},
            {"kind": "api_route", "entrypoint": "/api/orders", "language": "python"},
        ]
        with patch("services.target_service.get_session") as mock_ctx:
            # mock session
            targets = await service.create_targets_batch("camp_1", targets_data)
        assert len(targets) == 2
```

**Step 2:** Run test → FAIL

**Step 3:** Implement TargetService with mocked DB pattern (same as campaign_service).

**Step 4:** Run test → PASS

**Step 5:** Commit: `feat: add target registry service`

---

### Task 4: OpenAPI Surface Extractor

**Files:**
- Create: `backend/targets/__init__.py`
- Create: `backend/targets/extractors/__init__.py`
- Create: `backend/targets/extractors/openapi_extractor.py`
- Test: `backend/tests/targets/test_openapi_extractor.py`

**What it does:** Parse an OpenAPI spec and extract target descriptors for each operation (path + method). This is the core deterministic extractor for v1.

For each operation in the spec, produce a target descriptor:
```python
{
    "kind": "api_route",
    "entrypoint": "POST /api/orders",
    "language": detected_language,
    "schemas": ["openapi:/api/orders"],
    "stateful": bool,  # True if operation has auth/session requirements
    "actors": [],  # populated later
    "reset_strategy": "container_restart",
}
```

**Step 1: Write the failing test**

```python
class TestOpenAPIExtractor:
    def test_extract_routes_from_spec(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {
                "/api/users": {
                    "get": {"summary": "List users", "responses": {"200": {}}},
                    "post": {"summary": "Create user", "responses": {"201": {}}},
                },
                "/api/orders/{id}": {
                    "get": {"summary": "Get order", "responses": {"200": {}}},
                    "put": {"summary": "Update order", "responses": {"200": {}}},
                    "delete": {"summary": "Delete order", "responses": {"204": {}}},
                },
            },
        }
        targets = extract_targets_from_openapi(spec, language="python")
        assert len(targets) == 5
        entrypoints = {t["entrypoint"] for t in targets}
        assert "GET /api/users" in entrypoints
        assert "POST /api/users" in entrypoints
        assert "DELETE /api/orders/{id}" in entrypoints

    def test_all_targets_are_api_routes(self):
        spec = {"openapi": "3.0.0", "paths": {"/health": {"get": {}}}}
        targets = extract_targets_from_openapi(spec)
        assert all(t["kind"] == "api_route" for t in targets)

    def test_detects_auth_as_stateful(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/admin": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {}},
                    }
                }
            },
        }
        targets = extract_targets_from_openapi(spec)
        assert targets[0]["stateful"] is True

    def test_loads_spec_from_file(self, tmp_path):
        spec_file = tmp_path / "openapi.json"
        spec_file.write_text('{"openapi": "3.0.0", "paths": {"/api/test": {"get": {"responses": {"200": {}}}}}}')
        targets = extract_targets_from_file(str(spec_file))
        assert len(targets) == 1

    def test_loads_yaml_spec(self, tmp_path):
        spec_file = tmp_path / "openapi.yaml"
        spec_file.write_text("openapi: '3.0.0'\npaths:\n  /api/test:\n    get:\n      responses:\n        '200': {}")
        targets = extract_targets_from_file(str(spec_file))
        assert len(targets) == 1

    def test_empty_paths(self):
        spec = {"openapi": "3.0.0", "paths": {}}
        targets = extract_targets_from_openapi(spec)
        assert targets == []
```

**Step 2:** Run test → FAIL

**Step 3:** Implement:
- `extract_targets_from_openapi(spec: dict, language: str | None = None) -> list[dict]`
- `extract_targets_from_file(file_path: str, language: str | None = None) -> list[dict]`
- Parse paths, iterate operations (get/post/put/delete/patch), detect security requirements
- Return list of target descriptor dicts

Add `pyyaml` to requirements.txt if not already there (check first — it likely is).

**Step 4:** Run test → PASS

**Step 5:** Commit: `feat: add OpenAPI surface extractor`

---

### Task 5: Campaign Controller — Phase Transitions

**Files:**
- Create: `backend/campaigns/controller.py`
- Test: `backend/tests/campaigns/test_controller.py`

**What it does:** Orchestrate campaign phase transitions. This is the state machine that drives campaigns from `created` through `planning` → `extracting` → next steps.

**Methods:**
- `plan_campaign(campaign_id: str) -> CampaignResponse` — validate contract, detect capabilities, extract targets, update status
- `_run_intake(campaign_id, repo_path) -> tuple[ContractValidation, CapabilityProfile]`
- `_run_extraction(campaign_id, repo_path, capability_profile) -> list[TargetResponse]`

For v1, intake and extraction are synchronous (no Dramatiq job yet — that comes when we need LM-assisted extraction). The controller calls intake.py and openapi_extractor.py directly.

**Step 1: Write the failing test**

```python
class TestCampaignController:
    @pytest.mark.asyncio
    async def test_plan_campaign_valid_repo(self, tmp_path):
        """Plan campaign with valid repo creates targets."""
        # Set up valid repo
        (tmp_path / "docker-compose.yml").write_text("version: '3'\nservices:\n  app:\n    build: .")
        (tmp_path / "openapi.json").write_text(json.dumps({
            "openapi": "3.0.0",
            "paths": {
                "/api/users": {"get": {"responses": {"200": {}}}},
                "/api/orders": {"post": {"responses": {"201": {}}}},
            }
        }))

        controller = CampaignController()
        # Mock campaign_service.get_campaign to return a campaign pointing to tmp_path
        # Mock campaign_service.update_campaign_status
        # Mock target_service.create_targets_batch
        with patch.multiple(...):
            result = await controller.plan_campaign("camp_1")

        assert result.status == "extracting"

    @pytest.mark.asyncio
    async def test_plan_campaign_invalid_repo_fails(self, tmp_path):
        """Plan campaign with missing compose fails fast."""
        controller = CampaignController()
        with patch(...):
            with pytest.raises(ValueError, match="support contract"):
                await controller.plan_campaign("camp_1")

    @pytest.mark.asyncio
    async def test_plan_campaign_creates_targets(self, tmp_path):
        """Plan campaign creates targets from OpenAPI spec."""
        # Setup repo with 3 endpoints
        # Mock services
        # Verify target_service.create_targets_batch called with 3 targets
```

**Step 2:** Run test → FAIL

**Step 3:** Implement CampaignController:
- Get campaign from campaign_service
- Get repo path from project_service
- Run validate_support_contract
- If invalid, update campaign status to FAILED with reasons, raise ValueError
- Run detect_capability_profile
- Run extract_targets_from_file on detected OpenAPI spec
- Create targets via target_service.create_targets_batch
- Update campaign status to EXTRACTING
- Return updated campaign

**Step 4:** Run test → PASS

**Step 5:** Commit: `feat: add campaign controller with intake and extraction`

---

### Task 6: Expand Campaign Router

**Files:**
- Modify: `backend/routers/campaigns.py`
- Test: `backend/tests/routers/test_campaigns.py` (add tests)

**What it does:** Add endpoints for:
- `POST /api/campaigns/{id}/plan` — trigger planning phase
- `GET /api/campaigns/{id}/targets` — list targets

**Step 1: Write the failing test**

```python
class TestCampaignPlanEndpoint:
    def test_plan_endpoint_registered(self):
        from main import app
        routes = [r.path for r in app.routes]
        assert any("/campaigns/" in r and "/plan" in r for r in routes)

class TestCampaignTargetsEndpoint:
    def test_targets_endpoint_registered(self):
        from main import app
        routes = [r.path for r in app.routes]
        assert any("/campaigns/" in r and "/targets" in r for r in routes)
```

**Step 2:** Run test → FAIL

**Step 3:** Add endpoints:

```python
@router.post("/{campaign_id}/plan", response_model=CampaignResponse)
async def plan_campaign(campaign_id: str, auth_context = Depends(require_auth)):
    try:
        return await campaign_controller.plan_campaign(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{campaign_id}/targets", response_model=list[TargetResponse])
async def list_campaign_targets(campaign_id: str, auth_context = Depends(require_auth)):
    return await target_service.list_targets(campaign_id)
```

Import `campaign_controller` and `target_service`.

**Step 4:** Run test → PASS

**Step 5:** Commit: `feat: add plan and targets endpoints to campaign router`

---

### Task 7: Control Plane Job Dataclasses

**Files:**
- Modify: `backend/execution/jobs.py`
- Test: `backend/tests/execution/test_jobs.py` (add tests)

**What it does:** Add job dataclasses for the 5 control-plane job types that were defined as enum values but had no dataclass.

```python
@dataclass
class ExtractorJob(BaseJob):
    repo_path: str = ""
    capability_profile: dict = field(default_factory=dict)
    job_type: JobType = field(default=JobType.EXTRACTOR, init=False)

@dataclass
class PlannerJob(BaseJob):
    target_ids: list[str] = field(default_factory=list)
    campaign_preset: str = "quick"
    job_type: JobType = field(default=JobType.PLANNER, init=False)

@dataclass
class CompilerJob(BaseJob):
    lane_spec_id: str = ""
    lane_spec_revision: int = 1
    target_metadata: dict = field(default_factory=dict)
    job_type: JobType = field(default=JobType.COMPILER, init=False)

@dataclass
class SteeringJob(BaseJob):
    metrics_snapshot: dict = field(default_factory=dict)
    job_type: JobType = field(default=JobType.STEERING, init=False)

@dataclass
class AnalystJob(BaseJob):
    artifact_id: str = ""
    evidence_package_ref: str = ""
    job_type: JobType = field(default=JobType.ANALYST, init=False)
```

**Step 1: Write the failing test**

```python
class TestControlPlaneJobs:
    def test_extractor_job(self):
        job = ExtractorJob(campaign_id="c1", repo_path="/tmp/repo")
        assert job.job_type == JobType.EXTRACTOR
        assert job.repo_path == "/tmp/repo"

    def test_planner_job(self):
        job = PlannerJob(campaign_id="c1", target_ids=["t1", "t2"])
        assert job.job_type == JobType.PLANNER

    def test_compiler_job(self):
        job = CompilerJob(campaign_id="c1", lane_spec_id="ls1")
        assert job.job_type == JobType.COMPILER

    def test_steering_job(self):
        job = SteeringJob(campaign_id="c1")
        assert job.job_type == JobType.STEERING

    def test_analyst_job(self):
        job = AnalystJob(campaign_id="c1", artifact_id="a1")
        assert job.job_type == JobType.ANALYST
```

**Step 2:** Run test → FAIL

**Step 3:** Add the 5 dataclasses to `execution/jobs.py`.

**Step 4:** Run test → PASS

**Step 5:** Commit: `feat: add control plane job dataclasses`

---

### Task 8: Full Stack Verification

**Step 1: Run all tests**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend
python -m pytest tests/ --ignore=tests/agents/test_deep_audit_integration.py --ignore=tests/agents/deep_audit/test_foundation_integration.py --ignore=tests/integration -q --tb=short
```

Expected: All existing + new tests pass. Same 4 pre-existing failures.

**Step 2: Verify app imports**

```bash
python -c "import main; print('OK')"
```

**Step 3: Verify campaign intake works end-to-end (manual smoke test)**

```bash
python -c "
from campaigns.intake import validate_support_contract, detect_capability_profile
import tempfile, os, json

# Create a mock valid repo
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, 'docker-compose.yml'), 'w').write('version: \"3\"\nservices:\n  app:\n    build: .')
    open(os.path.join(d, 'openapi.json'), 'w').write(json.dumps({'openapi': '3.0.0', 'paths': {'/api/test': {'get': {'responses': {'200': {}}}}}}))

    v = validate_support_contract(d)
    print(f'Contract valid: {v.valid}')
    print(f'Compose: {v.compose_path}')
    print(f'OpenAPI: {v.openapi_path}')

    p = detect_capability_profile(d)
    print(f'Has OpenAPI: {p.has_openapi_spec}')
    print(f'Has Docker: {p.has_docker}')
"
```

**Step 4: Commit if any fixes needed**

```bash
git add -A
git commit -m "chore: verify step 3 full stack"
```
