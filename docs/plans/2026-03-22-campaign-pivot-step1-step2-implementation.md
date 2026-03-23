# Campaign Platform Pivot — Steps 1 & 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the agent/scan/finding data model with campaign/target/lane/artifact/issue and add Dramatiq + filesystem artifact storage infrastructure.

**Architecture:** New SQLAlchemy models alongside existing ones (no migration yet — old models stay until Step 9). New Pydantic schemas for all campaign nouns. Dramatiq workers with Redis broker (already running). Filesystem-backed artifact store with S3-compatible abstraction.

**Tech Stack:** SQLAlchemy async, Pydantic v2, Dramatiq + Redis, Python 3.12

**Design doc:** `docs/plans/2026-03-22-campaign-platform-pivot-design.md`

---

## Prerequisites

- Backend at `/Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend`
- Redis already running on port 6380 (from existing docker-compose)
- PostgreSQL already running on port 5432
- `redis` and `aioredis` already in requirements.txt
- No Alembic — uses `create_all()` at startup

---

### Task 1: New Enums

**Files:**
- Create: `backend/models/campaign_enums.py`
- Test: `backend/tests/models/test_campaign_enums.py`

**Step 1: Write the failing test**

```python
# backend/tests/models/test_campaign_enums.py
import pytest
from models.campaign_enums import (
    CampaignStatus,
    CampaignPreset,
    TargetKind,
    LaneSpecStatus,
    RunLaneStatus,
    RunnerJobStatus,
    ArtifactType,
    ArtifactClassification,
    AnalysisOutcome,
    IssueDisposition,
    IssueSeverity,
    ResourceProfile,
    StructureModel,
    InputProducer,
)


class TestCampaignEnums:
    def test_campaign_status_values(self):
        assert CampaignStatus.CREATED.value == "created"
        assert CampaignStatus.PLANNING.value == "planning"
        assert CampaignStatus.RUNNING.value == "running"
        assert CampaignStatus.PAUSED.value == "paused"
        assert CampaignStatus.COMPLETED.value == "completed"
        assert CampaignStatus.FAILED.value == "failed"
        assert CampaignStatus.CANCELLED.value == "cancelled"

    def test_campaign_preset_values(self):
        assert CampaignPreset.QUICK.value == "quick"
        assert CampaignPreset.EVIL.value == "evil"

    def test_target_kind_values(self):
        assert TargetKind.API_ROUTE.value == "api_route"
        assert TargetKind.PARSER.value == "parser"
        assert TargetKind.NATIVE_FUNCTION.value == "native_function"

    def test_lane_spec_status_separate_from_run(self):
        # Lane specs have their own status lifecycle
        assert "running" not in [s.value for s in LaneSpecStatus]
        assert "retired" in [s.value for s in LaneSpecStatus]
        # Run lanes have their own status lifecycle
        assert "retired" not in [s.value for s in RunLaneStatus]
        assert "running" in [s.value for s in RunLaneStatus]
        assert "superseded" in [s.value for s in RunLaneStatus]

    def test_artifact_classification_vs_issue_disposition(self):
        # These are separate systems
        art_values = [c.value for c in ArtifactClassification]
        issue_values = [d.value for d in IssueDisposition]
        assert "issue_candidate" in art_values
        assert "harness_artifact" in art_values
        assert "confirmed_security_issue" in issue_values
        assert "confirmed_security_issue" not in art_values
        assert "issue_candidate" not in issue_values

    def test_analysis_outcome_on_artifact(self):
        assert AnalysisOutcome.BY_DESIGN.value == "by_design"
        assert AnalysisOutcome.RESEARCH_LEAD.value == "research_lead"
        assert AnalysisOutcome.NONE.value == "none"
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/models/test_campaign_enums.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'models.campaign_enums'`

**Step 3: Write minimal implementation**

```python
# backend/models/campaign_enums.py
"""Enums for the campaign platform data model.

These replace the agent/scan/finding enums with campaign-oriented vocabulary.
"""
from enum import Enum


class CampaignStatus(str, Enum):
    CREATED = "created"
    PLANNING = "planning"
    EXTRACTING = "extracting"
    COMPILING = "compiling"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CampaignPreset(str, Enum):
    QUICK = "quick"
    MEDIUM = "medium"
    ADVANCED = "advanced"
    PRO = "pro"
    ULTRA = "ultra"
    EVIL = "evil"


class TargetKind(str, Enum):
    API_ROUTE = "api_route"
    PARSER = "parser"
    WORKFLOW = "workflow"
    BROWSER = "browser"
    CLI = "cli"
    MESSAGE_CONSUMER = "message_consumer"
    NATIVE_FUNCTION = "native_function"


class LaneSpecStatus(str, Enum):
    PLANNED = "planned"
    COMPILED = "compiled"
    VALIDATED = "validated"
    RETIRED = "retired"


class RunLaneStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    STALLED = "stalled"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"


class RunnerJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"


class ArtifactType(str, Enum):
    CRASH = "crash"
    HANG = "hang"
    ORACLE_HIT = "oracle_hit"
    DIFFERENTIAL_FAILURE = "differential_failure"


class ArtifactClassification(str, Enum):
    ISSUE_CANDIDATE = "issue_candidate"
    HARNESS_ARTIFACT = "harness_artifact"
    FLAKY_UNCONFIRMED = "flaky_unconfirmed"


class AnalysisOutcome(str, Enum):
    BY_DESIGN = "by_design"
    RESEARCH_LEAD = "research_lead"
    NONE = "none"


class IssueDisposition(str, Enum):
    CONFIRMED_SECURITY_ISSUE = "confirmed_security_issue"
    CONFIRMED_NON_SECURITY_BUG = "confirmed_non_security_bug"
    HARDENING_OBSERVATION = "hardening_observation"


class IssueSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResourceProfile(str, Enum):
    LIGHT = "light"
    MEDIUM = "medium"
    HEAVY = "heavy"


class StructureModel(str, Enum):
    SCHEMA = "schema"
    STATE_MACHINE = "state_machine"
    GRAMMAR = "grammar"
    RAW = "raw"
    TYPED = "typed"


class InputProducer(str, Enum):
    MUTATION = "mutation"
    GENERATION = "generation"
    HYBRID = "hybrid"
```

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/models/test_campaign_enums.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/models/campaign_enums.py backend/tests/models/test_campaign_enums.py
git commit -m "feat: add campaign platform enums"
```

---

### Task 2: Campaign SQLAlchemy Models (Core Chain)

**Files:**
- Create: `backend/database/campaign_models.py`
- Test: `backend/tests/database/test_campaign_models.py`

**Step 1: Write the failing test**

```python
# backend/tests/database/test_campaign_models.py
import pytest
from database.campaign_models import (
    Campaign,
    Target,
    LaneSpec,
    ExecutionBundle,
    RunLane,
    Artifact,
    ArtifactBucket,
    Issue,
    RegressionTest,
    CampaignPlan,
    SteeringDecision,
    Harness,
    OraclePack,
    SeedSet,
    Dictionary,
    Mutator,
    RunnerJob,
    EnvSnapshot,
    CoverageSnapshot,
    CoverageRollup,
    Corpus,
    CorpusItem,
    ReplayRun,
    ResearchLead,
)


class TestCampaignModels:
    def test_campaign_table_name(self):
        assert Campaign.__tablename__ == "campaigns"

    def test_target_table_name(self):
        assert Target.__tablename__ == "targets"

    def test_lane_spec_table_name(self):
        assert LaneSpec.__tablename__ == "lane_specs"

    def test_execution_bundle_table_name(self):
        assert ExecutionBundle.__tablename__ == "execution_bundles"

    def test_run_lane_table_name(self):
        assert RunLane.__tablename__ == "run_lanes"

    def test_artifact_table_name(self):
        assert Artifact.__tablename__ == "artifacts"

    def test_issue_table_name(self):
        assert Issue.__tablename__ == "issues"

    def test_core_chain_foreign_keys(self):
        """Verify the core FK chain: campaign → target → lane → bundle → run → artifact → issue."""
        # Target points to Campaign
        target_fks = {c.parent.name for c in Target.__table__.foreign_keys}
        assert "campaigns" in target_fks

        # LaneSpec points to Target
        lane_fks = {c.parent.name for c in LaneSpec.__table__.foreign_keys}
        assert "targets" in lane_fks

        # ExecutionBundle points to LaneSpec
        bundle_fks = {c.parent.name for c in ExecutionBundle.__table__.foreign_keys}
        assert "lane_specs" in bundle_fks

        # RunLane points to ExecutionBundle
        run_fks = {c.parent.name for c in RunLane.__table__.foreign_keys}
        assert "execution_bundles" in run_fks

        # Artifact points to RunLane
        artifact_fks = {c.parent.name for c in Artifact.__table__.foreign_keys}
        assert "run_lanes" in artifact_fks

        # Issue points to Artifact
        issue_fks = {c.parent.name for c in Issue.__table__.foreign_keys}
        assert "artifacts" in issue_fks

    def test_all_25_tables_exist(self):
        """Verify all 25 new tables are defined."""
        expected = {
            "campaigns", "targets", "lane_specs", "execution_bundles",
            "run_lanes", "artifacts", "artifact_buckets", "issues",
            "regression_tests", "campaign_plans", "steering_decisions",
            "harnesses", "oracle_packs", "seed_sets", "dictionaries",
            "mutators", "runner_jobs", "env_snapshots",
            "coverage_snapshots", "coverage_rollups", "corpora",
            "corpus_items", "replay_runs", "research_leads",
        }
        actual = {
            Campaign.__tablename__, Target.__tablename__,
            LaneSpec.__tablename__, ExecutionBundle.__tablename__,
            RunLane.__tablename__, Artifact.__tablename__,
            ArtifactBucket.__tablename__, Issue.__tablename__,
            RegressionTest.__tablename__, CampaignPlan.__tablename__,
            SteeringDecision.__tablename__, Harness.__tablename__,
            OraclePack.__tablename__, SeedSet.__tablename__,
            Dictionary.__tablename__, Mutator.__tablename__,
            RunnerJob.__tablename__, EnvSnapshot.__tablename__,
            CoverageSnapshot.__tablename__, CoverageRollup.__tablename__,
            Corpus.__tablename__, CorpusItem.__tablename__,
            ReplayRun.__tablename__, ResearchLead.__tablename__,
        }
        assert expected == actual
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/database/test_campaign_models.py -v`
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Write minimal implementation**

Create `backend/database/campaign_models.py` with all 24 SQLAlchemy models. Each model has the columns defined in the design doc Section 2. Use `Base` from `database.models` so they share the same metadata and `create_all()` picks them up.

The file is large (~500 lines) — here are the key models. The implementing agent should create ALL 24 models with proper columns, FKs, indexes, and JSONB fields.

Key patterns to follow:
- `id` columns are `String(64)`, primary key (matching existing pattern)
- `campaign_id`, `target_id`, etc. are `String(64)` with `ForeignKey`
- JSONB columns use `JSON` type (works for both SQLite and PostgreSQL)
- `created_at` / `updated_at` use `DateTime` with `default=func.now()`
- Status columns are `String(32)` storing enum `.value` strings
- `revision` columns are `Integer` with `default=1`

The core 7 models (Campaign, Target, LaneSpec, ExecutionBundle, RunLane, Artifact, Issue) plus 17 supporting models (ArtifactBucket, RegressionTest, CampaignPlan, SteeringDecision, Harness, OraclePack, SeedSet, Dictionary, Mutator, RunnerJob, EnvSnapshot, CoverageSnapshot, CoverageRollup, Corpus, CorpusItem, ReplayRun, ResearchLead).

Also create `backend/tests/database/__init__.py` if it doesn't exist.

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/database/test_campaign_models.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/database/campaign_models.py backend/tests/database/test_campaign_models.py backend/tests/database/__init__.py
git commit -m "feat: add 24 campaign SQLAlchemy models"
```

---

### Task 3: Campaign Pydantic Schemas

**Files:**
- Create: `backend/models/campaign_schemas.py`
- Test: `backend/tests/models/test_campaign_schemas.py`

**Step 1: Write the failing test**

```python
# backend/tests/models/test_campaign_schemas.py
import pytest
from models.campaign_schemas import (
    CampaignCreateRequest,
    CampaignResponse,
    TargetResponse,
    LaneSpecResponse,
    RunLaneResponse,
    ExecutionBundleResponse,
    ArtifactResponse,
    IssueResponse,
    ProofChecklist,
    ReplayRecipe,
)


class TestCampaignCreateRequest:
    def test_minimal_create(self):
        req = CampaignCreateRequest(repo_id="proj123", campaign_preset="quick")
        assert req.repo_id == "proj123"
        assert req.campaign_preset == "quick"
        assert req.max_parallel_lanes == 2
        assert req.lm_provider == "claude_cli"

    def test_full_create(self):
        req = CampaignCreateRequest(
            repo_id="proj123",
            campaign_preset="advanced",
            lm_provider="anthropic_sdk",
            lm_model="claude-opus-4-6",
            max_parallel_lanes=4,
            budget_seconds=7200,
            steering_interval_seconds=120,
        )
        assert req.budget_seconds == 7200


class TestProofChecklist:
    def test_all_fields_present(self):
        proof = ProofChecklist(
            target_real=True,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=True,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=True,
        )
        assert proof.target_real is True
        assert proof.security_impact_confirmed is True

    def test_core_gates(self):
        proof = ProofChecklist(
            target_real=True,
            harness_validated=True,
            real_code_reached=True,
            external_input_controlled=False,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=False,
        )
        assert proof.core_gates_pass() is True
        assert proof.is_security_issue() is False

    def test_core_gates_fail(self):
        proof = ProofChecklist(
            target_real=True,
            harness_validated=False,  # fails core gate
            real_code_reached=True,
            external_input_controlled=True,
            oracle_triggered_or_sanitizer_hit=True,
            reproduced_cleanly=True,
            artifact_minimization_attempted=True,
            not_harness_artifact=True,
            not_test_only=True,
            security_impact_confirmed=True,
        )
        assert proof.core_gates_pass() is False


class TestReplayRecipe:
    def test_structured_recipe(self):
        recipe = ReplayRecipe(
            runner="python",
            entrypoint="replay.py",
            args=["--artifact", "art_123"],
            env_snapshot_id="env_1",
            artifact_inputs=["file://artifacts/art_123/input.json"],
        )
        assert recipe.runner == "python"
        assert len(recipe.artifact_inputs) == 1


class TestResponses:
    def test_campaign_response_fields(self):
        fields = CampaignResponse.model_fields.keys()
        assert "id" in fields
        assert "repo_id" in fields
        assert "status" in fields
        assert "preset" in fields
        assert "created_at" in fields

    def test_target_response_fields(self):
        fields = TargetResponse.model_fields.keys()
        assert "id" in fields
        assert "campaign_id" in fields
        assert "kind" in fields
        assert "priority_score" in fields

    def test_artifact_response_fields(self):
        fields = ArtifactResponse.model_fields.keys()
        assert "run_lane_id" in fields
        assert "artifact_classification" in fields
        assert "analysis_outcome" in fields
        assert "replay_recipe" in fields

    def test_issue_response_fields(self):
        fields = IssueResponse.model_fields.keys()
        assert "artifact_id" in fields
        assert "disposition" in fields
        assert "proof" in fields
        assert "regression_test_id" in fields
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/models/test_campaign_schemas.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

Create `backend/models/campaign_schemas.py` with all Pydantic models from design doc Section 2. Key models:

- `CampaignCreateRequest` — all config params from design doc Section 10
- `CampaignResponse` — campaign state for API responses
- `TargetResponse` — target detail
- `LaneSpecResponse` — lane spec with revision
- `ExecutionBundleResponse` — full bundle with all IDs
- `RunLaneResponse` — run with status and resource limits
- `ArtifactResponse` — with classification, analysis_outcome, replay_recipe, evidence_refs
- `IssueResponse` — with proof checklist, disposition, regression_test_id
- `ProofChecklist` — with `core_gates_pass()` and `is_security_issue()` methods
- `ReplayRecipe` — structured recipe (not shell string)

Use the exact field names and types from the design doc schemas.

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/models/test_campaign_schemas.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/models/campaign_schemas.py backend/tests/models/test_campaign_schemas.py
git commit -m "feat: add campaign Pydantic schemas with proof gating logic"
```

---

### Task 4: Register Campaign Models with Database

**Files:**
- Modify: `backend/database/__init__.py`
- Test: verify `init_db()` creates the new tables

**Step 1: Write the failing test**

```python
# backend/tests/database/test_campaign_tables_created.py
import pytest
from sqlalchemy import inspect
from database.connection import engine, init_db


@pytest.mark.asyncio
async def test_campaign_tables_created():
    """Verify init_db() creates all 24 campaign tables."""
    await init_db()

    async with engine.connect() as conn:
        def get_tables(connection):
            inspector = inspect(connection)
            return set(inspector.get_table_names())

        tables = await conn.run_sync(get_tables)

    expected = {
        "campaigns", "targets", "lane_specs", "execution_bundles",
        "run_lanes", "artifacts", "artifact_buckets", "issues",
        "regression_tests", "campaign_plans", "steering_decisions",
        "harnesses", "oracle_packs", "seed_sets", "dictionaries",
        "mutators", "runner_jobs", "env_snapshots",
        "coverage_snapshots", "coverage_rollups", "corpora",
        "corpus_items", "replay_runs", "research_leads",
    }
    assert expected.issubset(tables), f"Missing tables: {expected - tables}"
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/database/test_campaign_tables_created.py -v`
Expected: FAIL — tables not created because campaign_models not imported

**Step 3: Write minimal implementation**

Edit `backend/database/__init__.py` to import campaign_models so `create_all()` picks them up:

```python
# Add this import so Base.metadata includes campaign tables
from database.campaign_models import *  # noqa: F401, F403
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add backend/database/__init__.py backend/tests/database/test_campaign_tables_created.py
git commit -m "feat: register campaign models with database init"
```

---

### Task 5: Artifact Storage — Filesystem Backend

**Files:**
- Create: `backend/storage/__init__.py`
- Create: `backend/storage/object_store.py`
- Test: `backend/tests/storage/test_object_store.py`

**Step 1: Write the failing test**

```python
# backend/tests/storage/test_object_store.py
import pytest
from pathlib import Path
from storage.object_store import LocalFileStore


class TestLocalFileStore:
    def test_put_and_get(self, tmp_path):
        store = LocalFileStore(root=tmp_path)
        store.put("campaign_1/artifacts/art_1/input.json", b'{"test": true}')
        data = store.get("campaign_1/artifacts/art_1/input.json")
        assert data == b'{"test": true}'

    def test_get_missing_returns_none(self, tmp_path):
        store = LocalFileStore(root=tmp_path)
        assert store.get("nonexistent/path") is None

    def test_exists(self, tmp_path):
        store = LocalFileStore(root=tmp_path)
        assert store.exists("foo/bar") is False
        store.put("foo/bar", b"data")
        assert store.exists("foo/bar") is True

    def test_delete(self, tmp_path):
        store = LocalFileStore(root=tmp_path)
        store.put("foo/bar", b"data")
        store.delete("foo/bar")
        assert store.exists("foo/bar") is False

    def test_list_keys(self, tmp_path):
        store = LocalFileStore(root=tmp_path)
        store.put("camp_1/a.json", b"1")
        store.put("camp_1/b.json", b"2")
        store.put("camp_2/c.json", b"3")
        keys = store.list_keys("camp_1/")
        assert set(keys) == {"camp_1/a.json", "camp_1/b.json"}

    def test_get_url(self, tmp_path):
        store = LocalFileStore(root=tmp_path)
        store.put("camp_1/input.json", b"data")
        url = store.get_url("camp_1/input.json")
        assert url.startswith("file://")
        assert "camp_1/input.json" in url

    def test_put_creates_directories(self, tmp_path):
        store = LocalFileStore(root=tmp_path)
        store.put("deep/nested/path/file.bin", b"content")
        assert store.get("deep/nested/path/file.bin") == b"content"
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/storage/test_object_store.py -v`
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/storage/__init__.py
"""Artifact storage abstraction."""

# backend/storage/object_store.py
"""Artifact store with filesystem backend (default) and optional S3/MinIO.

Usage:
    store = LocalFileStore(root=Path("./data/artifacts"))
    store.put("campaign_1/artifacts/art_1/input.json", data)
    data = store.get("campaign_1/artifacts/art_1/input.json")
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class ObjectStore(ABC):
    """Abstract artifact store interface."""

    @abstractmethod
    def put(self, key: str, data: bytes) -> None: ...

    @abstractmethod
    def get(self, key: str) -> Optional[bytes]: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def list_keys(self, prefix: str) -> list[str]: ...

    @abstractmethod
    def get_url(self, key: str) -> str: ...


class LocalFileStore(ObjectStore):
    """Filesystem-backed artifact store. Default for v1."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / key

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> Optional[bytes]:
        path = self._path(key)
        if not path.exists():
            return None
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            path.unlink()

    def list_keys(self, prefix: str) -> list[str]:
        prefix_path = self._path(prefix)
        if not prefix_path.exists():
            return []
        base = self.root
        return [
            str(p.relative_to(base))
            for p in prefix_path.rglob("*")
            if p.is_file()
        ]

    def get_url(self, key: str) -> str:
        return f"file://{self._path(key).resolve()}"
```

Also create `backend/tests/storage/__init__.py`.

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add backend/storage/ backend/tests/storage/
git commit -m "feat: add filesystem-backed artifact store"
```

---

### Task 6: Add Dramatiq + Redis Broker

**Files:**
- Modify: `backend/requirements.txt` (add dramatiq)
- Create: `backend/execution/__init__.py`
- Create: `backend/execution/broker.py`
- Create: `backend/execution/workers/__init__.py`
- Test: `backend/tests/execution/test_broker.py`

**Step 1: Add dramatiq to requirements**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend
echo "dramatiq[redis]>=1.17.0" >> requirements.txt
pip install "dramatiq[redis]>=1.17.0"
```

**Step 2: Write the failing test**

```python
# backend/tests/execution/test_broker.py
import pytest
from execution.broker import get_broker, QUEUE_NAMES


class TestBroker:
    def test_queue_names_defined(self):
        assert "control" in QUEUE_NAMES
        assert "package" in QUEUE_NAMES
        assert "fuzz" in QUEUE_NAMES
        assert "replay" in QUEUE_NAMES

    def test_get_broker_returns_redis_broker(self):
        broker = get_broker()
        # Should be a Dramatiq broker instance
        assert broker is not None
        assert hasattr(broker, "enqueue")
```

**Step 3: Write minimal implementation**

```python
# backend/execution/__init__.py
"""Campaign execution plane — workers, engines, replay."""

# backend/execution/workers/__init__.py
"""Dramatiq worker actors."""

# backend/execution/broker.py
"""Dramatiq broker configuration with Redis backend.

Redis is already running on port 6380 (local dev) or 6379 (Docker).
"""
from __future__ import annotations

import os

import dramatiq
from dramatiq.brokers.redis import RedisBroker

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6380")

QUEUE_NAMES = {
    "control": "qh_control",       # LM jobs: extractors, planners, compilers, steering, analysts
    "package": "qh_package",       # Package/validate harnesses
    "fuzz": "qh_fuzz",             # Run methodology lanes
    "replay": "qh_replay",         # Replay and minimize artifacts
}

_broker: RedisBroker | None = None


def get_broker() -> RedisBroker:
    """Get or create the Dramatiq Redis broker singleton."""
    global _broker
    if _broker is None:
        _broker = RedisBroker(url=REDIS_URL)
        dramatiq.set_broker(_broker)
    return _broker
```

Also create `backend/tests/execution/__init__.py`.

**Step 4: Run test to verify it passes**

Run: `cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend && python -m pytest tests/execution/test_broker.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add backend/execution/ backend/tests/execution/ backend/requirements.txt
git commit -m "feat: add Dramatiq broker with Redis backend"
```

---

### Task 7: Base Job Framework

**Files:**
- Create: `backend/execution/jobs.py`
- Test: `backend/tests/execution/test_jobs.py`

**Step 1: Write the failing test**

```python
# backend/tests/execution/test_jobs.py
import pytest
from execution.jobs import (
    JobType,
    JOB_QUEUE_MAP,
    PackageLaneBundleJob,
    HarnessValidationJob,
    RunLaneJob,
    ReplayJob,
    MinimizationJob,
)


class TestJobTypes:
    def test_job_type_enum(self):
        assert JobType.PACKAGE_LANE_BUNDLE.value == "package_lane_bundle"
        assert JobType.HARNESS_VALIDATION.value == "harness_validation"
        assert JobType.RUN_LANE.value == "run_lane"
        assert JobType.REPLAY.value == "replay"
        assert JobType.MINIMIZATION.value == "minimization"

    def test_queue_mapping(self):
        assert JOB_QUEUE_MAP[JobType.PACKAGE_LANE_BUNDLE] == "qh_package"
        assert JOB_QUEUE_MAP[JobType.RUN_LANE] == "qh_fuzz"
        assert JOB_QUEUE_MAP[JobType.REPLAY] == "qh_replay"

    def test_job_dataclasses(self):
        job = PackageLaneBundleJob(
            campaign_id="camp_1",
            lane_spec_id="lane_1",
            lane_spec_revision=1,
        )
        assert job.campaign_id == "camp_1"
        assert job.job_type == JobType.PACKAGE_LANE_BUNDLE

    def test_run_lane_job(self):
        job = RunLaneJob(
            campaign_id="camp_1",
            execution_bundle_id="bundle_1",
            cpu_limit="2",
            memory_limit_mb=2048,
            timeout_seconds=3600,
            resource_profile="medium",
        )
        assert job.job_type == JobType.RUN_LANE
        assert job.timeout_seconds == 3600

    def test_replay_job(self):
        job = ReplayJob(
            campaign_id="camp_1",
            artifact_id="art_1",
            execution_bundle_id="bundle_1",
        )
        assert job.job_type == JobType.REPLAY
```

**Step 2: Run test to verify it fails**

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/execution/jobs.py
"""Job type definitions for the campaign execution plane.

Each job type maps to a Dramatiq queue. Jobs are dataclasses that serialize
to JSON for enqueuing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from execution.broker import QUEUE_NAMES


class JobType(str, Enum):
    # Control plane
    EXTRACTOR = "extractor"
    PLANNER = "planner"
    COMPILER = "compiler"
    STEERING = "steering"
    ANALYST = "analyst"
    # Execution plane
    PACKAGE_LANE_BUNDLE = "package_lane_bundle"
    HARNESS_VALIDATION = "harness_validation"
    RUN_LANE = "run_lane"
    REPLAY = "replay"
    MINIMIZATION = "minimization"


JOB_QUEUE_MAP: dict[JobType, str] = {
    JobType.EXTRACTOR: QUEUE_NAMES["control"],
    JobType.PLANNER: QUEUE_NAMES["control"],
    JobType.COMPILER: QUEUE_NAMES["control"],
    JobType.STEERING: QUEUE_NAMES["control"],
    JobType.ANALYST: QUEUE_NAMES["control"],
    JobType.PACKAGE_LANE_BUNDLE: QUEUE_NAMES["package"],
    JobType.HARNESS_VALIDATION: QUEUE_NAMES["package"],
    JobType.RUN_LANE: QUEUE_NAMES["fuzz"],
    JobType.REPLAY: QUEUE_NAMES["replay"],
    JobType.MINIMIZATION: QUEUE_NAMES["replay"],
}


@dataclass
class BaseJob:
    campaign_id: str
    job_type: JobType = field(init=False)


@dataclass
class PackageLaneBundleJob(BaseJob):
    lane_spec_id: str = ""
    lane_spec_revision: int = 1
    job_type: JobType = field(default=JobType.PACKAGE_LANE_BUNDLE, init=False)


@dataclass
class HarnessValidationJob(BaseJob):
    execution_bundle_id: str = ""
    job_type: JobType = field(default=JobType.HARNESS_VALIDATION, init=False)


@dataclass
class RunLaneJob(BaseJob):
    execution_bundle_id: str = ""
    cpu_limit: str = "1"
    memory_limit_mb: int = 1024
    timeout_seconds: int = 1800
    resource_profile: str = "light"
    job_type: JobType = field(default=JobType.RUN_LANE, init=False)


@dataclass
class ReplayJob(BaseJob):
    artifact_id: str = ""
    execution_bundle_id: str = ""
    job_type: JobType = field(default=JobType.REPLAY, init=False)


@dataclass
class MinimizationJob(BaseJob):
    artifact_id: str = ""
    execution_bundle_id: str = ""
    budget_seconds: int = 60
    job_type: JobType = field(default=JobType.MINIMIZATION, init=False)
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add backend/execution/jobs.py backend/tests/execution/test_jobs.py
git commit -m "feat: add job type definitions and queue mapping"
```

---

### Task 8: Campaign Service (CRUD)

**Files:**
- Create: `backend/services/campaign_service.py`
- Test: `backend/tests/services/test_campaign_service.py`

**Step 1: Write the failing test**

```python
# backend/tests/services/test_campaign_service.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from services.campaign_service import CampaignService
from models.campaign_schemas import CampaignCreateRequest


class TestCampaignService:
    @pytest.mark.asyncio
    async def test_create_campaign(self):
        service = CampaignService()
        request = CampaignCreateRequest(
            repo_id="proj_123",
            campaign_preset="quick",
        )
        # Mock DB session
        with patch("services.campaign_service.get_session") as mock_session_ctx:
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            campaign = await service.create_campaign(request)

        assert campaign.repo_id == "proj_123"
        assert campaign.status == "created"
        assert campaign.preset == "quick"
        assert campaign.id is not None
        assert len(campaign.id) == 8

    @pytest.mark.asyncio
    async def test_create_campaign_budget_from_preset(self):
        service = CampaignService()
        request = CampaignCreateRequest(
            repo_id="proj_123",
            campaign_preset="medium",
        )
        with patch("services.campaign_service.get_session") as mock_session_ctx:
            mock_session = AsyncMock()
            mock_session_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

            campaign = await service.create_campaign(request)

        assert campaign.budget_seconds == 1800  # medium = 30 min
```

**Step 2: Run test to verify it fails**

Expected: FAIL

**Step 3: Write minimal implementation**

```python
# backend/services/campaign_service.py
"""Campaign lifecycle service — create, start, pause, resume, cancel."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from database.connection import get_session
from database.campaign_models import Campaign as DBCampaign
from models.campaign_schemas import CampaignCreateRequest, CampaignResponse
from models.campaign_enums import CampaignStatus

PRESET_BUDGETS: dict[str, int] = {
    "quick": 600,       # 10 min
    "medium": 1800,     # 30 min
    "advanced": 7200,   # 2 hrs
    "pro": 21600,       # 6 hrs
    "ultra": 86400,     # 24 hrs
    "evil": 259200,     # 72 hrs
}


class CampaignService:
    """Manages campaign lifecycle."""

    async def create_campaign(self, request: CampaignCreateRequest) -> CampaignResponse:
        campaign_id = str(uuid.uuid4())[:8]
        budget = request.budget_seconds or PRESET_BUDGETS.get(request.campaign_preset, 600)

        db_campaign = DBCampaign(
            id=campaign_id,
            repo_id=request.repo_id,
            status=CampaignStatus.CREATED.value,
            preset=request.campaign_preset,
            budget_seconds=budget,
            max_parallel_lanes=request.max_parallel_lanes,
            lm_provider=request.lm_provider,
            lm_model=request.lm_model,
            config=request.model_dump(exclude_none=True),
            created_at=datetime.now(timezone.utc),
        )

        async with get_session() as session:
            session.add(db_campaign)
            await session.commit()

        return CampaignResponse(
            id=campaign_id,
            repo_id=request.repo_id,
            status=CampaignStatus.CREATED.value,
            preset=request.campaign_preset,
            budget_seconds=budget,
            max_parallel_lanes=request.max_parallel_lanes,
            created_at=db_campaign.created_at,
        )


campaign_service = CampaignService()
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add backend/services/campaign_service.py backend/tests/services/test_campaign_service.py
git commit -m "feat: add campaign service with create operation"
```

---

### Task 9: Campaign Router (Basic CRUD)

**Files:**
- Create: `backend/routers/campaigns.py`
- Test: `backend/tests/routers/test_campaigns.py`

**Step 1: Write the failing test**

```python
# backend/tests/routers/test_campaigns.py
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient


class TestCampaignRouter:
    def test_create_campaign_endpoint_exists(self):
        """Verify the endpoint is registered and returns 200 with valid input."""
        from main import app
        # Just verify the route exists — full integration test later
        routes = [r.path for r in app.routes]
        assert "/api/campaigns" in routes or any("/campaigns" in r for r in routes)
```

**Step 2: Run test to verify it fails**

Expected: FAIL — no campaigns route registered

**Step 3: Write minimal implementation**

```python
# backend/routers/campaigns.py
"""Campaign management API router."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.auth import AuthContext, require_auth
from models.campaign_schemas import CampaignCreateRequest, CampaignResponse
from services.campaign_service import campaign_service

router = APIRouter()


@router.post("", response_model=CampaignResponse)
async def create_campaign(
    request: CampaignCreateRequest,
    auth_context: AuthContext = Depends(require_auth),
):
    """Create a new fuzzing campaign."""
    try:
        return await campaign_service.create_campaign(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=list[CampaignResponse])
async def list_campaigns(
    repo_id: str | None = None,
    auth_context: AuthContext = Depends(require_auth),
):
    """List campaigns with optional repo filter."""
    return await campaign_service.list_campaigns(repo_id=repo_id)


@router.get("/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(
    campaign_id: str,
    auth_context: AuthContext = Depends(require_auth),
):
    """Get campaign details."""
    campaign = await campaign_service.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return campaign
```

Then register the router in `main.py`:

Add to `main.py` imports:
```python
from routers.campaigns import router as campaigns_router
```

Add to router registration:
```python
app.include_router(campaigns_router, prefix="/api/campaigns", tags=["campaigns"])
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add backend/routers/campaigns.py backend/tests/routers/test_campaigns.py backend/main.py
git commit -m "feat: add campaign router with create/list/get endpoints"
```

---

### Task 10: Verify Full Stack — All Tests Pass

**Step 1: Run all existing tests to verify nothing broke**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend
python -m pytest tests/ --ignore=tests/agents/test_deep_audit_integration.py --ignore=tests/agents/deep_audit/test_foundation_integration.py --ignore=tests/integration -q --tb=short
```

Expected: All existing tests still pass + all new tests pass. The 4 pre-existing failures are acceptable.

**Step 2: Verify app starts**

```bash
cd /Users/0xkato/Desktop/Hobby/claude_apps/quick_hacker/.worktrees/campaign-pivot/backend
python -c "import main; print('OK')"
```

Expected: OK (no import errors)

**Step 3: Commit**

```bash
git add -A
git commit -m "chore: verify full test suite passes after step 1+2"
```
