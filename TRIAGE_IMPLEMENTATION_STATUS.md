# Vulnerability Triage System - Implementation Status

## Completed Components ✅

### 1. Database Layer
- ✅ `backend/migrations/add_triage_columns.sql` - Complete migration with idempotency
  - Extends findings table with triage columns
  - Creates evidence_blobs table
  - All necessary indexes

- ✅ `backend/database/models.py` - SQLAlchemy ORM models
  - Finding model with all triage fields
  - EvidenceBlob model with relationships
  - Proper indexes and constraints

### 2. Schema Layer
- ✅ `backend/models/schemas.py` - Pydantic models and enums
  - Disposition enum (6 dispositions)
  - ChecklistStatus enum (tri-state)
  - VulnerabilityCategory enum (19 categories)
  - ChecklistItem, ProofChecklist models
  - EvidenceBlob, TriageMetrics, TriageResult models
  - TriageRequest, TriageResponse, BudgetConfig models

### 3. Core Services
- ✅ `backend/services/evidence_gatherer.py` - Symbol-centered evidence collection
  - AST parsing for Python files
  - Heuristic fallback for other languages
  - Framework detection (FastAPI, Flask, Django, aiohttp, etc.)
  - ripgrep-based searches for sources, sinks, auth gates, route registration
  - SSRF-specific URL analysis
  - File caching for performance
  - Strict time budgets (300ms per finding, 15s batch)

- ✅ `backend/services/strict_classifier.py` - Tri-state proof checklist + disposition logic
  - All 6 checklist items (A-F) with PROVEN/DISPROVEN/UNKNOWN logic
  - security_control_bypassed for BUG disposition
  - Strict disposition rules (priority order)
  - Pattern-based downgrades (ONLY downgrades, never upgrades)
  - Conservative BY_DESIGN logic (never for command injection)
  - Confidence scoring (classification + exploit)
  - Reasoning generation (2-4 bullets per finding)

- ✅ `backend/services/finding_triage_service.py` - Orchestration service
  - Batch processing with timeout
  - Coordinates gatherer + classifier
  - GUARANTEES: triaged_count == raw_count (never drops findings)
  - Timeout handling (marks as SPECULATIVE with UNKNOWN checklist)
  - Error handling (graceful degradation)
  - Metrics generation

- ✅ `backend/services/redaction_service.py` - Secret redaction (optional)
  - Precompiled regex patterns
  - API keys, tokens, passwords, JWTs, private keys
  - Database URL passwords
  - Toggle via TRIAGE_ENABLE_REDACTION env var

## Remaining Work 🚧

### 4. Integration (Critical)

#### A. Agent Orchestrator Integration
**File**: `backend/services/agent_orchestrator.py`

**Location**: After findings collection, before storage

**Implementation**:
```python
# After collecting raw findings
if config.TRIAGE_ENABLED:
    from services.finding_triage_service import triage_service
    from models.schemas import BudgetConfig

    budgets = BudgetConfig(
        batch_ms=config.TRIAGE_BATCH_BUDGET_MS,
        per_finding_ms=config.TRIAGE_PER_FINDING_BUDGET_MS,
        max_evidence_bytes=config.TRIAGE_MAX_EVIDENCE_BYTES,
        max_snippet_lines=config.TRIAGE_MAX_SNIPPET_LINES
    )

    # Run triage in thread
    triage_result = await asyncio.to_thread(
        triage_service.triage_findings,
        repo_root=repo_path,
        findings=raw_findings,
        policy_version=config.TRIAGE_POLICY_VERSION,
        budgets=budgets
    )

    # Assert no findings dropped
    assert triage_result.triaged_count == len(raw_findings)

    # Store ALL triaged findings (back on main thread)
    await store_findings(triage_result.triaged_findings, db)

    # Store evidence blobs
    await store_evidence_blobs(triage_result, db)

    # Update agent metrics
    agent.findings_count = triage_result.metrics.reportable_count
    agent.total_findings_count = triage_result.metrics.triaged_count

    # Track triage gateway in flow (main thread)
    from services.tool_core import tool_core
    await tool_core.track_triage_gate(
        agent_id=agent.id,
        batch_id=triage_result.batch_id,
        raw_count=triage_result.metrics.raw_count,
        triaged_count=triage_result.metrics.triaged_count,
        reportable_count=triage_result.metrics.reportable_count,
        by_disposition=triage_result.metrics.by_disposition,
        policy_version=config.TRIAGE_POLICY_VERSION,
        finding_refs=[(f.id, f.disposition.value) for f in triage_result.triaged_findings[:50]]
    )
```

#### B. Tool Core Flow Tracking
**File**: `backend/services/tool_core.py`

**Add method**:
```python
async def track_triage_gate(
    self,
    agent_id: str,
    batch_id: str,
    raw_count: int,
    triaged_count: int,
    reportable_count: int,
    by_disposition: dict[str, int],
    policy_version: str,
    finding_refs: list[tuple[str, str]]  # (finding_id, disposition)
) -> None:
    """Track triage gateway node in flow graph."""
    from models.schemas import TriageGatewayNode  # Add to schemas.py

    node = TriageGatewayNode(
        id=f"triage_gateway_{batch_id}",
        type="triage_gateway",
        label=f"Triage Gateway (v{policy_version})",
        batch_id=batch_id,
        raw_count=raw_count,
        triaged_count=triaged_count,
        reportable_count=reportable_count,
        by_disposition=by_disposition,
        finding_refs=finding_refs,
        total_findings=triaged_count,
        policy_version=policy_version,
        timestamp=datetime.utcnow().isoformat()
    )

    await self.add_node(agent_id, node)
```

**Add to schemas.py**:
```python
class TriageGatewayNode(BaseModel):
    """Triage gateway node in investigation flow."""
    id: str
    type: Literal["triage_gateway"]
    label: str
    batch_id: str
    raw_count: int
    triaged_count: int
    reportable_count: int
    by_disposition: dict[str, int]
    finding_refs: list[dict[str, str]]  # [{id, disposition}, ...]
    total_findings: int
    policy_version: str
    timestamp: str

# Update InvestigationNode union
InvestigationNode = Union[
    # ... existing node types ...
    TriageGatewayNode
]
```

### 5. API Endpoints
**File**: `backend/routers/agents.py`

Add two endpoints (see design Part 6 for full implementation):
1. `POST /api/agents/{agent_id}/triage` - Re-triage findings
2. `GET /api/agents/{agent_id}/triaged-findings/batch/{batch_id}` - Get batch results

### 6. Frontend Updates

#### A. Flow Visualization
**File**: `frontend/components/FlowVisualization/FlowVisualization.tsx`

Add triage gateway node rendering (see design Part 6).

#### B. Findings List
**File**: `frontend/components/FindingsPanel/FindingsList.tsx`

Update to show disposition badges always, severity only for reportable.

#### C. Show Filtered Toggle
Add toggle component to findings panel.

### 7. Configuration
**File**: `backend/config.py`

Add environment variables:
```python
# Triage system configuration
TRIAGE_ENABLED: bool = Field(default=True)
TRIAGE_POLICY_VERSION: str = Field(default="1.0.0")
TRIAGE_BATCH_BUDGET_MS: int = Field(default=15000)
TRIAGE_PER_FINDING_BUDGET_MS: int = Field(default=300)
TRIAGE_MAX_EVIDENCE_BYTES: int = Field(default=10000)
TRIAGE_MAX_SNIPPET_LINES: int = Field(default=200)
TRIAGE_ENABLE_REDACTION: bool = Field(default=True)
TRIAGE_SHOW_FILTERED_BY_DEFAULT: bool = Field(default=False)
```

### 8. Docker/Deployment
**File**: `Dockerfile` (backend)

Add ripgrep installation:
```dockerfile
RUN apt-get update && apt-get install -y \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*
```

### 9. Testing
Create test files with fixtures from design Part 7:
- `backend/tests/services/test_strict_classifier.py`
- `backend/tests/services/test_finding_triage_service.py`
- `backend/tests/services/test_evidence_gatherer.py`

### 10. Documentation
**File**: `docs/triage-system.md`

Complete user documentation (see design Part 7).

## Running Migrations

```bash
# Connect to database
psql $DATABASE_URL

# Run migration
\i backend/migrations/add_triage_columns.sql

# Verify tables
\dt findings
\dt evidence_blobs
```

## Testing the Implementation

```bash
# Run tests
cd backend
pytest tests/services/test_strict_classifier.py -v
pytest tests/services/test_finding_triage_service.py -v

# Test integration (after completing agent_orchestrator integration)
# Start a scan and verify triage runs
```

## Key Guarantees

1. **No findings dropped**: `triaged_count == raw_count` always
2. **Deterministic**: No LLM in decision path
3. **Conservative**: Strict rules for VALID_SECURITY_ISSUE
4. **Transparent**: All findings stored with reasoning
5. **Budgeted**: 300ms per finding, 15s batch timeout
6. **Thread-safe**: Evidence/classification in thread, DB/flow on main thread

## Next Steps

1. Complete agent_orchestrator integration (highest priority)
2. Add tool_core flow tracking method
3. Implement API endpoints
4. Update frontend components
5. Add configuration to config.py
6. Update Dockerfile
7. Write tests
8. Create documentation
9. Run migrations
10. Test end-to-end

## Design Reference

All implementation details are in the approved design (Parts 1-7).
