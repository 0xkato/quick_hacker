# Vulnerability Triage System

**Version**: 1.0.0
**Last Updated**: 2026-01-12

## Overview

The Vulnerability Triage System is a deterministic, rule-based false positive reduction system that labels every scanner finding with a **disposition** based on proof of exploitability. The system runs automatically after agent scans and dramatically reduces noise by filtering non-actionable findings.

### Key Features

- **Never Drops Findings**: All findings are labeled and stored, never silently discarded
- **Deterministic**: No LLM in classification path - decisions are reproducible and auditable
- **Conservative**: Strict proof requirements for VALID_SECURITY_ISSUE disposition
- **Fast**: 300ms per finding, 15s batch timeout by default
- **Symbol-Centered**: Evidence gathered within function scope using AST + ripgrep
- **Thread-Safe**: Evidence gathering runs in worker thread, DB/flow on main thread

### What It Does

1. **Collects Evidence**: Gathers code context, sources, sinks, auth gates, route registration
2. **Evaluates Proof**: Applies tri-state checklist (PROVEN/DISPROVEN/UNKNOWN) for 6 criteria
3. **Assigns Disposition**: Labels finding based on strict rules + pattern downgrades
4. **Provides Reasoning**: 2-4 bullets explaining why the disposition was chosen
5. **Filters UI**: Only shows reportable findings (VALID_SECURITY_ISSUE, BUG) by default

## Dispositions

The system assigns one of 6 dispositions to every finding:

### Reportable Dispositions

#### VALID_SECURITY_ISSUE
Exploitable vulnerability meeting all proof requirements.

**Requirements**: ALL of these must be PROVEN True:
- **A**: Source controlled by attacker (request parameters, headers, etc.)
- **B**: Dangerous sink present (command exec, SQL, SSRF, deserialization, etc.)
- **C**: Dataflow between source and sink
- **D**: Reachable from external interface (route registration / handler registration)
- **E**: Security boundary crossed (public → privileged operation)
- **F**: Not only exploitable with security disabled

**Example**:
```python
@app.post("/execute")  # D: route registration (REACHABLE)
async def run_command(cmd: str):  # A: request parameter (SOURCE)
    # E: boundary crossed (external → command execution)
    result = subprocess.run(cmd, shell=True)  # B: command injection (SINK)
    return result.stdout
```
→ **VALID_SECURITY_ISSUE**

#### BUG
Security control is bypassed or contradicted.

**Requirements**:
- `security_control_bypassed` is PROVEN True (explicit bypass/skip/ignore markers)
- AND sink_present is PROVEN True
- AND reachable is PROVEN True

**Example**:
```python
@app.post("/admin/delete")
async def delete_user(user_id: str, skip_auth: bool = False):
    if not skip_auth:  # Explicit bypass mechanism
        check_admin()
    db.users.delete(user_id)  # Dangerous operation
```
→ **BUG**

### Non-Reportable Dispositions

#### HARDENING
Defense-in-depth recommendation with no exploitable path.

**Common Cases**:
- Dangerous pattern but no attacker-controlled source
- Missing validation on internal/trusted input
- Deserialization of developer-controlled data

**Example**:
```python
def load_config():
    with open('config.yaml', 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)  # Unsafe, but file is trusted
    return config
```
→ **HARDENING** (no attacker source)

#### MISCONFIGURATION
Only exploitable when security is explicitly disabled.

**Requirements**:
- `not_only_misconfig` is PROVEN False (evidence of "when disabled" pattern)
- AND other requirements met (sink, source, reachable, boundary crossed)

**Example**:
```python
@app.post("/admin/users")
async def create_user(username: str):
    if not settings.REQUIRE_AUTH:  # Only when auth disabled
        db.users.create(username)
```
→ **MISCONFIGURATION**

#### BY_DESIGN
Expected product feature, not a vulnerability.

**Applies To**:
- Code execution endpoints/features (exec, eval, kernel execute)
- SQL builders/connectors with developer-controlled inputs
- Pipelines/ETL with dynamic code

**NEVER Applies To**:
- Command injection (shell=True, create_subprocess_shell)
- User-controlled code/command execution

**Example**:
```python
# In pipelines/transform.py
def execute_transformation(config):
    # Developer-controlled pipeline code
    exec(config['transformation_logic'])
```
→ **BY_DESIGN** (product feature in pipeline context)

**Counter-Example**:
```python
@app.post("/run")
async def run_code(code: str):
    exec(code)  # User-controlled exec
```
→ **VALID_SECURITY_ISSUE** (NOT by design)

#### SPECULATIVE
Insufficient evidence to classify, or triage timeout.

**Common Cases**:
- Missing evidence (no sources/sinks/routes found)
- Timeout during evidence gathering
- Pattern downgrades (SSRF with constant URL, etc.)

## Tri-State Proof Checklist

Every finding is evaluated against 6 checklist items. Each item has a **status** (PROVEN/DISPROVEN/UNKNOWN) and a **value** (true/false).

### Checklist Items

#### A. source_controlled_input
**Question**: Is the input controlled by an attacker?

- **PROVEN True**: Request parameters, headers, body, websocket messages
- **DISPROVEN**: Config files, environment variables, hard-coded values
- **UNKNOWN**: Cannot determine origin

#### B. sink_present
**Question**: Is there a dangerous operation?

- **PROVEN True**: Command exec, SQL execute, code eval, HTTP client, file ops, deserialization
- **DISPROVEN**: No dangerous operation found
- **UNKNOWN**: Ambiguous code pattern

#### C. dataflow_evidenced
**Question**: Does data flow from source to sink?

- **PROVEN True**: Variable tracing, same function scope, explicit assignment
- **DISPROVEN**: Separate code paths, different variables
- **UNKNOWN**: Complex control flow, insufficient evidence

#### D. reachable
**Question**: Is this code reachable from external interfaces?

**STRICT**: Only route registration or handler registration counts as PROVEN
- **PROVEN True**: @app.route, @app.post, app.add_api_route, WebSocket handlers
- **UNKNOWN**: Missing route registration (local symbol references don't count)

**Why Strict**: Symbol references are too weak - many internal functions are referenced but not exposed.

#### E. boundary_crossed
**Question**: Does this cross a security boundary?

- **PROVEN True**: External input → privileged operation, public → internal resource
- **UNKNOWN**: Internal-only operation, unclear privilege level

#### F. not_only_misconfig
**Question**: Is it exploitable with default/secure config?

- **PROVEN False**: Only when security explicitly disabled (REQUIRE_AUTH=false)
- **PROVEN True**: Public route, explicit bypass, no auth check
- **UNKNOWN**: Missing auth check (could be middleware)

### Special Checklist Item

#### security_control_bypassed (for BUG disposition)
**Question**: Is there an explicit bypass of security controls?

- **PROVEN True**: skip_auth, bypass_rbac, ignore_permissions flags within same scope
- **UNKNOWN**: No bypass evidence (default)

## Pattern-Based Downgrades

After checklist evaluation, pattern rules may **downgrade** the disposition. Pattern rules can ONLY downgrade, never upgrade.

### SSRF Downgrades

**Constant URL**:
```python
requests.get("https://api.example.com/health")
```
→ **SPECULATIVE** (not exploitable)

**Config-Only URL**:
```python
url = os.getenv("API_ENDPOINT")
requests.get(url)
```
→ **SPECULATIVE** (integration test, not vulnerability)

### CSWSH Downgrades

**check_origin without ambient credentials**:
```python
if websocket.headers.get("origin") != expected_origin:
    await websocket.close()
```
→ **HARDENING** (defense-in-depth without exploitable impact)

### Deserialization Downgrades

**YAML load without attacker source**:
```python
with open('trusted_config.yaml') as f:
    yaml.load(f, Loader=yaml.Loader)
```
→ **HARDENING** (no attacker control)

### SQL Injection Downgrades

**Connector/pipeline with no request source**:
```python
# In connectors/database.py
def build_query(table, columns):
    # Developer-controlled connector
    query = f"SELECT {','.join(columns)} FROM {table}"
    return execute(query)
```
→ **BY_DESIGN** (product feature)

### Hardcoded Secrets Downgrades

**Example/test/docker files**:
```yaml
# docker-compose.yml
services:
  db:
    environment:
      POSTGRES_PASSWORD: example_password
```
→ **HARDENING** (example file, not production)

## Evidence Collection

Evidence is gathered using a **symbol-centered** approach:

### 1. Symbol Identification
- Parse file with AST (Python) or heuristic scan (other languages)
- Identify enclosing function/class for the reported line
- Extract symbol boundaries (start/end lines)

### 2. Framework Detection
- Check imports in symbol scope: FastAPI, Flask, Django, aiohttp, etc.
- Fallback to repo-level detection (requirements.txt, imports)

### 3. ripgrep Searches

Within symbol scope, search for:
- **Sources**: request, websocket, body, params, headers
- **Sinks**: subprocess, exec, eval, sql.execute, requests.get, yaml.load, pickle.load
- **Auth Gates**: @require_auth, check_admin, verify_token
- **Route Registration**: @app.route, @app.post, app.add_api_route
- **Handler Registration**: WebSocketEndpoint, add_websocket_route

### 4. Symbol References (Weak)
- Find where the symbol is referenced elsewhere
- Does NOT count as reachability proof (too weak)

### 5. SSRF-Specific Analysis
- Detect request call sites (requests.get/post, httpx, aiohttp)
- Check if URL is constant string literal
- Check if URL comes from environment/config only

### Budget Limits

- **Per Finding**: 300ms (default)
- **Batch**: 15s (default)
- **Snippet**: 200 lines max, 8192 bytes
- **Evidence**: 10KB max per finding

### Excluded Directories
`.git`, `.venv`, `venv`, `site-packages`, `node_modules`, `dist`, `build`, `__pycache__`, `.mypy_cache`

## Configuration

### Environment Variables

```bash
# Enable/disable triage system
TRIAGE_ENABLED=true

# Policy version for tracking rule changes
TRIAGE_POLICY_VERSION=1.0.0

# Time budgets (milliseconds)
TRIAGE_BATCH_BUDGET_MS=15000           # Max batch time
TRIAGE_PER_FINDING_BUDGET_MS=300       # Max per finding

# Evidence limits
TRIAGE_MAX_EVIDENCE_BYTES=10000        # Max evidence size
TRIAGE_MAX_SNIPPET_LINES=200           # Max snippet lines

# Features
TRIAGE_ENABLE_REDACTION=true           # Redact secrets in evidence
TRIAGE_SHOW_FILTERED_BY_DEFAULT=false  # Show filtered in UI
TRIAGE_ALLOW_MANUAL_OVERRIDE=true      # Allow manual overrides
```

### Configuration Object

```python
from models.schemas import BudgetConfig

budgets = BudgetConfig(
    batch_ms=15000,
    per_finding_ms=300,
    max_evidence_bytes=10000,
    max_snippet_lines=200,
)
```

## Database Schema

### Findings Table Extensions

```sql
ALTER TABLE findings ADD COLUMN IF NOT EXISTS
  batch_id VARCHAR(32),
  disposition VARCHAR(32),
  classification_confidence INTEGER,
  exploit_confidence INTEGER,
  proof_checklist JSONB,
  reasoning JSONB,
  triage_policy_version VARCHAR(16),
  triaged_at TIMESTAMP,
  category VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_findings_batch_id ON findings(batch_id);
CREATE INDEX IF NOT EXISTS idx_findings_disposition ON findings(disposition);
CREATE INDEX IF NOT EXISTS idx_findings_agent_disposition ON findings(agent_id, disposition);
CREATE INDEX IF NOT EXISTS idx_findings_agent_triaged_at ON findings(agent_id, triaged_at);
```

### Evidence Blobs Table

```sql
CREATE TABLE IF NOT EXISTS evidence_blobs (
  id VARCHAR(64) PRIMARY KEY,
  finding_id VARCHAR(64) NOT NULL,
  evidence_type VARCHAR(32) NOT NULL,
  file_path VARCHAR(512),
  line_number INTEGER,
  snippet TEXT CHECK (LENGTH(snippet) <= 8192),
  match_type VARCHAR(32),
  created_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_blobs(finding_id);
```

## API Endpoints

### Re-Triage Findings

**POST** `/api/agents/{agent_id}/triage`

Re-run triage on existing findings with optional budget override.

**Authorization**: Agent owner or admin

**Request Body**:
```json
{
  "finding_ids": ["finding-001", "finding-002"],  // Optional: specific findings
  "budget_override_ms": 20000                     // Optional: override batch budget
}
```

**Response**:
```json
{
  "batch_id": "batch-abc123",
  "triaged_count": 2,
  "reportable_count": 1,
  "by_disposition": {
    "VALID_SECURITY_ISSUE": 1,
    "SPECULATIVE": 1
  },
  "timeout_count": 0,
  "policy_version": "1.0.0"
}
```

### Get Batch Results

**GET** `/api/agents/{agent_id}/triaged-findings/batch/{batch_id}`

Retrieve all findings from a specific triage batch.

**Authorization**: Agent owner or admin

**Query Parameters**:
- `include_evidence=true` - Include evidence snippets (default: false)

**Response**:
```json
{
  "batch_id": "batch-abc123",
  "count": 2,
  "findings": [
    {
      "id": "finding-001",
      "disposition": "VALID_SECURITY_ISSUE",
      "reasoning": [
        "Request parameter flows to subprocess call",
        "Route registration confirms reachability",
        "No authentication check present"
      ],
      "classification_confidence": 95,
      "exploit_confidence": 85,
      "proof_checklist": { ... },
      ...
    }
  ]
}
```

**Security Note**: These endpoints expose code snippets and reasoning. Authorization is strictly enforced.

## User Interface

### Findings Panel

**Disposition Badge** (always shown):
- Color-coded badge for every finding
- VALID_SECURITY_ISSUE: Red
- BUG: Orange
- MISCONFIGURATION: Yellow
- HARDENING: Blue
- BY_DESIGN: Gray
- SPECULATIVE: Light gray

**Severity Badge** (only for reportable):
- Shown only for VALID_SECURITY_ISSUE and BUG
- CRITICAL / HIGH / MEDIUM / LOW

**Filtered Notice**:
- Non-reportable findings show "Filtered by triage" badge
- Tooltip: "This finding was filtered by triage. Click 'Show Filtered' to see why."

**Triage Details** (expanded view):
- Reasoning bullets (2-4)
- Classification confidence (0-100%)
- Exploit confidence (0-100%, only for reportable)

### Show Filtered Toggle

- Button in findings panel header
- Default: OFF (hides non-reportable findings)
- When ON: Shows all findings including filtered
- Counts: "15 of 47 (32 filtered)"

### Flow Visualization

**Triage Gateway Node**:
- Appears in flow graph after findings collection
- Shows reportable/filtered counts
- Top 3 dispositions with counts
- Border color based on dominant disposition (priority order)
- Click to expand: batch ID, policy version, full breakdown

## Troubleshooting

### High Timeout Rate

**Symptom**: Many findings marked SPECULATIVE with "timeout" in reasoning

**Causes**:
- Large codebase with many files to search
- Complex code structure requiring deep analysis
- Budget too restrictive

**Solutions**:
```bash
# Increase batch budget
export TRIAGE_BATCH_BUDGET_MS=30000

# Increase per-finding budget
export TRIAGE_PER_FINDING_BUDGET_MS=500
```

### Too Many False Positives

**Symptom**: Many VALID_SECURITY_ISSUE findings that aren't exploitable

**Check**:
1. Are sources actually attacker-controlled?
2. Is dataflow actually proven?
3. Are routes actually registered?

**Note**: The system is designed to be conservative. Some false positives are acceptable to avoid false negatives.

### Too Many False Negatives

**Symptom**: Real vulnerabilities marked as HARDENING or SPECULATIVE

**Causes**:
- Missing evidence (ripgrep didn't find sources/sinks/routes)
- Non-standard framework or patterns
- Complex dataflow not detected

**Solutions**:
1. Check if framework is detected: Add to evidence gatherer
2. Verify route registration patterns: Add to ripgrep searches
3. Manual review: Use "Show Filtered" toggle to inspect reasoning

### Evidence Not Found

**Symptom**: Empty evidence results, SPECULATIVE disposition

**Causes**:
- File not found (bad path in finding)
- Symbol identification failed
- ripgrep not installed
- Excluded directory

**Solutions**:
```bash
# Verify ripgrep is installed
which rg

# Check file path in finding
ls -la <file_path>

# Check if directory is excluded
# (.git, .venv, node_modules, etc. are excluded by default)
```

### Performance Issues

**Symptom**: Triage takes too long, blocks agent completion

**Solutions**:
```bash
# Reduce batch budget (fail faster)
export TRIAGE_BATCH_BUDGET_MS=10000

# Reduce per-finding budget
export TRIAGE_PER_FINDING_BUDGET_MS=200

# Reduce evidence limits
export TRIAGE_MAX_EVIDENCE_BYTES=5000
export TRIAGE_MAX_SNIPPET_LINES=100
```

**Note**: Triage runs in worker thread and should not block the main event loop.

## Testing

### Running Tests

```bash
cd backend
pytest tests/services/test_strict_classifier.py -v
pytest tests/services/test_finding_triage_service.py -v
```

### Test Coverage

**Strict Classifier Tests**:
- Code execution BY_DESIGN vs command injection VALID
- SSRF pattern downgrades
- CSWSH check_origin without credentials
- Deserialization without attacker source
- SQL injection in connectors
- BUG disposition (auth bypass)
- MISCONFIGURATION (auth disabled)
- Pattern rules only downgrade, never upgrade
- Websocket text doesn't auto-normalize to CSWSH

**Triage Service Tests**:
- Never drops findings (triaged_count == raw_count)
- Batch timeout handling
- Metrics calculation
- Error handling (missing files, invalid paths)
- Budget enforcement

## Limitations

### Not a Zero False Negative System

The triage system prioritizes **reducing false positives** over eliminating false negatives. Real vulnerabilities may be marked as HARDENING or SPECULATIVE if evidence is insufficient.

**Why**: Reducing noise is critical for analyst productivity. A system that catches 80% of real issues with 90% precision is better than one that catches 95% with 20% precision.

### Dataflow Analysis is Heuristic

The system uses heuristics (same function scope, variable tracing) rather than full dataflow analysis. Complex dataflows may not be detected.

### Framework-Specific

Evidence gathering works best with supported frameworks (FastAPI, Flask, Django, aiohttp). Custom frameworks may require additional patterns.

### Static Analysis Limitations

Like all static analysis, the system cannot:
- Evaluate runtime conditions
- Trace through reflection/dynamic code
- Handle complex control flow with 100% accuracy

## Version History

### 1.0.0 (2026-01-12)
- Initial release
- 6 dispositions (VALID, BUG, HARDENING, MISCONFIGURATION, BY_DESIGN, SPECULATIVE)
- Tri-state proof checklist (6 items)
- Symbol-centered evidence gathering
- Pattern-based downgrades (SSRF, CSWSH, deserialization, SQL, secrets)
- Batch timeout handling (15s default)
- Never-drop guarantee (triaged_count == raw_count)

## References

- **Design Document**: See approved design (Parts 1-7)
- **Implementation Status**: `TRIAGE_IMPLEMENTATION_STATUS.md`
- **API Endpoints**: `backend/routers/agents.py`
- **Core Services**: `backend/services/strict_classifier.py`, `backend/services/evidence_gatherer.py`
- **Tests**: `backend/tests/services/`

## Support

For questions or issues:
1. Check this documentation
2. Review `TRIAGE_IMPLEMENTATION_STATUS.md` for implementation details
3. Inspect triage reasoning in UI (expand finding → Triage Details)
4. Use "Show Filtered" toggle to see why findings were filtered
5. Check test cases for expected behavior examples
