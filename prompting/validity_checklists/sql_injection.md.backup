# SQL Injection Proof Checklist

You are analyzing a potential SQL injection vulnerability. Follow this evidence-gathering plan:

## 1. Identify the Sink (sink_present)

**Goal:** Prove a SQL query construction/execution happens.

**Evidence Required:**
- Exact file path and line number of SQL execution
- Function name: `execute()`, `executemany()`, `raw()`, `cursor.execute()`, `db.query()`, or similar

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(execute|executemany|raw|cursor\\.execute|db\\.query)\\(",
    "file_pattern": "**/*.py",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if SQL execution found
- `sink_present = PROVEN_FALSE` if no SQL operations in codebase
- `sink_present = UNKNOWN` if files are missing or code is obfuscated

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls the input.

**Evidence Required:**
- Input comes from: request parameters, body, headers, cookies, URL path
- NOT from: hardcoded values, config files, internal variables

**Common Patterns:**
- Flask: `request.args.get()`, `request.form[]`, `request.json[]`
- Django: `request.GET[]`, `request.POST[]`, `request.body`
- FastAPI: Function parameters with `Query()`, `Body()`, `Path()`

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/routes.py",
    "start_line": 20,
    "end_line": 50
  }
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if input is from HTTP request/external source
- `source_controlled_input = PROVEN_FALSE` if input is hardcoded or internal
- `source_controlled_input = UNKNOWN` if input origin is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input flows to SQL query without sufficient sanitization.

**Evidence Required:**
- Step-by-step path from source to sink
- Cite each intermediate variable/function with file:line
- Note any sanitization attempts (but prove they're insufficient)

**Parameterized Queries (Safe Pattern):**
If you see `execute("SELECT * FROM users WHERE id = ?", [user_id])` or similar:
- This IS parameterized (safe)
- `dataflow_evidenced = PROVEN_FALSE` (data flow is blocked by parameterization)

**String Concatenation (Unsafe Pattern):**
If you see `execute(f"SELECT * FROM users WHERE id = {user_id}")` or `"... WHERE id = " + user_id`:
- This is NOT parameterized (unsafe)
- `dataflow_evidenced = PROVEN_TRUE` if you can trace user_id to request input

**Tool Call Example:**
```json
{
  "tool": "trace_data_flow",
  "arguments": {
    "source": "request.args.get('id')",
    "file_path": "app/routes.py",
    "sink_patterns": ["execute(", "executemany("]
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unsanitized flow exists
- `dataflow_evidenced = PROVEN_FALSE` if parameterized or sanitized
- `dataflow_evidenced = UNKNOWN` if intermediate steps are missing

## 4. Verify Reachability (reachable)

**Goal:** Prove the vulnerable code can actually execute.

**Evidence Required:**
- Function is called (not dead code)
- Route/API endpoint is registered
- No conditional guards that make it unreachable

**Tool Call Example:**
```json
{
  "tool": "get_entry_points",
  "arguments": {
    "framework": "flask"
  }
}
```

**Checklist Update:**
- `reachable = PROVEN_TRUE` if function is called and route is registered
- `reachable = PROVEN_FALSE` if dead code or feature-flagged off
- `reachable = UNKNOWN` if call graph is incomplete

## 5. Verify Boundary Crossing (boundary_crossed)

**Goal:** Prove external input reaches the internal SQL execution.

**Evidence Required:**
- Input comes from outside the system (HTTP, CLI, message queue, etc.)
- NOT an internal admin function or debug endpoint

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(@login_required|@auth\\.required|@require_auth)",
    "file_pattern": "**/*.py",
    "max_results": 50
  }
}
```

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if externally accessible (e.g., public API)
- `boundary_crossed = PROVEN_FALSE` if internal-only (e.g., localhost-only admin)
- `boundary_crossed = UNKNOWN` if access controls are unclear

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Evidence Required:**
- Vulnerability exists regardless of config settings
- NOT just "debug mode enabled" or "CORS misconfigured"

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a config issue
- `not_only_misconfig = UNKNOWN` if unclear

## 7. StrictClassifier Alignment

**Expected Disposition:**
- If ALL 6 items are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- If sink_present or source_controlled_input is PROVEN_FALSE → `BY_DESIGN` or `SPECULATIVE`
- If dataflow_evidenced is PROVEN_FALSE (parameterized) → `BY_DESIGN` (safe by design)
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE` (unless preliminary_disposition fast-tracks)

**Disposition-Sensitive Downgrades:**
- If preliminary_disposition is already `BUG` or `VALID_SECURITY_ISSUE`, critic should fast-track to `READY_TO_REPORT` unless contradictions exist
- If preliminary_disposition is `MISCONFIGURATION`, critic should return `STOP_FILTERED` with disposition_hint='MISCONFIGURATION'

## Common False Positives to Avoid

**Trap 1: Query string is built but never executed**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"  # Vulnerable pattern
# But if execute(query) never happens, sink_present = PROVEN_FALSE
```

**Trap 2: Parameterized queries with misleading formatting**
```python
# This LOOKS like string formatting but is actually parameterized:
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])  # SAFE
# %s here is a parameterization placeholder, not Python string formatting
```

**Trap 3: ORM usage (often safe)**
```python
User.objects.filter(id=user_id)  # Django ORM - parameterized by default
# dataflow_evidenced = PROVEN_FALSE (ORM handles sanitization)
```

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
- Never say "I believe" or "it appears" - use UNKNOWN if uncertain
