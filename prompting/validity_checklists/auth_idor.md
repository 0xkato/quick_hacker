# Authorization / IDOR Proof Checklist

You are analyzing a potential authorization bypass or Insecure Direct Object Reference (IDOR) vulnerability. Follow this evidence-gathering plan:

## Pattern A: Authentication Bypass

**Goal:** Prove that a protected resource can be accessed without authentication.

### 1. Identify the Sink (sink_present)

**Evidence Required:**
- Exact file path and line number of the protected operation
- Operation type: database query, file access, admin function, sensitive data retrieval

**Tool Call Example:**
```json
{
  "tool": "RipgrepTool",
  "arguments": {
    "pattern": "(User\\.objects\\.get|db\\.query|admin_only|@admin_required)",
    "file_pattern": "**/*.py",
    "case_sensitive": false
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if protected operation found
- `sink_present = PROVEN_FALSE` if no protected operations
- `sink_present = UNKNOWN` if files are missing

### 2. Identify the Source (source_controlled_input)

**Evidence Required:**
- Attacker can trigger the request (HTTP endpoint, API route)
- NOT an internal function

**Tool Call Example:**
```json
{
  "tool": "GetRoutesTool",
  "arguments": {}
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if externally accessible route
- `source_controlled_input = PROVEN_FALSE` if internal-only function
- `source_controlled_input = UNKNOWN` if unclear

### 3. Verify Missing Authentication (security_control_bypassed)

**Goal:** Prove that authentication is NOT required.

**Evidence Required:**
- No `@login_required`, `@auth.required`, or similar decorator
- No authentication middleware for this route
- No explicit auth checks in function body

**Tool Call Example:**
```json
{
  "tool": "ReadFileTool",
  "arguments": {
    "file_path": "app/routes.py",
    "line_start": 50,
    "line_end": 80
  }
}
```

```json
{
  "tool": "GetAuthGatesTool",
  "arguments": {}
}
```

**Checklist Update:**
- `security_control_bypassed = PROVEN_TRUE` if no auth required
- `security_control_bypassed = PROVEN_FALSE` if auth is enforced
- `security_control_bypassed = UNKNOWN` if auth logic is unclear

### 4. dataflow_evidenced for Auth Bypass

**Interpretation:**
- For auth bypass, `dataflow_evidenced` means: attacker request → unprotected endpoint → sensitive operation
- If route is unprotected and calls sensitive function, `dataflow_evidenced = PROVEN_TRUE`

### 5. boundary_crossed for Auth Bypass

**Interpretation:**
- `boundary_crossed = PROVEN_TRUE` if endpoint is externally accessible (public API)
- `boundary_crossed = PROVEN_FALSE` if localhost-only or internal service

---

## Pattern B: IDOR (Insecure Direct Object Reference)

**Goal:** Prove that a user can access/modify resources belonging to other users.

### 1. Identify the Sink (sink_present)

**Evidence Required:**
- Exact file path and line number of resource access
- Operation: `User.objects.get(id=user_id)`, `db.query("SELECT * FROM orders WHERE id = ?", [order_id])`

**Tool Call Example:**
```json
{
  "tool": "RipgrepTool",
  "arguments": {
    "pattern": "(objects\\.get|db\\.query|find_by_id)\\(.*id",
    "file_pattern": "**/*.py",
    "case_sensitive": false
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if resource access found
- `sink_present = PROVEN_FALSE` if no resource access
- `sink_present = UNKNOWN` if files are missing

### 2. Identify the Source (source_controlled_input)

**Evidence Required:**
- User provides the resource ID: `request.args.get('id')`, `request.json['order_id']`, URL path parameter

**Tool Call Example:**
```json
{
  "tool": "ReadFileTool",
  "arguments": {
    "file_path": "app/orders.py",
    "line_start": 20,
    "line_end": 50
  }
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if user provides ID
- `source_controlled_input = PROVEN_FALSE` if ID is from session or internal
- `source_controlled_input = UNKNOWN` if ID origin is unclear

### 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user-provided ID flows to resource access without ownership check.

**Safe Pattern:**
```python
order_id = request.args.get('id')
order = Order.objects.get(id=order_id, user_id=current_user.id)  # Ownership check present
# dataflow_evidenced = PROVEN_FALSE
```

**Unsafe Pattern:**
```python
order_id = request.args.get('id')
order = Order.objects.get(id=order_id)  # No ownership check
# dataflow_evidenced = PROVEN_TRUE
```

**Tool Call Example:**
```json
{
  "tool": "CallGraphTool",
  "arguments": {
    "function_name": "get_order",
    "max_depth": 2
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if no ownership check
- `dataflow_evidenced = PROVEN_FALSE` if ownership check present
- `dataflow_evidenced = UNKNOWN` if logic is unclear

### 4. Verify Authorization Missing (security_control_bypassed)

**Goal:** Prove that no ownership or permission check exists.

**Evidence Required:**
- No check like: `if order.user_id != current_user.id: raise Forbidden`
- No filter like: `Order.objects.filter(user_id=current_user.id)`

**Checklist Update:**
- `security_control_bypassed = PROVEN_TRUE` if no ownership check
- `security_control_bypassed = PROVEN_FALSE` if check is present
- `security_control_bypassed = UNKNOWN` if unclear

---

## Shared Checklist Items (Both Patterns)

### 5. Verify Reachability (reachable)

**Evidence Required:**
- Function is called from registered route
- Not dead code

**Tool Call Example:**
```json
{
  "tool": "GetRoutesTool",
  "arguments": {}
}
```

**Checklist Update:**
- `reachable = PROVEN_TRUE` if route is registered
- `reachable = PROVEN_FALSE` if dead code
- `reachable = UNKNOWN` if unclear

### 6. Verify Boundary Crossing (boundary_crossed)

**Evidence Required:**
- Endpoint is externally accessible
- NOT internal-only

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if external access
- `boundary_crossed = PROVEN_FALSE` if internal-only
- `boundary_crossed = UNKNOWN` if unclear

### 7. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code lacks auth checks
- `not_only_misconfig = PROVEN_FALSE` if only a config issue
- `not_only_misconfig = UNKNOWN` if unclear

---

## StrictClassifier Alignment

**Expected Disposition:**
- If ALL required items are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- If security_control_bypassed is PROVEN_FALSE (auth is enforced) → `BY_DESIGN`
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE`

## Common False Positives

**Trap 1: Session-based access (not IDOR)**
```python
user_id = session['user_id']  # ID from session, not user input
User.objects.get(id=user_id)  # source_controlled_input = PROVEN_FALSE
```

**Trap 2: Admin endpoints with auth**
```python
@admin_required
def delete_user(user_id):  # security_control_bypassed = PROVEN_FALSE
    User.objects.get(id=user_id).delete()
```

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
