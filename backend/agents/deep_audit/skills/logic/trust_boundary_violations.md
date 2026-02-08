# Trust Boundary Violation Detection

## Methodology

This skill targets a vulnerability class that traditional sink-pattern-matching cannot find: violations of trust boundaries where data crosses from an untrusted zone to a trusted zone without proper validation or where the boundary enforcement itself is flawed.

### Step 1: Identify Trust Boundaries from the Security Map

Trust boundaries are defined in the Security Map's `trust_boundaries.json`. For each boundary, understand:

1. **What zones does it separate?** (e.g., "internet → application", "user-space → admin-space", "tenant A → tenant B")
2. **What enforcement mechanism exists?** (middleware, validation layer, auth check, sanitizer)
3. **What data crosses the boundary?** (request bodies, headers, file uploads, database results, inter-service messages)
4. **What assumptions does the trusted zone make about data that has crossed?** (e.g., "all input is validated by Pydantic", "user ID in token is correct")

### Step 2: Verify Boundary Enforcement is Complete

For each trust boundary, check:

**Is the enforcement applied to ALL crossing points?**
- List every place where data from the untrusted zone enters the trusted zone
- For each crossing point, verify the enforcement mechanism is active
- Look for: new endpoints added without middleware, internal APIs exposed externally, websocket handlers missing auth

**Is the enforcement mechanism correct?**
- Does it validate what it claims to validate?
- Can it be bypassed? (encoding, case sensitivity, null bytes, unicode normalization)
- Does it fail open or fail closed?
- Is there a TOCTOU gap? (check happens, then data changes before use)

**Is the enforcement mechanism sufficient?**
- Does it cover all attack vectors for this boundary type?
- Example: Pydantic validates types but not business logic constraints
- Example: Auth middleware checks identity but not authorization (can access, but should they?)

### Step 3: Hunt for Implicit Trust

The most dangerous trust boundary violations are **implicit** — where code trusts data without any explicit check because the developer assumed the data was already validated.

**Patterns to look for:**

**Cross-service trust:**
```python
# Service A validates input and calls Service B
# Service B trusts the input because "Service A already validated it"
# But: what if Service B is also called directly? Or by Service C that doesn't validate?

@app.route("/api/process")
def process_item(item_id: int):
    item = internal_service.get_item(item_id)  # Trusted because "we fetched it ourselves"
    # But: what if internal_service.get_item returns data from an external source?
    execute_query(f"UPDATE items SET status = '{item.status}'")  # Trusts item.status
```

**Database trust:**
```python
# "Data from our database is trusted" — but who put it there?
user = db.get_user(user_id)
# If user.bio was stored from user input without sanitization,
# using it in HTML without escaping is XSS
return f"<div class='bio'>{user.bio}</div>"
```

**Environment/config trust:**
```python
# "Config values are trusted" — but who sets them?
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")
# If ALLOWED_HOSTS comes from a user-editable config file, dashboard, or
# shared environment, it's not truly trusted
```

**Inter-process trust:**
```python
# "Messages from our message queue are trusted"
@celery.task
def process_payment(payment_data: dict):
    # If any service can publish to this queue, the data is not trusted
    # Even if only our service publishes, was the original input validated?
    amount = payment_data["amount"]
    recipient = payment_data["recipient"]
    transfer(amount, recipient)  # No validation of amount or recipient
```

### Step 4: Check Boundary Consistency

**Inconsistent enforcement across similar endpoints:**
```python
# POST /api/items — validates input ✓
@app.post("/api/items")
def create_item(data: ItemCreateSchema):  # Pydantic validates
    return create_item(data)

# PUT /api/items/<id> — different validation level ✗
@app.put("/api/items/<id>")
def update_item(id: int):
    data = request.json  # Raw JSON, no Pydantic validation!
    return update_item_in_db(id, data)
```

**One-way enforcement:**
```python
# Input is validated, but output is not
# If service returns data that includes user input from other users,
# the consumer trusts it as "from the API = safe"
@app.get("/api/comments")
def get_comments():
    comments = db.get_comments()  # Contains user-submitted HTML
    return jsonify(comments)      # Consumer renders without escaping
```

### Step 5: Evaluate Multi-Tenant Boundaries

For multi-tenant systems, the tenant isolation boundary is critical:

1. **Data isolation**: Can Tenant A query Tenant B's data?
   - Check: Is tenant_id included in ALL queries, not just some?
   - Check: Is tenant_id from the auth token, not from request params?
   - Check: Are there any admin/superuser bypasses that skip tenant filtering?

2. **Resource isolation**: Can Tenant A affect Tenant B's resources?
   - Check: Rate limits per tenant, not global
   - Check: File storage namespaced by tenant
   - Check: Background jobs scoped to tenant

3. **Configuration isolation**: Can Tenant A see Tenant B's config?
   - Check: API keys, webhooks, settings per tenant
   - Check: Error messages don't leak cross-tenant info

### Step 6: Classify

- **VULNERABLE (Critical)**: Trust boundary completely absent where one should exist (e.g., internal API exposed without auth)
- **VULNERABLE (High)**: Boundary exists but is bypassable (path manipulation, encoding tricks)
- **VULNERABLE (High)**: Multi-tenant isolation missing on data query
- **HARDENED (Medium)**: Boundary inconsistently applied (some endpoints protected, some not)
- **HARDENED (Medium)**: Implicit trust of database/queue data that originates from user input
- **HARDENED (Low)**: Boundary exists but doesn't cover all vectors (validates types but not business logic)
- **SAFE**: All crossing points enforced, mechanism correct and sufficient
- **BY_DESIGN**: Intentionally open boundary (document why)

## Decision Tree

```
Is there a trust boundary defined in the Security Map?
├── No → Should there be one? (data crosses from less-trusted to more-trusted zone)
│   ├── Yes → VULNERABLE (Critical — missing boundary)
│   └── No → Not applicable
└── Yes → Is the boundary enforced at ALL crossing points?
    ├── No → Are the unprotected crossing points reachable?
    │   ├── Yes → VULNERABLE (Critical/High)
    │   └── No (dead code, internal only) → HARDENED (Low — document)
    └── Yes → Is the enforcement mechanism correct?
        ├── No (bypassable, fails open) → VULNERABLE (High)
        └── Yes → Is the enforcement sufficient?
            ├── No (validates type but not logic) → HARDENED (Medium)
            └── Yes → Does code AFTER the boundary still trust data implicitly?
                ├── Yes (database trust, queue trust) → HARDENED (Medium)
                └── No → SAFE
```

## Real-World Examples

### Example 1: Tenant Isolation Missing on API Endpoint

**Vulnerable pattern:**
```python
@app.get("/api/documents/{doc_id}")
@require_auth
def get_document(doc_id: int, current_user: User):
    # BUG: No tenant filter — any authenticated user can access any document
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(404)
    return doc

# Correct version for comparison:
@app.get("/api/documents/{doc_id}")
@require_auth
def get_document(doc_id: int, current_user: User):
    doc = db.query(Document).filter(
        Document.id == doc_id,
        Document.tenant_id == current_user.tenant_id  # Tenant scoping!
    ).first()
    if not doc:
        raise HTTPException(404)
    return doc
```

**Why vulnerable:** Authentication is enforced (user must be logged in), but authorization/tenant scoping is missing. User from Tenant A can request `GET /api/documents/42` and see Tenant B's document by guessing IDs. This is an IDOR (Insecure Direct Object Reference) at the tenant boundary.

**Impact:** Complete cross-tenant data leakage.

### Example 2: Internal Service Exposed Without Auth

**Vulnerable pattern:**
```yaml
# docker-compose.yml
services:
  api:
    ports:
      - "8080:8080"   # Public API — has auth middleware

  admin-service:
    ports:
      - "9090:9090"   # Internal admin service — NO auth
                       # Developers assumed this was only reachable internally
                       # But it's bound to 0.0.0.0 and exposed through port mapping
```

```python
# admin_service.py — no auth because "it's internal"
@app.delete("/admin/user/{user_id}")
def delete_user(user_id: int):
    db.query(User).filter(User.id == user_id).delete()
    return {"status": "deleted"}
```

**Why vulnerable:** The admin service was designed as an internal tool but is accidentally exposed to the network. No authentication because the developer assumed only internal services would call it. Any network-accessible attacker can delete arbitrary users.

### Example 3: Celery Task Trusting Queue Data

**Vulnerable pattern:**
```python
# API endpoint — validates input
@app.post("/api/reports/generate")
@require_auth
def generate_report(request: ReportRequest):  # Pydantic validates
    # Enqueue for async processing
    celery_app.send_task("generate_report", args=[request.dict()])
    return {"status": "queued"}

# Celery worker — trusts data from queue
@celery_app.task
def generate_report(report_data: dict):
    template_name = report_data["template"]
    # DANGEROUS: template_name was validated by Pydantic at the API layer,
    # but what if another service or admin tool also publishes to this queue
    # without the same validation?
    template = jinja_env.get_template(template_name)  # Path traversal risk
    output = template.render(report_data)
    save_report(output)
```

**Why vulnerable:** The API layer validates with Pydantic, but the Celery worker trusts the queue data implicitly. If any other service, admin tool, or compromised component can publish to the same queue, the validation is bypassed. The trust boundary between "validated API input" and "queue message" is implicit.

### Example 4: False Positive — Validated at the Right Layer

```python
# This looks like implicit trust but is actually correct
@app.post("/api/orders")
@require_auth
def create_order(order: OrderCreate, current_user: User):
    # Pydantic validates structure
    # Auth middleware validates identity
    # Service layer validates business logic
    order_service.create(
        user_id=current_user.id,      # From auth token (trusted)
        items=order.items,             # Pydantic validated (trusted structure)
        total=calculate_total(order),  # Server-calculated (trusted)
    )
```

**Why safe:** Each piece of data is validated at the appropriate layer. User identity comes from the auth token (not request body). Order structure is Pydantic-validated. Total is server-calculated, not client-submitted. The trust boundaries are properly enforced.

## Common False Positive Patterns

1. **Server-calculated values**: Data computed by the server itself (timestamps, totals, IDs) — doesn't cross a trust boundary
2. **Framework-enforced boundaries**: Django's CSRF middleware, Rails' strong parameters — check if framework is configured correctly before flagging
3. **Properly scoped internal services**: Service A calls Service B over authenticated internal network with service-to-service auth tokens
4. **Read-only public data**: Public endpoint returning non-sensitive, non-user-specific data
5. **Webhook with HMAC verification**: Looks unauthenticated, but body is HMAC-verified (check HMAC implementation correctness separately)
