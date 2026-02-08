# IDOR Detection

## Methodology

### Step 1: Identify Object Reference Points

Map every location where a user-supplied identifier fetches, modifies, or deletes a resource.

- **Path params:** `/api/users/{id}`, `/api/orders/{order_id}`, `/api/files/{filename}`
- **Query params:** `?user_id=123`, `?doc_id=abc`
- **Request body:** `{"account_id": 456}`
- **GraphQL:** `query { user(id: "123") { email, ssn } }`, `mutation { deletePost(postId: "abc") { success } }`
- **gRPC:** `rpc GetUserProfile (UserRequest) returns (UserProfile);` where `UserRequest` contains a user-supplied ID

**Search strategy:**
- Grep route definitions for path params: `{id}`, `:id`, `<int:id>`
- Grep handlers for `request.params`, `request.query`, `request.body` accessing ID-like fields
- Check ORM calls where `.find()`, `.findById()`, `.get()`, or `WHERE id =` uses a request-supplied value

### Step 2: Check Authorization on Each Reference

For each object reference, answer three questions:

**Q1: Is there an ownership or permission check?**
```python
# VULNERABLE — no check
@app.route("/api/orders/<order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)  # Fetches ANY order
    return jsonify(order.to_dict())

# SAFE — ownership verified
@app.route("/api/orders/<order_id>")
@login_required
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return jsonify(order.to_dict())
```

**Q2: WHERE does the check happen?**

| Location | Reliability | Notes |
|---|---|---|
| Query filter (best) | High | `filter_by(id=order_id, user_id=current_user.id)` — impossible to fetch wrong user's data |
| Service layer | High | Centralized, all callers go through it |
| Middleware/decorator | Medium | Good if consistent, easy to forget on new routes |
| Controller/handler | Low | Per-endpoint, duplicated logic, easy to miss one |
| Missing entirely | Critical | IDOR vulnerability |

**Q3: Is the check on the CORRECT field?**
```python
# WRONG — user_id from request body, attacker controls it
user = User.query.get(request.json["user_id"])

# RIGHT — user_id from auth token, server controls it
user = User.query.get(current_user.id)
```

### Step 3: Check Reference Predictability

| ID Type | Enumerable? | Risk Multiplier |
|---|---|---|
| Sequential integer (1, 2, 3...) | Trivially | High — iterate all IDs |
| Timestamp-based | Mostly | Medium — narrow window |
| UUID v4 | No | Low — but UUIDs are NOT secrets |
| UUID v1 | Partially | Medium — contains MAC + timestamp |
| Slug/filename | Guessable | Medium — common names, directory listing |

Key principle: **unpredictable IDs are defense-in-depth, NOT a substitute for authorization checks.** A UUID-based IDOR is still a logic flaw — if a user leaks their URL, another user accesses their resource.

### Step 4: Multi-Tenant Context

Every resource query MUST include the tenant boundary.

```python
# VULNERABLE — no tenant scope
def get_invoices(user_id):
    return Invoice.query.filter_by(user_id=user_id).all()

# SAFE — tenant-scoped, tenant_id from auth token
def get_invoices(user_id, tenant_id):
    return Invoice.query.filter_by(user_id=user_id, tenant_id=tenant_id).all()
```

**Checklist:**
- Does tenant_id come from the auth token (safe) or the request (vulnerable)?
- Are admin paths scoped to their own tenant, or do they leak cross-tenant data?
- Do caching keys, file storage paths, and background jobs include tenant_id?

### Step 5: Classify

- **VULNERABLE (High)**: No ownership/permission check on user-supplied ID. Sequential IDs make exploitation trivial.
- **VULNERABLE (High)**: Tenant scoping missing — cross-tenant data leak.
- **VULNERABLE (Medium)**: UUID-based but no ownership check (requires ID leak to exploit, still broken auth logic).
- **VULNERABLE (Medium)**: Ownership check uses attacker-controlled value (user_id from request body instead of auth token).
- **HARDENED (Low)**: Ownership check in the wrong layer (controller instead of service/query). Correct but fragile.
- **HARDENED (Low)**: Ownership check for read but missing for update/delete on the same resource.
- **SAFE**: Ownership/permission check at query or service layer, tenant_id from auth token, all CRUD operations covered.
- **BY_DESIGN**: Intentionally shared resource (public content, workspace with explicit access grants).

## Decision Tree

```
Does the endpoint accept a user-supplied resource identifier?
├── No → Not an IDOR target (skip)
└── Yes → Does the code verify the requester owns/can access the resource?
    ├── No check at all → Is the ID sequential/guessable?
    │   ├── Yes → VULNERABLE (High)
    │   └── No (UUID v4) → VULNERABLE (Medium)
    ├── Check exists → Is the identity source correct?
    │   ├── From auth token/session →
    │   │   ├── At query/service layer → SAFE
    │   │   └── At controller only → HARDENED (Low)
    │   └── From request body/header → VULNERABLE (Medium)
    └── Resource is intentionally public → BY_DESIGN

Multi-tenant second pass:
    Is tenant_id in every resource query?
    ├── No → VULNERABLE (High)
    └── Yes → From auth token?
        ├── Yes → SAFE
        └── No → VULNERABLE (High)
```

## Real-World Examples

### Example 1: User Accesses Other Users' Orders (Vulnerable)

```python
# Python/Flask
@app.route("/api/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    # BUG: No check that current_user owns this order
    return jsonify({
        "id": order.id,
        "items": [item.to_dict() for item in order.items],
        "shipping_address": order.shipping_address,  # PII leak
        "payment_last4": order.payment_last4          # Financial data leak
    })
```

**Exploitation:** Authenticated user sends `GET /api/orders/1`, then `/api/orders/2`, etc. Sequential IDs make enumeration trivial.

**Impact:** Full order history of all users exposed, including PII and payment info. Triggers GDPR/CCPA breach notification.

**Fix:** Scope the query to the authenticated user:
```python
order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
```

### Example 2: Admin Endpoint Missing Tenant Scope (Vulnerable)

```javascript
// Node.js/Express — tenant admin dashboard
router.get("/admin/users", requireRole("tenant_admin"), async (req, res) => {
    // BUG: No tenant_id filter — returns users from ALL tenants
    const users = await db.query(
        "SELECT id, email, name, role FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        [50, (parseInt(req.query.page) || 0) * 50]
    );
    res.json({ users: users.rows });
});
```

**Exploitation:** Tenant admin at `acme-corp` paginates through `GET /admin/users?page=0,1,2...` and sees users from every tenant.

**Impact:** Cross-tenant data exposure in B2B SaaS. Customer lists leaked between competing companies.

**Fix:** Add tenant_id from the verified JWT:
```javascript
const users = await db.query(
    "SELECT id, email, name, role FROM users WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    [req.user.tenant_id, 50, (parseInt(req.query.page) || 0) * 50]
);
```

### Example 3: False Positive — Public Product Catalog

```javascript
// Node.js/Express — intentionally public
router.get("/api/products/:productId", async (req, res) => {
    const product = await Product.findOne({
        where: { id: req.params.productId, status: "published" },
        attributes: ["id", "name", "description", "price", "imageUrl"]
    });
    if (!product) return res.status(404).json({ error: "Not found" });
    res.json(product);
});
```

**Why NOT vulnerable:** The catalog is intentionally public, only `published` items are returned, the attribute list excludes sensitive fields (`supplier_cost`, `internal_notes`), and no user-specific data is involved. **Would** be a problem if it returned draft products or internal cost data.

## Common False Positive Patterns

1. **Public/shared resources by design**: Product catalogs, blog posts, public profiles. Verify the resource contains no sensitive data and that unpublished/draft items are filtered out.

2. **Scoping via non-obvious mechanisms**: ORM default scopes, PostgreSQL row-level security policies, or middleware that silently injects `WHERE tenant_id = ?`. Check for `default_scope`, RLS policies, or query-building middleware before flagging.

3. **Lookup by intentionally-shared unguessable tokens**: Password reset tokens, invitation links, share URLs. The token IS the authorization. Flag only if the token is short, predictable, or never expires.

4. **Platform superadmins with legitimate cross-tenant access**: Verify the role check distinguishes `platform_admin` from `tenant_admin` and that audit logging exists for cross-tenant reads.

5. **Endpoints returning different data based on auth state**: `GET /api/posts/:id` may return full content to the owner and a preview to others. No hard 403 does not mean IDOR — verify owner-only fields (analytics, draft content, edit history) are actually stripped for non-owners.

6. **Service-to-service internal calls**: Microservices passing user IDs with service tokens or mTLS. Auth boundary is at the API gateway. Flag only if the internal service is externally reachable or gateway auth is missing.

7. **Batch endpoints with silent filtering**: `POST /api/orders/bulk-status` accepts an array of IDs but returns only the caller's orders, silently dropping non-owned IDs. This is a valid pattern — verify non-owned IDs return no data rather than other users' data.
