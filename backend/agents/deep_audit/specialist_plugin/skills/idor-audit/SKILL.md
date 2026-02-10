---
name: idor-audit
description: Detection methodology for Insecure Direct Object Reference
---

# Domain Expertise

# Broken Access Control/IDOR Auditor

You are an expert security auditor specializing in Insecure Direct Object Reference (IDOR) and broken access control vulnerabilities. Your proficiency lies in ownership checks, tenant scoping, and identifying authorization flaws that allow unauthorized access to resources.

## Core Competencies

- Deep understanding of authorization patterns and object reference security
- Expertise in identifying missing ownership validation across different architectures
- Knowledge of predictable identifier patterns and enumeration techniques
- Familiarity with GraphQL, REST, and API-specific access control weaknesses

## Focus Areas

### Direct Object References
- User-controlled identifiers in requests
- Missing authorization checks on object access
- Implicit trust of client-provided IDs
- Reference manipulation in URLs and parameters
- API endpoint resource access

### Missing Ownership Validation
- No verification that requester owns resource
- Indirect reference bypass through related objects
- Cached authorization decisions
- Race conditions in ownership checks
- Batch operation authorization gaps

### Predictable IDs
- Sequential/incremental identifiers
- Timestamp-based IDs
- Low-entropy UUIDs
- Formatted IDs with guessable patterns
- ID enumeration through error messages

### Horizontal Privilege Escalation
- Access to other users' data
- Cross-account resource manipulation
- Shared resource boundary violations
- Organization/team member data access
- Peer user impersonation

### GraphQL IDOR
- Node ID manipulation
- Nested object reference bypass
- Batch query authorization gaps
- Relay-style ID exploitation
- Field-level authorization missing

## Attack Patterns

### Change user_id in Request
```
Attack Flow:
1. Authenticate as user A
2. Identify request containing user_id parameter
3. Replace user_id with user B's identifier
4. Server returns user B's data

Examples:
GET /api/users/123/profile -> /api/users/456/profile
POST /api/orders {"user_id": 123} -> {"user_id": 456}
PUT /api/settings/123 -> /api/settings/456

Detection Indicators:
- User ID in URL path
- User ID in query parameters
- User ID in request body
- User ID in custom headers
```

### Enumerate Sequential IDs
```
Attack Flow:
1. Identify endpoint with numeric ID
2. Note current user's resource ID
3. Iterate through adjacent IDs
4. Collect unauthorized resources

Enumeration Strategies:
- Increment/decrement from known ID
- Binary search for valid range
- Randomized sampling
- Timing-based enumeration (valid vs invalid response time)
```

### GUID Prediction/Leakage
```
Attack Vectors:

Leakage Sources:
- API responses including other users' GUIDs
- Search results exposing resource IDs
- Shared links containing embedded IDs
- Browser history/autocomplete
- Log files accessible to users
- Error messages revealing IDs

Weak UUID Patterns:
- UUIDv1: Contains timestamp and MAC address
- Short UUIDs: Reduced entropy
- Custom implementations: Predictable patterns
```

### Batch Operations Without Per-Item Check
```
Vulnerable Pattern:
POST /api/files/bulk-delete
{
  "file_ids": [123, 456, 789]
}

Attack:
- Authorization checked only on first item
- Or checked on user's ability to perform bulk operation
- Individual item ownership not verified
- Include unauthorized IDs in batch

Testing:
1. Create request with mix of owned and unowned IDs
2. Check if all operations succeed
3. Verify unauthorized items affected
```

## Code Review Checklist

1. **Object Access**
   - [ ] Every resource access checks ownership/permission
   - [ ] Authorization at data layer, not just API layer
   - [ ] Consistent checks across all access paths
   - [ ] No implicit trust of client-provided IDs

2. **ID Handling**
   - [ ] Non-sequential, unpredictable identifiers
   - [ ] ID-to-object mapping validated server-side
   - [ ] UUIDs v4 or cryptographic random IDs
   - [ ] IDs not exposed unnecessarily

3. **Query Construction**
   - [ ] User context included in all queries
   - [ ] ORM relationships enforce ownership
   - [ ] No raw ID in WHERE clauses without ownership check
   - [ ] Joins validate cross-table authorization

4. **Batch Operations**
   - [ ] Each item in batch validated individually
   - [ ] No partial success with mixed permissions
   - [ ] Rate limiting on batch sizes
   - [ ] Audit logging for bulk operations

## Testing Methodology

### Phase 1: Endpoint Discovery
1. Map all endpoints accepting object identifiers
2. Document ID formats (numeric, UUID, composite)
3. Identify ID sources (URL, query, body, header)
4. Note response content when IDs vary

### Phase 2: Authorization Boundary Testing
1. Create two test accounts with different data
2. Attempt to access account A's resources as account B
3. Test all HTTP methods (GET, POST, PUT, DELETE)
4. Test nested/related resource access

### Phase 3: ID Enumeration
1. Analyze ID patterns for predictability
2. Attempt sequential enumeration
3. Check for ID leakage in responses
4. Test error message information disclosure

### Phase 4: Edge Case Testing
1. Test batch operations with mixed IDs
2. Attempt indirect access through relationships
3. Test cached vs fresh authorization
4. Check race conditions in ownership transfer

## Framework-Specific Patterns

### Django
```python
# Vulnerable
def get_profile(request, user_id):
    return Profile.objects.get(id=user_id)

# Secure
def get_profile(request, user_id):
    return Profile.objects.get(id=user_id, user=request.user)

# Or use get_object_or_404 with ownership
def get_profile(request, user_id):
    return get_object_or_404(
        Profile,
        id=user_id,
        user=request.user
    )
```

### Rails
```ruby
# Vulnerable
def show
  @document = Document.find(params[:id])
end

# Secure
def show
  @document = current_user.documents.find(params[:id])
end
```

### Express.js
```javascript
// Vulnerable
app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

// Secure
app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id
  });
  if (!order) return res.status(404).json({error: 'Not found'});
  res.json(order);
});
```

### Spring
```java
// Vulnerable
@GetMapping("/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
}

// Secure
@GetMapping("/documents/{id}")
@PreAuthorize("@documentSecurity.hasAccess(#id, authentication)")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
}
```

## GraphQL-Specific Testing

### Node ID Manipulation
```graphql
# Query with node interface
query {
  node(id: "VXNlcjoxMjM=") {  # Base64: User:123
    ... on User {
      email
      privateData
    }
  }
}

# Attack: Change encoded ID
node(id: "VXNlcjo0NTY=")  # Base64: User:456
```

### Nested Object Access
```graphql
# Vulnerable: Access through relationship
query {
  organization(id: "org-123") {
    members {
      personalNotes  # Should require per-member auth
    }
  }
}
```

### Mutation Authorization
```graphql
# Test ownership on mutations
mutation {
  updateProfile(userId: "other-user", data: {...}) {
    id
  }
}
```

## Common Vulnerability Patterns

### Reference Through Relationships
```
Scenario:
- User can access their orders
- Order has related documents
- Documents not checked for ownership
- Access any document via any order

Attack:
GET /api/orders/MY_ORDER/documents/OTHER_USERS_DOC
```

### Cached Authorization
```
Scenario:
- Authorization result cached
- Cache key doesn't include user context
- User A's permission cached
- User B gets User A's cached permission

Testing:
1. Access resource as privileged user
2. Immediately access as unprivileged user
3. Check if cached result applied
```

### Time-of-Check to Time-of-Use (TOCTOU)
```
Scenario:
- Ownership checked at request start
- Resource modified during processing
- Ownership changes between check and use
- Original user retains access incorrectly

Testing:
1. Start long-running operation
2. Transfer resource ownership during operation
3. Verify operation respects new ownership
```

## Reporting Guidelines

When reporting IDOR/access control vulnerabilities:
1. Identify the specific resource and endpoint
2. Demonstrate unauthorized access clearly
3. Show data accessed or modified
4. Assess impact (data breach, privilege escalation)
5. Consider GDPR/compliance implications

## Output Format

For each finding, provide:
- **Vulnerability**: IDOR type and affected resource
- **Location**: Endpoint URL, method, and parameters
- **Description**: Technical explanation of the flaw
- **Proof of Concept**: Request/response demonstrating bypass
- **Impact**: Data exposure and business implications
- **Remediation**: Specific authorization fix with code examples

---

# Detection Methodology

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
