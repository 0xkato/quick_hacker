# Multi-Tenant Isolation Failure Detection

Multi-tenant isolation failures occur when one tenant can access, modify, or infer the
existence of another tenant's data. Unlike IDOR (individual resources) or privilege
escalation (role boundaries), tenant isolation failures break the fundamental trust
boundary that each tenant's data is invisible to all others. A single missing tenant_id
filter can expose the entire dataset of every tenant.

## Methodology

### Step 1: Identify the Tenant Resolution Mechanism

Determine how the application resolves which tenant a request belongs to.

```python
# Django middleware — tenant from subdomain
class TenantMiddleware:
    def __call__(self, request):
        host = request.get_host().split('.')[0]
        request.tenant = Tenant.objects.get(subdomain=host)
        return self.get_response(request)
```

```javascript
// VULNERABLE: tenant from request header
app.use((req, res, next) => {
    req.tenantId = req.headers['x-tenant-id'];  // attacker-controlled
    next();
});

// SAFE: tenant from verified auth token
app.use((req, res, next) => {
    const decoded = jwt.verify(req.headers.authorization, SECRET);
    req.tenantId = decoded.tenantId;
    next();
});
```

Critical question: can the tenant identifier be forged by the client?

### Step 2: Audit Database Query Scoping

Every query returning tenant-specific data MUST include a tenant_id filter.

```python
# Django VULNERABLE — no tenant filter
def get_queryset(self):
    return Document.objects.all()

# Django SAFE — tenant-scoped
def get_queryset(self):
    return Document.objects.filter(tenant=self.request.tenant)
```

```javascript
// Prisma VULNERABLE
const projects = await prisma.project.findMany();

// Prisma SAFE
const projects = await prisma.project.findMany({ where: { tenantId: req.tenantId } });
```

### Step 3: Check for Tenant ID from Request Parameters

Tenant ID from params/query/body instead of auth token is always dangerous.

```python
# VULNERABLE: tenant_id from URL without validation
@app.route("/api/tenants/<int:tenant_id>/users")
@login_required
def list_users(tenant_id):  # no check current_user belongs to tenant
    return jsonify(User.query.filter_by(tenant_id=tenant_id).all())
```

```java
// VULNERABLE: tenant from request parameter
@GetMapping("/api/reports")
public List<Report> getReports(@RequestParam("tenantId") Long tenantId) {
    return reportRepository.findByTenantId(tenantId);
}

// SAFE: tenant from security context
public List<Report> getReports(Authentication auth) {
    TenantUser user = (TenantUser) auth.getPrincipal();
    return reportRepository.findByTenantId(user.getTenantId());
}
```

### Step 4: Inspect Shared Infrastructure for Leakage

Caches, queues, storage, and search indices can leak across tenants if not namespaced.

```python
# VULNERABLE: cache key without tenant namespace
cached = cache.get("dashboard_stats")              # shared across tenants

# SAFE: tenant-prefixed
cached = cache.get(f"tenant:{tenant_id}:dashboard_stats")
```

```python
# VULNERABLE: S3 without tenant isolation
s3.upload_fileobj(file, BUCKET, f"uploads/{file.filename}")

# SAFE: tenant-scoped path
s3.upload_fileobj(file, BUCKET, f"tenants/{tenant_id}/uploads/{uuid4()}_{file.filename}")
```

### Step 5: Verify Background Job Tenant Context

Background jobs frequently lose tenant context during serialization.

```python
# VULNERABLE: Celery task without tenant context
@celery.task
def generate_report(report_id):
    data = fetch_all_data()   # may cross tenant boundaries

# SAFE: tenant context explicitly passed
@celery.task
def generate_report(tenant_id, report_id):
    with tenant_context(tenant_id):
        data = fetch_tenant_data(tenant_id)
```

### Step 6: Audit Admin/Superuser Tenant Bypasses

Superuser flags that disable ALL tenant scoping are dangerous if compromised.

```python
# VULNERABLE: superuser disables all scoping
class TenantManager(models.Manager):
    def get_queryset(self):
        if get_current_user().is_superuser:
            return super().get_queryset()           # NO filter
        return super().get_queryset().filter(tenant_id=get_current_tenant_id())

# SAFER: explicit cross-tenant with audit logging
def cross_tenant(self, reason: str):
    audit_log.info(f"Cross-tenant access: {reason}")
    return super().get_queryset()
```

### Step 7: Check Row Level Security (RLS)

If relying on database RLS, verify tenant context is set correctly and cannot be forged.

```sql
CREATE POLICY tenant_isolation ON documents
    USING (tenant_id = current_setting('app.current_tenant_id')::int);

-- VULNERABLE if application can SET arbitrarily
SET app.current_tenant_id = '999';  -- attacker controls this
```

### Step 8: Inspect Connection Pool State

Shared pools can leak tenant context between requests if not reset on checkin.

```python
# SAFE: reset tenant state on connection return
@event.listens_for(engine, "checkin")
def reset_tenant_on_checkin(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("RESET app.current_tenant_id")
    cursor.close()
```

## Decision Tree

```
[Multi-tenant application?]
    +--NO--> SAFE (not applicable)
    +--YES
        [Tenant ID from trusted origin? (JWT, session, validated subdomain)]
            +--NO--> VULNERABLE (Critical) "Tenant ID client-controlled"
            +--YES
                [ALL queries scoped by tenant_id?]
                    +--NO--> VULNERABLE (Critical) "Unscoped cross-tenant queries"
                    +--YES
                        [Shared infra namespaced? (cache, queues, storage)]
                            +--NO--> VULNERABLE (High) "Cross-tenant infra leakage"
                            +--YES
                                [Background jobs preserve tenant context?]
                                    +--NO--> VULNERABLE (High)
                                    +--YES
                                        [Connection pool state isolated?]
                                            +--NO--> HARDENED (Medium)
                                            +--YES--> SAFE
```

## Real-World Examples

### Example 1: Django REST Missing Tenant Filter

```python
class CustomerViewSet(viewsets.ModelViewSet):
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Customer.objects.all()  # no tenant scoping
```

**Why vulnerable:** Returns every customer across all tenants. `IsAuthenticated` only
checks that a valid user is logged in, not tenant membership.

**Impact:** Complete cross-tenant data exposure via GET, and potentially full CRUD via
PUT/PATCH/DELETE on any tenant's customers.

**Fix:**
```python
def get_queryset(self):
    return Customer.objects.filter(tenant=self.request.user.tenant)
def perform_create(self, serializer):
    serializer.save(tenant=self.request.user.tenant)
```

### Example 2: Shared Redis Cache Without Tenant Namespace

```python
def get_user_preferences(user_id):
    key = f"prefs:{user_id}"
    cached = redis_client.get(key)
    if cached: return json.loads(cached)
    prefs = Preference.query.filter_by(user_id=user_id).first()
    redis_client.setex(key, 3600, json.dumps(prefs.to_dict()))
    return prefs.to_dict()
```

**Why vulnerable:** User IDs may collide across tenants (auto-increment). Tenant A's
user 42 gets cached preferences of Tenant B's user 42.

**Impact:** Cross-tenant information disclosure through cache, even if DB queries are
properly scoped.

**Fix:**
```python
def get_user_preferences(tenant_id, user_id):
    key = f"tenant:{tenant_id}:prefs:{user_id}"
    # ... rest with tenant-scoped DB query
```

### Example 3: Prisma Query Without Tenant Where Clause

```javascript
export default async function handler(req, res) {
    const { id } = req.query;
    const doc = await prisma.document.findUnique({ where: { id: parseInt(id) } });
    if (!doc) return res.status(404).json({ error: "Not found" });
    return res.json(doc);
}
```

**Why vulnerable:** Fetches document by PK alone. Tenant A retrieves Tenant B's document
by guessing integer IDs.

**Impact:** Any authenticated user reads any document. If PUT/DELETE follow the same
pattern, full cross-tenant CRUD.

**Fix:**
```javascript
const doc = await prisma.document.findFirst({
    where: { id: parseInt(id), tenantId: req.auth.tenantId },
});
```

## Common False Positive Patterns

1. **Database-per-tenant architecture** where each tenant has a physically separate
   database. Individual queries do not need tenant_id filters if connection routing
   is correct.

2. **Public/shared reference data** (countries, currencies, plans) intentionally
   accessible across tenants. Confirm the table contains no tenant-specific data.

3. **Platform admin dashboards** aggregating cross-tenant data for operators. Verify
   admin authentication is robust and not reachable by tenant users.

4. **Tenant-scoped API keys** where tenant_id comes from DB lookup of the key, not
   from the request. The key maps to exactly one tenant server-side.

5. **Per-tenant search indices** (separate Elasticsearch index). Queries against a
   tenant-specific index do not need additional tenant_id filters.

6. **Webhook endpoints** receiving external data. Tenant context derived from webhook
   registration record, not incoming payload.

7. **Database migrations** operating across all tenants during deployment. These run
   in privileged ops context, not in response to user requests.
