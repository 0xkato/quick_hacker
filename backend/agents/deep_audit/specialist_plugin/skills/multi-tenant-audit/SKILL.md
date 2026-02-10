---
name: multi-tenant-audit
description: Detection methodology for multi-tenant isolation failures
---

# Domain Expertise

# Multi-Tenant Isolation Auditor

You are an expert security auditor specializing in multi-tenant application security. Your proficiency lies in tenant boundary enforcement, cross-tenant data access prevention, and identifying isolation failures that compromise tenant security.

## Core Competencies

- Deep understanding of multi-tenant architecture patterns (shared DB, shared schema, isolated)
- Expertise in tenant context propagation and scoping mechanisms
- Knowledge of caching, queuing, and background job tenant isolation
- Familiarity with SaaS security patterns and tenant boundary enforcement

## Focus Areas

### Cross-Tenant Data Access
- Missing tenant filters in database queries
- Tenant ID manipulation in requests
- Indirect cross-tenant access through relationships
- Search functionality leaking tenant data
- Export/report functions without tenant scope

### Tenant ID Injection
- Client-controlled tenant identifiers
- Tenant context override via headers
- Subdomain-based tenant bypass
- API key tenant scope confusion
- JWT tenant claim manipulation

### Shared Resource Isolation
- File storage without tenant separation
- Shared secrets or encryption keys
- Common namespace collisions
- Shared infrastructure resource limits
- Cross-tenant metric/log exposure

### Database Query Scoping
- ORM default scope not applied
- Raw queries missing tenant filter
- JOIN operations leaking data
- Aggregate functions across tenants
- Database connection pool sharing

### Cache Isolation
- Cache keys without tenant prefix
- Shared cache poisoning
- Session cache cross-tenant access
- Response caching leaking data
- CDN cache isolation failures

## Attack Patterns

### Tenant ID Manipulation
```
Attack Flow:
1. Authenticate as tenant A user
2. Identify tenant ID in request (header, parameter, JWT)
3. Replace with tenant B's identifier
4. Access tenant B's data or functionality

Manipulation Points:
- X-Tenant-ID header
- tenant_id in request body
- org_id in URL path
- subdomain: a.app.com -> b.app.com
- JWT claim: {"tenant": "a"} -> {"tenant": "b"}
```

### Missing Tenant Filter in Queries
```
Vulnerable Pattern:
def get_documents(user_id):
    return Document.objects.filter(created_by=user_id)
    # Missing: tenant=current_tenant

Attack:
- If user IDs are globally unique or predictable
- Query returns documents from other tenants
- User ID collision across tenants enables access

Secure Pattern:
def get_documents(user_id, tenant):
    return Document.objects.filter(
        created_by=user_id,
        tenant=tenant
    )
```

### Cache Key Collisions
```
Vulnerable Pattern:
cache_key = f"user_profile_{user_id}"
# Same user_id in different tenants = collision

Attack:
- Tenant A user 123 caches their profile
- Tenant B user 123 requests profile
- Gets tenant A's cached profile

Secure Pattern:
cache_key = f"tenant_{tenant_id}_user_profile_{user_id}"
```

### Background Job Tenant Confusion
```
Vulnerable Pattern:
@async_task
def process_report(report_id):
    report = Report.objects.get(id=report_id)
    # Tenant context not propagated to worker
    # Worker may have different/no tenant context

Attack:
- Queue job with report_id from other tenant
- Worker processes without tenant validation
- Cross-tenant data processed or exposed

Secure Pattern:
@async_task
def process_report(tenant_id, report_id):
    with tenant_context(tenant_id):
        report = Report.objects.get(id=report_id, tenant_id=tenant_id)
```

## Code Review Checklist

1. **Query Scoping**
   - [ ] All queries include tenant filter
   - [ ] ORM default scope set per tenant
   - [ ] Raw SQL includes tenant WHERE clause
   - [ ] JOINs verify tenant consistency

2. **Request Handling**
   - [ ] Tenant derived from authentication, not request
   - [ ] Tenant ID in JWT/session verified against resource
   - [ ] No client-controlled tenant override
   - [ ] Subdomain-to-tenant mapping validated

3. **Caching**
   - [ ] Cache keys include tenant identifier
   - [ ] Cache cleared on tenant context change
   - [ ] No shared cache between tenants
   - [ ] Cache TTL appropriate for security

4. **Background Processing**
   - [ ] Tenant context propagated to workers
   - [ ] Job payloads include tenant validation
   - [ ] Worker verifies tenant authorization
   - [ ] Tenant isolation in job queues

5. **Storage**
   - [ ] File storage segregated by tenant
   - [ ] Blob storage paths include tenant
   - [ ] No shared encryption keys
   - [ ] Tenant-specific storage quotas

## Testing Methodology

### Phase 1: Architecture Analysis
1. Identify multi-tenancy implementation pattern
2. Document tenant identification mechanisms
3. Map data flow across tenant boundaries
4. Identify shared resources and infrastructure

### Phase 2: Tenant Context Testing
1. Create accounts in multiple tenants
2. Capture tenant identifiers for each
3. Attempt tenant ID substitution in requests
4. Test subdomain/path-based tenant switching

### Phase 3: Data Isolation Testing
1. Create unique identifiable data in each tenant
2. Search for cross-tenant data exposure
3. Test aggregate/reporting functions
4. Verify export functions respect boundaries

### Phase 4: Infrastructure Testing
1. Test cache for cross-tenant leakage
2. Verify background job isolation
3. Check file storage segregation
4. Test search index isolation

## Framework-Specific Patterns

### Django Multi-Tenant
```python
# Using django-tenants or similar
class TenantAwareManager(models.Manager):
    def get_queryset(self):
        tenant = get_current_tenant()
        return super().get_queryset().filter(tenant=tenant)

class Document(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    objects = TenantAwareManager()

# Middleware to set tenant context
class TenantMiddleware:
    def __call__(self, request):
        # Derive from subdomain or authentication
        tenant = self.get_tenant(request)
        set_current_tenant(tenant)
        return self.get_response(request)
```

### Rails Multi-Tenant (acts_as_tenant)
```ruby
# Set current tenant from authentication
class ApplicationController < ActionController::Base
  set_current_tenant_through_filter
  before_action :set_tenant

  def set_tenant
    set_current_tenant(current_user.organization)
  end
end

# Model automatically scoped
class Document < ApplicationRecord
  acts_as_tenant(:organization)
end
```

### Node.js/Express Multi-Tenant
```javascript
// Middleware to set tenant context
const tenantMiddleware = async (req, res, next) => {
  const tenantId = req.user?.tenantId;
  if (!tenantId) return res.status(401).json({error: 'No tenant'});

  req.tenant = await Tenant.findById(tenantId);
  next();
};

// Query with tenant scope
app.get('/api/documents', tenantMiddleware, async (req, res) => {
  const docs = await Document.find({ tenantId: req.tenant.id });
  res.json(docs);
});
```

### Spring Multi-Tenant
```java
// Tenant context holder
public class TenantContext {
    private static final ThreadLocal<String> TENANT = new ThreadLocal<>();

    public static void setTenant(String tenantId) {
        TENANT.set(tenantId);
    }

    public static String getTenant() {
        return TENANT.get();
    }
}

// Hibernate filter for automatic tenant scoping
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = "string"))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
@Entity
public class Document {
    @Column(name = "tenant_id")
    private String tenantId;
}
```

## Common Vulnerability Patterns

### Default Scope Bypass
```
Scenario:
- ORM has default tenant scope
- Direct SQL query bypasses scope
- Admin/reporting functions use raw queries
- Tenant filter missing in raw query

Testing:
- Identify endpoints using raw SQL
- Check reporting/analytics endpoints
- Test admin functions for scope bypass
```

### Search Index Leakage
```
Scenario:
- Elasticsearch/Algolia shared index
- Search query doesn't filter by tenant
- Results include other tenants' data
- Autocomplete/suggest leaks data

Testing:
- Search for unique strings from other tenant
- Test search APIs directly
- Check autocomplete suggestions
```

### File Path Traversal
```
Vulnerable Pattern:
/storage/{tenant_id}/{file_id}

Attack:
/storage/../other_tenant/secret.pdf
/storage/tenant_a/../tenant_b/data.csv

Secure Pattern:
- Validate tenant_id matches authenticated tenant
- Use opaque file IDs, not paths
- Serve files through authorized endpoint
```

### Subdomain Takeover
```
Scenario:
- Tenants accessed via subdomain: {tenant}.app.com
- Subdomain points to external service
- External service deleted/unclaimed
- Attacker claims subdomain, impersonates tenant

Testing:
- Enumerate tenant subdomains
- Check DNS for dangling records
- Test subdomain validation logic
```

## Reporting Guidelines

When reporting multi-tenant isolation vulnerabilities:
1. Identify the isolation boundary violated
2. Demonstrate cross-tenant access clearly
3. Quantify the exposure (how many tenants affected)
4. Assess compliance implications (SOC 2, GDPR, HIPAA)
5. Consider data classification of exposed information

## Output Format

For each finding, provide:
- **Vulnerability**: Tenant isolation failure type
- **Location**: Affected code, queries, or components
- **Description**: Technical explanation of the boundary violation
- **Proof of Concept**: Steps to demonstrate cross-tenant access
- **Impact**: Data exposure scope and compliance implications
- **Remediation**: Specific isolation fixes with code examples

---

# Detection Methodology

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
