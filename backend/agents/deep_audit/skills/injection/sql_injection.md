# SQL Injection Detection

## Methodology

### Step 1: Identify Query Construction Points

Search for all locations where SQL queries are built. Priority targets:

**Direct string construction:**
- String concatenation with SQL keywords (`"SELECT " + column`, `f"WHERE {field} = {value}"`)
- `.format()` calls containing SQL fragments
- Template strings with SQL content
- String joining or building that includes SQL keywords

**ORM raw query escape hatches:**
- SQLAlchemy: `text()`, `session.execute()` with string args, `engine.execute()` with raw strings
- Django: `.raw()`, `.extra()`, `cursor.execute()` with string formatting, `RawSQL()`
- Sequelize: `sequelize.query()`, `Sequelize.literal()`
- ActiveRecord: `.find_by_sql()`, `.where()` with string interpolation, `Arel.sql()`
- Prisma: `$queryRaw`, `$executeRaw`

**Stored procedure calls:**
- Dynamic SQL inside stored procedures (`EXEC sp_executesql`, `EXECUTE IMMEDIATE`)
- Procedure parameters passed without binding

### Step 2: Trace Input Source

For each query construction point, trace backwards to answer:

1. **Where does the data originate?**
   - HTTP request (query params, body, headers, cookies) → HIGH risk
   - Database result used in another query → MEDIUM risk (second-order SQLi)
   - Configuration file → LOW risk
   - Hardcoded constant → NO risk

2. **What transformations occur between source and sink?**
   - Parameterized binding (safe)
   - Type casting to int/float/UUID (safe for that specific injection vector)
   - Allowlist validation (safe if allowlist is correct and complete)
   - Blocklist/regex filtering (fragile — check for bypass)
   - HTML escaping (irrelevant for SQL — does NOT prevent SQLi)
   - URL encoding/decoding (irrelevant for SQL)

3. **How many hops?**
   - Direct (request param → query) → easy to trace, high confidence
   - Indirect (request → variable → function → query) → trace each hop
   - Cross-function (request handled in controller, query built in service) → trace through call chain

### Step 3: Evaluate Defenses

For each potential injection point, check:

**Parameterized queries (SAFE):**
```python
# Safe — value is bound, not interpolated
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

**ORM queries (USUALLY SAFE):**
```python
# Safe — ORM handles escaping
User.objects.filter(id=user_id)
session.query(User).filter(User.id == user_id)
```

**Type casting (SAFE for that vector):**
```python
# Safe — int() will throw on injection payload
user_id = int(request.args.get("id"))
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Allowlist (SAFE if correct):**
```python
# Safe — sort_by can only be one of the allowed values
ALLOWED = {"name", "created_at", "email"}
sort_by = request.args.get("sort", "name")
if sort_by not in ALLOWED:
    sort_by = "name"
```

**Manual escaping (FRAGILE):**
```python
# DANGEROUS — escape functions can be bypassed
# (encoding tricks, multibyte chars, context-dependent escaping)
clean = value.replace("'", "''")
cursor.execute(f"SELECT * FROM users WHERE name = '{clean}'")
```

**Blocklist/regex (FRAGILE):**
```python
# DANGEROUS — blocklists are always incomplete
if re.search(r"(union|select|drop|insert|update|delete)", value, re.I):
    raise ValueError("SQL injection detected")
# Bypass: using comments (SEL/**/ECT), encoding, case tricks
```

### Step 4: Check for Second-Order SQLi

Data stored in the database from one request, then used unsafely in a query from another request:

1. Find places where user input is stored to DB (usually safe at write time)
2. Find places where DB values are used to construct queries (dangerous if not parameterized)
3. If stored value is used in string-constructed SQL, it's second-order SQLi

### Step 5: Classify

- **VULNERABLE (Critical)**: User input reaches query construction without parameterization, endpoint is unauthenticated or low-privilege
- **VULNERABLE (High)**: Same as above but requires authentication
- **HARDENED (Medium)**: Defense exists but is fragile (manual escaping, incomplete blocklist)
- **HARDENED (Low)**: Requires second-order exploitation or unusual conditions
- **SAFE**: Parameterized query, ORM-only, or input is provably not user-controlled
- **BY_DESIGN**: Raw SQL used intentionally with admin-only input or internal tooling

## Decision Tree

```
Is SQL constructed with external data interpolated into the query string?
├── No → SAFE (not a finding)
└── Yes → Is the query parameterized (bound parameters)?
    ├── Yes → SAFE
    └── No → Is the external data user-controlled?
        ├── No (hardcoded, config-only, internal) → BY_DESIGN (note it, low priority)
        └── Yes → Is the input validated before use?
            ├── No validation → VULNERABLE
            │   ├── Unauthenticated endpoint → Critical
            │   └── Authenticated endpoint → High
            └── Yes → What kind of validation?
                ├── Type cast (int, UUID, enum) → SAFE
                ├── Strict allowlist → SAFE (verify allowlist is actually strict)
                ├── Regex blocklist → HARDENED (Medium — bypass risk)
                ├── Manual escaping → HARDENED (High — fragile)
                └── HTML/URL escaping → VULNERABLE (wrong escaping type)
```

## Real-World Examples

### Example 1: Django ORM Escape Hatch (CVE-2020-9402)

**Vulnerable pattern:**
```python
# Django GIS — user-controlled tolerance parameter in raw SQL
class GeoQuerySet(QuerySet):
    def snap_to_grid(self, *args, **kwargs):
        # tolerance comes from user input
        tolerance = kwargs.get('tolerance', 0.0)
        # Interpolated directly into SQL
        self.query.add_extra(
            select={'snapped': f"ST_SnapToGrid(geom, {tolerance})"},
            select_params=None, where=None, params=None,
            tables=None, order_by=None
        )
```

**Why vulnerable:** The `tolerance` parameter flows from user input through Django's `.extra()` method, which does NOT parameterize `select` expressions. An attacker passes `tolerance=0); DROP TABLE users; --` and achieves arbitrary SQL execution.

**Fix:** Use parameterized form or validate tolerance is a float.
```python
tolerance = float(kwargs.get('tolerance', 0.0))  # Type cast
```

### Example 2: Second-Order SQLi via Stored Username

**Vulnerable pattern:**
```python
# Registration — stores username to DB (safe at this point)
@app.post("/register")
def register(username: str, password: str):
    db.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
               [username, hash_password(password)])

# Admin panel — uses stored username in raw query (UNSAFE)
@app.get("/admin/user-activity")
def user_activity(user_id: int):
    user = db.execute("SELECT username FROM users WHERE id = %s", [user_id])
    username = user[0]["username"]
    # Second-order: stored username used in string-constructed SQL
    logs = db.execute(f"SELECT * FROM audit_log WHERE actor = '{username}'")
    return logs
```

**Why vulnerable:** Attacker registers with username `admin' UNION SELECT password FROM users WHERE username='admin' --`. The registration INSERT is safe (parameterized), but when the admin panel reads the username back and interpolates it into the audit_log query, the injection payload executes.

**Fix:** Parameterize the second query too.
```python
logs = db.execute("SELECT * FROM audit_log WHERE actor = %s", [username])
```

### Example 3: False Positive — Dynamic Table Name from Enum

```python
# This looks dangerous but is safe
TABLE_MAP = {
    "users": "app_users",
    "orders": "app_orders",
    "products": "app_products",
}

def get_records(table_name: str):
    actual_table = TABLE_MAP.get(table_name)
    if actual_table is None:
        raise ValueError(f"Unknown table: {table_name}")
    # Safe: actual_table can only be one of 3 hardcoded strings
    return db.execute(f"SELECT * FROM {actual_table} LIMIT 100")
```

**Why safe:** `actual_table` is resolved through a dictionary lookup against hardcoded keys. Even though the final query uses string interpolation, the interpolated value can only be one of three known-safe strings. The `TABLE_MAP.get()` + `None` check is an effective allowlist.

## Common False Positive Patterns

1. **ORM-only queries**: `User.objects.filter(name=input)` — ORM handles escaping
2. **Parameterized queries**: `execute("SELECT ... WHERE id = ?", [input])` — bound parameters
3. **Integer-cast inputs**: `int(request.args["id"])` before use in query
4. **Allowlisted values**: Input checked against a fixed set before interpolation
5. **Internal/admin-only queries**: SQL with data from config files or hardcoded values
6. **Migration scripts**: Raw SQL in database migrations — runs once, not user-facing
7. **Test fixtures**: Raw SQL in test setup/teardown — not production code
