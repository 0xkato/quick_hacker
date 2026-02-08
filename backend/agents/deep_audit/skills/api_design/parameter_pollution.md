# HTTP Parameter Pollution Detection

HTTP Parameter Pollution (HPP) exploits inconsistencies in how different components of
a web stack handle duplicate or conflicting parameters. When a WAF parses
`?role=user&role=admin` differently than the backend, attackers bypass security controls.

## Methodology

### Step 1: Map Parameter Ingestion Points

Identify how each framework handles duplicate parameter keys.

```javascript
// Express — ?role=user&role=admin
req.query.role             // with qs parser: ["user", "admin"]
req.body.role              // depends on body parser
// req.param("role") merges params -> body -> query (deprecated)
```

```python
# Django QueryDict — last wins by default
request.GET["role"]          # "admin" (last)
request.GET.getlist("role")  # ["user", "admin"]

# Flask Werkzeug — first wins by default
request.args["role"]         # "user" (first)
request.args.getlist("role") # ["user", "admin"]
```

```java
// Spring — first value for simple types
@RequestParam String role     // "user" (first)
@RequestParam String[] role   // ["user", "admin"]
request.getParameter("role")  // first value
```

### Step 2: Identify Proxy/Backend Parsing Discrepancies

The core HPP attack: different layers select different values from duplicates.

| Component        | Duplicate Param Behavior   |
|------------------|----------------------------|
| Apache (mod_php) | Last value wins            |
| Nginx (proxy)    | Passes all to backend      |
| Express (qs)     | Converts to array          |
| Flask/Werkzeug   | First value wins           |
| Django           | Last value wins            |
| Spring Boot      | First value wins           |
| ASP.NET          | Comma-joins: "user,admin"  |
| PHP ($_GET)      | Last value wins            |
| Rails            | Last value wins            |

```
Exploitation: ?role=user&role=admin
WAF inspects:  role=user  (first) -> passes
Backend uses:  role=admin (last)  -> privilege escalation
```

### Step 3: Check for Parameter Source Merging

Frameworks merging parameters from query, body, and cookies create distinct vectors.

```javascript
// VULNERABLE: validation checks query, handler reads body
app.post("/transfer",
  query("amount").isInt({ max: 1000 }),  // validates query
  (req, res) => {
    const amount = req.body.amount;       // reads body — UNCHECKED
    transfer(amount);
  }
);
```

```python
# VULNERABLE: Django view checks GET but processes POST
def transfer(request):
    # Middleware validated request.GET["amount"]
    amount = request.POST.get("amount")  # different source
```

### Step 4: Detect JSON Key Duplication

Duplicate JSON keys have implementation-defined behavior (RFC 7159).

```json
{ "role": "user", "role": "admin" }
```

| Parser              | Behavior        |
|---------------------|-----------------|
| Python `json`       | Last value wins |
| Node.js JSON.parse  | Last value wins |
| Java Jackson/Gson   | Last value wins |
| Go encoding/json    | Last value wins |

A WAF checking the first key passes validation; the backend keeps the last.

### Step 5: Examine Array Parameter Injection

Type confusion when a framework returns an array where a string was expected.

```javascript
// VULNERABLE: NoSQL operator injection via array params
// URL: /api/search?filter=safe&filter[$gt]=
app.get("/api/search", (req, res) => {
  // req.query.filter === { "$gt": "" } — not a string!
  db.collection.find({ status: req.query.filter });
});
```

```python
# Flask: getlist returns unexpected multiple values
# URL: /search?tag=safe&tag=malicious
tags = request.args.getlist("tag")  # ["safe", "malicious"]
```

### Step 6: Analyze Middleware Parameter Mutation

Middleware that merges or normalizes params can create pollution vectors.

```javascript
// VULNERABLE: body overwrites query in merged object
app.use((req, res, next) => {
  req.data = { ...req.query, ...req.body };
  next();
});
// Attacker: role=user in query (passes WAF), role=admin in body (wins merge)
```

```python
# VULNERABLE: manual source merging
def my_view(request):
    params = {}
    params.update(request.GET.dict())
    params.update(request.POST.dict())  # POST overwrites GET
```

### Step 7: Distinguish Server-Side vs Client-Side HPP

**SS-HPP:** Duplicate params reach backend logic, bypassing server-side checks.

**CS-HPP:** Polluted params reflected into URLs or HTML processed by the browser.

```python
# CS-HPP: reflected parameter in redirect
def callback(request):
    next_url = request.GET.get("next")
    # ?next=dashboard&next=http://evil.com -> redirects to evil.com
    return redirect(next_url)
```

## Decision Tree

```
DUPLICATE/CONFLICTING PARAMETERS POSSIBLE?
|
+--NO--> SAFE (single source, no duplication)
|
+--YES
   |
   MULTI-LAYER PARSING WITH DIFFERENT SEMANTICS?
   |
   +--YES
   |  |
   |  SECURITY CHECK ON ONE LAYER, LOGIC ON ANOTHER?
   |  +--YES--> VULNERABLE (Critical) — first/last value bypass
   |  +--NO---> HARDENED (Medium)
   |
   +--NO
      |
      PARAMETER SOURCE MERGING WITHOUT PRECEDENCE CONTROL?
      |
      +--YES
      |  |
      |  SENSITIVE FIELDS AFFECTED (role, auth, amount)?
      |  +--YES--> VULNERABLE (High)
      |  +--NO---> HARDENED (Low)
      |
      +--NO
         |
         ARRAY INJECTION CAUSES TYPE CONFUSION?
         +--YES--> VULNERABLE (High) — validation bypass
         +--NO---> SAFE
```

## Real-World Examples

### Example 1: WAF Bypass via Duplicate Query Parameters

```python
# Client -> WAF (checks first param) -> Django (uses last param)
# Request: GET /api/run?cmd=echo+hello&cmd=rm+-rf+/
# WAF sees "echo hello" -> PASS; Django sees "rm -rf /" -> EXECUTES

def run_command(request):
    cmd = request.GET["cmd"]  # last value
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return JsonResponse({"output": result.stdout.decode()})
```

**Why vulnerable:** WAF inspects the first value (benign); Django returns the last
value (malicious). Arbitrary commands smuggled past WAF.

**Impact:** Remote code execution bypassing WAF protection.

**Fix:** Reject requests with duplicate parameter keys using `getlist()` length check.
Also: never pass user input to `subprocess.run(shell=True)`.

### Example 2: Express Source Merging Privilege Escalation

```javascript
app.use((req, res, next) => {
  req.merged = Object.assign({}, req.query, req.body);
  next();
});

app.post("/api/action", (req, res) => {
  const role = req.merged.role;
  // Query: ?role=user  Body: { "role": "admin" }
  // Merged: role="admin" (body overwrites)
  if (role === "admin") performAdminAction();
});
```

**Why vulnerable:** `Object.assign` gives body precedence over query. Attacker sets
benign query value (passes inspection) and malicious body value (wins merge).

**Impact:** Privilege escalation to admin.

**Fix:** Read role from the authenticated user object, never from client params.

### Example 3: JSON Duplicate Key Smuggling

```python
def validate_transfer(raw_body):
    data = json.loads(raw_body)
    if data["amount"] > 10000:
        raise ValidationError("Amount too high")
    return data

# Attack: {"amount": 100, "amount": 999999}
# json.loads keeps last: amount=999999
# If WAF checked first: amount=100 -> passed
```

**Why vulnerable:** JSON spec does not mandate behavior for duplicate keys. If a
validation layer and application use different parsers or the developer misunderstands
last-wins behavior, the attacker smuggles values past checks.

**Impact:** Financial control bypass for unauthorized large transfers.

**Fix:** Use `object_pairs_hook` to reject duplicate JSON keys during parsing.

## Common False Positive Patterns

1. **Intentional multi-value parameters.** `?tag=python&tag=rust` by design with
   `getlist()` handling consistently across all layers.

2. **Array bracket syntax.** `?ids[]=1&ids[]=2` is structured array input, not
   pollution, when the framework recognizes the notation.

3. **Test harness code.** Duplicate params in test code verifying server behavior
   are not production vulnerabilities.

4. **Content-Type enforced endpoints.** Strict `application/json` requirement blocks
   form-encoded body attacks, eliminating query/body merge vectors.

5. **Single-source parameter reading.** Handlers reading from exactly one source
   with no middleware merging have no pollution vector.

6. **Framework default deduplication.** Middleware that rejects or deduplicates
   params before handler code runs. Verify it is active and not bypassable.

7. **GraphQL/RPC endpoints.** Single JSON body with defined schema, no query
   param reading. Only flag if the schema parser mishandles duplicate keys.
