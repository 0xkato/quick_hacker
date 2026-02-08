# Parser Differential Attacks

When two components parse the same input differently, security boundaries collapse.
A WAF sees one request, the backend sees another. Parser differentials cause request
smuggling, authentication bypass, and schema validation evasion.

## Methodology

### Step 1: Identify Parser Chains

Map every point where the same input is parsed by more than one component.

- **HTTP**: Load balancer -> WAF -> reverse proxy -> application server
- **JSON**: Schema validator -> ORM/model layer -> database driver
- **URL**: Client-side router -> server-side router -> downstream service
- **XML**: WAF/filter -> application XML parser -> XSLT engine

### Step 2: Test Duplicate Key Handling in JSON

JSON RFC 7159 states duplicate keys produce "unpredictable" behavior.

```json
{"role": "user", "role": "admin"}
```

| Parser               | Behavior    |
|----------------------|-------------|
| Python json/ujson    | Last wins   |
| Node.js JSON.parse   | Last wins   |
| Java Gson/Jackson    | Last wins   |
| Go encoding/json     | Last wins   |
| .NET System.Text.Json | Error (configurable) |

The vulnerability arises when the **validator** and the **consumer** disagree:

```python
# VULNERABLE: validator uses json, downstream re-parses raw body
import json, rapidjson

raw = '{"admin": false, "admin": true}'
validated = json.loads(raw)   # {"admin": true}
# If middleware checked first-key and handler uses last-key: bypass
```

### Step 3: Test Unicode Normalization Differences

```python
# Key truncation via null bytes
payload = '{"user\\u0000admin": "controlled_value"}'
# Some parsers truncate at \u0000 -> key becomes "user"
# Others keep full key -> "user\x00admin"
```

```javascript
// U+FF41 (fullwidth 'a') normalizes to U+0061 ('a') under NFKC
const input = '\uFF41dmin';  // "admin" after NFKC normalization
// WAF sees non-ASCII (no block) — backend normalizes to "admin"
```

### Step 4: Test URL Parsing Differentials

```python
from urllib.parse import urlparse
url = "https://evil.com\\@good.com/"
parsed = urlparse(url)
# Python: netloc = "evil.com\\@good.com"
# Some browsers: host = "evil.com", path = "/@good.com/"
```

```javascript
const url = require('url');
const legacy = url.parse('http://user@evil.com@good.com/');
const whatwg = new URL('http://user@evil.com@good.com/');
// legacy.hostname: "good.com" — whatwg may differ
```

### Step 5: Test HTTP Request Smuggling

When front-end and back-end disagree on request boundaries:

```
# CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

### Step 6: Test JSON Content-Type Confusion

```python
# Flask — VULNERABLE if using force=True
@app.route('/api', methods=['POST'])
def api():
    data = request.get_json(force=True)  # Parses regardless of Content-Type
    # WAF skipped JSON inspection (saw text/plain Content-Type)
```

### Step 7: Test Comment Handling in JSON

```javascript
// JSON5 accepts comments; standard JSON.parse does NOT
const payload = '{"role": "user" /* , "role": "admin" */}';
// If WAF uses lenient parser but app uses strict (or vice versa): differential
```

## Decision Tree

```
Input parsed by 2+ components?
|
+-- NO --> SAFE (single parser, no differential)
|
+-- YES
    |
    Parsers from different libraries/languages?
    |
    +-- YES
    |   |
    |   Duplicate JSON keys possible?
    |   +-- YES --> VULNERABLE (Critical) if auth/authz fields affected
    |   +-- NO  --> Unicode normalization inconsistent?
    |       +-- YES --> VULNERABLE (High)
    |       +-- NO  --> URL parsed by different implementations?
    |           +-- YES --> VULNERABLE (High) — SSRF/redirect risk
    |           +-- NO  --> HARDENED (Medium)
    |
    +-- NO (same library, same config)
        |
        Input re-serialized between stages?
        +-- YES --> HARDENED (Medium) — re-serialization may alter semantics
        +-- NO  --> SAFE (parsed object passed by reference)
```

## Real-World Examples

### Example 1: Authentication Bypass via Duplicate JSON Keys

```python
def auth_middleware(raw_body):
    data = json.loads(raw_body)
    if data.get("role") == "admin":
        raise Forbidden("Cannot self-assign admin")
    return raw_body  # Passes RAW body to next handler

def handler(raw_body):
    import rapidjson
    data = rapidjson.loads(raw_body)
    user.role = data["role"]  # Different parser, different value
    user.save()
# Payload: {"role": "user", "role": "admin"}
```

**Why vulnerable:** Middleware and handler use different JSON parsers. If they disagree
on which duplicate key wins, the middleware validates one value while the handler uses another.

**Impact:** Privilege escalation from regular user to admin.

**Fix:**
```python
def auth_middleware(raw_body):
    data = json.loads(raw_body)
    if data.get("role") == "admin":
        raise Forbidden()
    return data  # Pass parsed dict, never re-parse raw input
```

### Example 2: SSRF via URL Parser Differential

```python
def fetch_url(user_url):
    parsed = urlparse(user_url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return requests.get(user_url)
# Attack: "http://allowed.com@evil.com/path"
# urlparse and requests may disagree on hostname
```

**Why vulnerable:** `urlparse` and the HTTP library's internal parser disagree on hostname
when userinfo or fragment separators are abused.

**Impact:** SSRF allowing access to internal services and cloud metadata.

**Fix:**
```python
def fetch_url(user_url):
    parsed = urlparse(user_url)
    if parsed.username or parsed.password:
        raise ValueError("Userinfo not allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    safe_url = f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
    return requests.get(safe_url)  # Reconstruct from parsed components
```

### Example 3: WAF Bypass via JSON Comment Injection

```javascript
// WAF: strict JSON parser — rejects comments, passes raw body through
// App: JSON5 parser — accepts comments
// Attack: WAF fails to parse -> skips inspection -> app parses successfully
const payload = '{"query": "SELECT * FROM users; DR" /* */ + "OP TABLE users"}';
```

**Why vulnerable:** WAF and application use different JSON dialects. The WAF cannot
inspect payloads the application accepts.

**Impact:** SQL injection or any payload class the WAF was meant to block.

**Fix:**
```javascript
app.use((req, res, next) => {
    if (req.is('json')) {
        try { JSON.parse(req.rawBody); }
        catch (e) { return res.status(400).json({ error: 'Invalid JSON' }); }
    }
    next();
});
```

## Common False Positive Patterns

1. **Same parser instance shared across pipeline** — Parsed object (not raw string)
   passed between middleware and handler means no re-parsing, no differential.

2. **Schema validation rejecting duplicates** — Parser configured to error on duplicate
   keys eliminates the differential at the gate.

3. **Single-language monolith with one JSON library** — Consistent duplicate key behavior
   throughout; no differential even if it picks an arbitrary winner.

4. **URL reconstruction from parsed components** — Parsing, validating, then rebuilding
   a canonical URL from parts neutralizes differentials in the original string.

5. **Content-Type enforcement at the gateway** — Strictly rejecting mismatched
   Content-Type headers blocks content-type confusion attacks.

6. **HTTP/2 end-to-end** — Binary framing with explicit length fields eliminates CL/TE
   ambiguity. Note: H1 downgrade between proxy and backend re-introduces the risk.

7. **Input canonicalization before validation** — Normalizing once (NFKC, URL decode,
   case fold) at entry ensures downstream parsers all see identical input.
