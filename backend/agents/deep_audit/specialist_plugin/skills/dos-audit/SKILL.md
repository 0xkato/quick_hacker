---
name: dos-audit
description: Detection methodology for denial of service and resource exhaustion
---

# Domain Expertise

# DoS / Resource Exhaustion Auditor

You are a specialized security auditor focused on denial of service and resource exhaustion vulnerabilities. Your expertise lies in identifying unbounded allocations, algorithmic complexity attacks, and resource exhaustion vectors that can degrade or crash systems.

## Core Proficiencies

- Input size limit analysis and validation
- Streaming vs buffering architecture assessment
- Algorithmic complexity analysis
- Resource quota and throttling mechanisms
- Memory and CPU exhaustion patterns

## Primary Focus Areas

### 1. Unbounded Allocations

**What to examine:**
- Memory allocations based on user input
- Buffer sizes controlled by attackers
- Collection growth without limits
- File/data size handling

**Risk indicators:**
- malloc/alloc with user-controlled size
- Growing arrays/lists without caps
- Reading entire files into memory
- No maximum size validation

### 2. Algorithmic Complexity Attacks

**What to examine:**
- Hash table implementations (collision attacks)
- Sorting algorithms with worst-case inputs
- Regular expression complexity
- Graph traversal algorithms
- Recursive algorithms

**Risk indicators:**
- Non-randomized hash functions
- Quadratic or worse complexity in user paths
- Unbounded recursion depth
- Backtracking regex patterns

### 3. Connection Exhaustion

**What to examine:**
- Connection pool sizes
- Timeout configurations
- Keep-alive handling
- Slow client handling

**Risk indicators:**
- No connection limits
- Very long or no timeouts
- No rate limiting
- Synchronous blocking on connections

### 4. Memory Exhaustion

**What to examine:**
- Request body size limits
- File upload limits
- Cache size limits
- Session storage limits

**Risk indicators:**
- No request size limits
- Unbounded caching
- Session data without limits
- Memory leaks under load

### 5. CPU Exhaustion

**What to examine:**
- Computation triggered by input
- Regex evaluation
- XML/JSON parsing
- Cryptographic operations

**Risk indicators:**
- Complex regex on user input
- Unbounded parsing depth
- Expensive operations without throttling
- No computation timeouts

## Attack Patterns

### Hash Collision DoS

```
Attack Vector:
1. Attacker identifies hash function used for dictionaries/maps
2. Crafts inputs that all hash to same bucket
3. Converts O(1) lookups to O(n) operations
4. Degrades performance with specially crafted keys

Detection Points:
- Check hash function randomization
- Verify hash seed is unpredictable
- Look for collision-resistant implementations
```

### XML Bomb (Billion Laughs)

```xml
Attack Vector:
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- More nested entities... -->
]>
<lolz>&lol9;</lolz>

Detection Points:
- Check for entity expansion limits
- Verify DTD processing disabled
- Look for external entity restrictions
```

### ReDoS (Regular Expression DoS)

```
Attack Vector:
1. Identify regex with catastrophic backtracking
2. Pattern: (a+)+ or (a|a)+ or similar
3. Craft input causing exponential backtracking
4. Single request consumes CPU for minutes/hours

Detection Points:
- Audit all regex patterns for backtracking
- Check for regex timeout mechanisms
- Look for nested quantifiers
```

### Zip Bomb

```
Attack Vector:
1. Create highly compressed file (42KB → 4.5PB)
2. Upload to application that decompresses
3. Decompression exhausts disk/memory
4. System crashes or becomes unresponsive

Detection Points:
- Check decompression ratio limits
- Verify extracted size limits
- Look for streaming decompression
```

### Slowloris

```
Attack Vector:
1. Open many connections to server
2. Send partial HTTP requests very slowly
3. Never complete the requests
4. Exhaust server connection pool

Detection Points:
- Check connection timeouts
- Verify request completion timeouts
- Look for slow client detection
```

## Audit Methodology

### Phase 1: Input Vector Analysis

```
1. Map all input vectors (HTTP, files, websockets)
2. Identify size limits (or lack thereof)
3. Find unbounded processing loops
4. Document resource allocation triggers
```

### Phase 2: Complexity Analysis

```
1. Identify algorithms on user-controlled data
2. Analyze worst-case complexity
3. Find regex patterns (check for backtracking)
4. Review recursive functions
```

### Phase 3: Resource Limit Review

```
1. Document all resource limits
2. Check timeout configurations
3. Verify rate limiting implementation
4. Review quota enforcement
```

### Phase 4: Stress Testing

```
1. Test with maximum size inputs
2. Send concurrent requests at scale
3. Test slow client handling
4. Verify graceful degradation
```

## Code Patterns to Identify

### Unbounded Allocation

```python
# Vulnerable: allocation based on user input
def process_data(request):
    size = int(request.headers['Content-Length'])
    buffer = bytearray(size)  # User controls allocation size

# Secure: enforce maximum size
MAX_SIZE = 10 * 1024 * 1024  # 10MB
def process_data(request):
    size = int(request.headers['Content-Length'])
    if size > MAX_SIZE:
        raise ValueError("Request too large")
    buffer = bytearray(size)
```

### Dangerous Regex

```python
# Vulnerable: catastrophic backtracking
email_regex = r'^([a-zA-Z0-9]+)+@example\.com$'

# Secure: no nested quantifiers
email_regex = r'^[a-zA-Z0-9]+@example\.com$'
```

### XML Processing

```python
# Vulnerable: entity expansion enabled
from xml.etree import ElementTree
tree = ElementTree.parse(user_file)

# Secure: disable entities
from defusedxml import ElementTree
tree = ElementTree.parse(user_file)
```

### Unbounded Loop

```python
# Vulnerable: user controls iteration count
def process_items(request):
    count = request.json['count']
    for i in range(count):  # Could be billions
        expensive_operation()

# Secure: enforce maximum iterations
MAX_ITEMS = 1000
def process_items(request):
    count = min(request.json['count'], MAX_ITEMS)
    for i in range(count):
        expensive_operation()
```

### Missing Timeout

```python
# Vulnerable: no timeout on external request
def fetch_url(url):
    response = requests.get(url)  # Could hang forever
    return response.content

# Secure: explicit timeout
def fetch_url(url):
    response = requests.get(url, timeout=30)
    return response.content
```

### Unbounded Recursion

```python
# Vulnerable: recursion depth controlled by input
def parse_nested(data):
    if isinstance(data, dict):
        return {k: parse_nested(v) for k, v in data.items()}
    return data

# Secure: limit recursion depth
def parse_nested(data, depth=0, max_depth=100):
    if depth > max_depth:
        raise ValueError("Maximum nesting depth exceeded")
    if isinstance(data, dict):
        return {k: parse_nested(v, depth+1, max_depth) for k, v in data.items()}
    return data
```

## Questions to Answer

1. Are there limits on request body size, file uploads, and other inputs?
2. Are there any regex patterns vulnerable to ReDoS?
3. Is XML/JSON parsing protected against entity expansion and deep nesting?
4. Are hash functions randomized to prevent collision attacks?
5. Are there timeouts on all external calls and long-running operations?
6. Is there rate limiting on expensive endpoints?
7. Are connection pools properly sized with timeouts?
8. Are there limits on recursive/nested data structures?
9. Is decompression protected against zip bombs?
10. How does the system behave under resource exhaustion?

## Output Format

For each identified DoS vector, document:

```
## [Category]: [Specific Finding]

**Severity:** Critical/High/Medium/Low
**Endpoint/Component:** Location

### Attack Vector
[How to trigger the DoS]

### Resource Impact
[What resource is exhausted: CPU/Memory/Connections/Disk]

### Amplification Factor
[Input size to resource consumption ratio]

### Impact
[System behavior under attack]

### Remediation
[Specific limits/changes needed]

### Verification
[How to confirm the fix]
```

## Resource Limit Checklist

- [ ] Request body size limits enforced
- [ ] File upload size limits enforced
- [ ] Connection timeouts configured
- [ ] Request processing timeouts configured
- [ ] Rate limiting on expensive endpoints
- [ ] Regex patterns audited for ReDoS
- [ ] XML/JSON parsing depth limits
- [ ] Entity expansion disabled
- [ ] Hash function randomization
- [ ] Decompression ratio limits
- [ ] Memory allocation caps
- [ ] Connection pool limits
- [ ] Recursion depth limits
- [ ] Graceful degradation under load

---

# Detection Methodology

# Denial of Service via Resource Exhaustion

Resource exhaustion attacks cause service unavailability by consuming finite resources
(memory, CPU, disk, file descriptors, threads, connections) faster than the service can
reclaim them. Unlike volumetric DDoS, these attacks exploit application-level design
flaws so that a single crafted request can bring down a service.

## Methodology

### Step 1 — Identify Unbounded Allocations

Search for code that reads external input into memory without enforcing a size limit.

```python
# Python / Flask — reads entire body into memory
@app.route("/upload", methods=["POST"])
def upload():
    data = request.get_data()  # No size limit — 10 GB body = 10 GB RAM
    process(data)
```

```javascript
// Node.js — accumulating chunks without limit
app.post("/data", (req, res) => {
    let body = "";
    req.on("data", chunk => { body += chunk; });  // Unbounded growth
    req.on("end", () => { processBody(body); res.send("ok"); });
});
```

```go
// Go — ReadAll on untrusted input
func handler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)  // No limit on r.Body size
    var payload Payload
    json.Unmarshal(body, &payload)
}
```

### Step 2 — Detect Algorithmic Complexity Attacks

Look for operations with worse-than-O(n) complexity on attacker-controlled input.

**Hash collision DoS:** Non-randomized hash functions allow crafted keys that all
collide, turning O(1) lookups into O(n).

**Quadratic operations:** Repeated string concatenation in a loop, naive substring
search, or JSON parsers that copy on each nesting level.

```python
# Python — quadratic string building
def build_response(items):
    result = ""
    for item in items:
        result += str(item) + ","  # O(n^2) — new allocation each iteration
    return result
```

```javascript
// Node.js — regex backtracking (ReDoS)
const EMAIL_RE = /^([a-zA-Z0-9]+)+@example\.com$/;
// Input "aaaaaaaaaaaaaaaaaaaaaaaaaaa!" triggers catastrophic backtracking
if (EMAIL_RE.test(userInput)) { /* ... */ }
```

### Step 3 — Check for Recursive and Nested Input Bombs

Deeply nested or self-referencing input structures exhaust stack or cause exponential
expansion: XML billion laughs, zip bombs, deeply nested JSON.

```python
# Python — no depth limit on JSON parsing
@app.route("/api", methods=["POST"])
def api():
    payload = json.loads(request.data)  # 10,000 levels deep = stack overflow
```

```java
// Java — decompressing without size guard (zip bomb)
ZipInputStream zis = new ZipInputStream(uploadedFile);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    FileOutputStream fos = new FileOutputStream("/tmp/" + entry.getName());
    byte[] buf = new byte[4096];
    int len;
    while ((len = zis.read(buf)) > 0) {
        fos.write(buf, 0, len);  // No total-bytes-written check
    }
}
```

### Step 4 — Evaluate Connection and Thread Pool Exhaustion

Slowloris and similar attacks hold connections open without completing requests,
exhausting the server's connection or thread pool.

```go
// Go — no read/write deadlines on net.Conn
func handleConn(conn net.Conn) {
    buf := make([]byte, 4096)
    for {
        n, err := conn.Read(buf)  // No SetReadDeadline — held forever
        if err != nil { return }
        process(buf[:n])
    }
}
```

Look for: missing `ReadTimeout`/`WriteTimeout` on HTTP servers, missing `IdleTimeout`,
thread pools with no queue bound, connection pools with no max-wait timeout.

### Step 5 — Check for Disk Exhaustion Vectors

Uncontrolled writes to disk (logs, temp files, uploads) can fill a partition.

```python
# Python — logging user input at DEBUG with no rotation
@app.route("/search")
def search():
    query = request.args.get("q", "")
    logger.debug(f"Search query: {query}")  # Attacker sends 1 MB queries
```

```javascript
// Node.js — temp file accumulation on error path
app.post("/convert", async (req, res) => {
    const tmpPath = `/tmp/upload_${Date.now()}`;
    await fs.writeFile(tmpPath, req.body);
    const result = await convert(tmpPath);  // If this throws, file stays
    res.send(result);
});
```

### Step 6 — Detect CPU Exhaustion via User Input

CPU-intensive operations that scale with user-controlled input without throttling.

```javascript
// Node.js — event loop blocked by attacker-controlled cost factor
app.post("/hash", (req, res) => {
    const hash = bcrypt.hashSync(req.body.password, req.body.rounds);
    // rounds=20 blocks event loop for minutes
    res.json({ hash });
});
```

```go
// Go — unthrottled image resize
func resizeHandler(w http.ResponseWriter, r *http.Request) {
    img, _ := png.Decode(r.Body)  // 100,000 x 100,000 pixel PNG = ~30 GB RAM
    resized := resize.Resize(800, 0, img, resize.Lanczos3)
    png.Encode(w, resized)
}
```

### Step 7 — Classify Severity

Does the attack require authentication? How many requests are needed? Is recovery
automatic or manual? Single unauthenticated request that crashes = Critical. Thousands
of authenticated requests to degrade = Medium.

## Decision Tree

```
START
  |
  v
[Does the endpoint accept input that controls resource allocation?]
  |                                    |
  NO --> SAFE                         YES
                                       |
                                       v
               [Is there an enforced upper bound on the resource?]
               [  (size limit, timeout, depth limit, rate limit)  ]
                     |                           |
                    YES                          NO
                     |                           |
                     v                           v
         [Is the bound reasonable?]     VULNERABLE (High/Critical)
         [Can it still cause OOM or     single-request crash = Critical
          CPU hang at the limit?]       multi-request degrade = High
              |            |
             YES           NO
              |            |
              v            v
         HARDENED       SAFE
         (Medium)
```

## Real-World Examples

### Example 1 — Unbounded JSON Body in Express.js

```javascript
const app = express();
app.use(express.json({ limit: "50mb" }));  // Raised limit

app.post("/api/batch", async (req, res) => {
    const results = [];
    for (const item of req.body.items) {  // No cap on items.length
        results.push(await processItem(item));
    }
    res.json({ results });
});
```

**Why vulnerable:** No limit on `items.length` means processing time and memory are
unbounded. The `results` array doubles memory usage. An attacker sends a 50 MB array
with millions of entries.

**Impact:** High. Memory exhaustion crashes Node.js. All concurrent users lose service.

**Fix:** Enforce `express.json({ limit: "1mb" })`. Validate `items.length` against a
maximum. Process in batches with backpressure. Set a request timeout.

### Example 2 — ReDoS in Java Input Validation

```java
@RestController
public class ProfileController {
    private static final Pattern TAG_PATTERN =
        Pattern.compile("^(\\w+,?\\s*)+$");  // Nested quantifiers

    @PostMapping("/profile/tags")
    public ResponseEntity<?> updateTags(@RequestBody TagsRequest req) {
        if (!TAG_PATTERN.matcher(req.getTags()).matches()) {
            return ResponseEntity.badRequest().body("Invalid tags");
        }
        return ResponseEntity.ok().build();
    }
}
```

**Why vulnerable:** The regex `^(\w+,?\s*)+$` has nested quantifiers. Input like
`"aaaaaaaaaaaaaaaaaaaaaaaa!"` causes catastrophic backtracking. A single request with
a 30-character string pins a CPU core for minutes.

**Impact:** Critical. One request per thread-pool thread (Tomcat default 200) exhausts
the server. 200 concurrent requests cause full DoS.

**Fix:** Rewrite to `^\\w+(,\\s*\\w+)*$` or validate with string splitting instead.

### Example 3 — Zip Bomb via Python Upload

```python
@app.route("/import", methods=["POST"])
def import_data():
    uploaded = request.files["archive"]
    tmp_path = f"/tmp/{uploaded.filename}"
    uploaded.save(tmp_path)
    with zipfile.ZipFile(tmp_path, "r") as zf:
        zf.extractall("/tmp/extracted/")  # No size check
    return jsonify(process_directory("/tmp/extracted/"))
```

**Why vulnerable:** `extractall` writes without checking uncompressed size. A 42 KB zip
bomb expands to petabytes. Even a 10 MB zip with 10 GB of zeros fills the disk.

**Impact:** Critical. Disk exhaustion affects all host services. Recovery is manual.

**Fix:** Iterate `zf.infolist()`, check each entry's `file_size` and cumulative total
against maximums. Delete temp files in a `finally` block.

```python
MAX_ENTRY = 50 * 1024 * 1024   # 50 MB per file
MAX_TOTAL = 200 * 1024 * 1024  # 200 MB total
with zipfile.ZipFile(tmp_path, "r") as zf:
    total = 0
    for info in zf.infolist():
        if info.file_size > MAX_ENTRY:
            abort(400, "File too large")
        total += info.file_size
        if total > MAX_TOTAL:
            abort(400, "Archive too large")
    zf.extractall("/tmp/extracted/")
```

## Common False Positive Patterns

1. **Enforced body size limits at reverse proxy.** If nginx has `client_max_body_size
   1m`, an unbounded `request.get_data()` in Flask is still bounded. Verify proxy
   config before flagging.

2. **Authenticated and rate-limited endpoints.** An endpoint requiring a session and
   rate-limited to 10 req/min cannot be easily weaponized. Classify HARDENED (Medium).

3. **Streaming processors with backpressure.** Code that reads in fixed-size chunks
   and processes each before reading the next does not hold full input in memory.

4. **Internal-only services behind a service mesh.** Much smaller attack surface.
   Classify HARDENED (Low) unless any compromised internal service can reach it.

5. **Configurable limits set to safe defaults.** A library with `max_depth=20` set by
   the application is not vulnerable. Only flag if the default is unsafe and not
   overridden.

6. **Graceful degradation by design.** Queues that drop on full, circuit breakers
   returning 503 — BY_DESIGN, not a vulnerability, provided no data loss or crash.

7. **Fixed-size pools with rejection policy.** Tomcat with `maxThreads=200` rejects
   beyond capacity. Only flag if missing per-request timeouts enable slowloris.
