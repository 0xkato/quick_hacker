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