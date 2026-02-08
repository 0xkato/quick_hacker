# Regular Expression Denial of Service (ReDoS)

ReDoS exploits regex engines that use backtracking. When a regex contains ambiguous
quantifiers (nested repetition, overlapping alternations), certain inputs cause the
engine to explore an exponential number of paths before failing to match. A single
crafted request can pin a CPU core for hours.

## Methodology

### Step 1: Identify All Regex Usage

```python
# Python — backtracking engine
import re
re.compile(pattern); re.match(pattern, input); re.search(pattern, input)
re.findall(pattern, input); re.sub(pattern, repl, input)
# Safe alternative
import re2  # google-re2: linear-time guarantee
```

```javascript
// Node.js — backtracking engine
new RegExp(userInput)      // CRITICAL: user-controlled pattern
/pattern/.test(input)
str.match(/pattern/); str.replace(/pattern/, repl); str.split(/pattern/)
// Safe: const RE2 = require('re2');
```

```java
// Java — backtracking engine
Pattern.compile(userInput);  // CRITICAL
pattern.matcher(input).matches();
String.matches(pattern); String.replaceAll(pattern, repl); String.split(pattern);
```

```go
// Go — SAFE by default (RE2 engine)
import "regexp"  // Linear-time guarantee
// HOWEVER: github.com/dlclark/regexp2 uses backtracking — VULNERABLE
```

### Step 2: Classify Risk — User-Supplied vs Hardcoded

```python
# CRITICAL: user supplies the regex pattern
@app.route('/search')
def search():
    pattern = request.args.get('q')
    results = re.findall(pattern, document_text)  # Arbitrary ReDoS
    return jsonify(results)

# MODERATE: developer pattern, user supplies input
EMAIL_RE = re.compile(r'^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
def validate(user_input):
    return EMAIL_RE.match(user_input)  # Nested quantifiers + user input
```

### Step 3: Detect Catastrophic Backtracking Patterns

```
# Nested quantifiers — exponential
(a+)+       (a+)*       (a*)*       (a|a)+

# Overlapping alternations with quantifier
(a|ab)+     (\w|\d)+    (.*,)*

# Quantified group with suffix that can fail
(a+)+b      (\w+\s*)+$

# Adjacent overlapping quantifiers — polynomial
\d+\d+\.    .*.*        \w+\w+@
```

### Step 4: Analyze Backtracking Complexity

```python
# Exponential O(2^n): nested quantifiers on same char class
r'(a+)+'     r'([a-z]+)*'

# Polynomial O(n^k): adjacent overlapping quantifiers
r'\d+\d+\d+'   # O(n^3)
r'.*\s.*'       # O(n^2)

# Linear O(n): non-overlapping, no nesting
r'[a-z]+\d+'    r'\w+'
```

```python
# Empirical test
import re, time
pattern = re.compile(r'(a+)+b')
for n in range(15, 30):
    s = 'a' * n + 'X'
    start = time.time()
    pattern.search(s)
    print(f"n={n}: {time.time()-start:.4f}s")
# Each increment roughly doubles time: n=25 ~1.6s, n=30 ~50s
```

### Step 5: Check for Regex Timeout Protections

```java
// Java — manual timeout via thread interruption
ExecutorService exec = Executors.newSingleThreadExecutor();
Future<Boolean> f = exec.submit(() -> pattern.matcher(input).matches());
try { return f.get(1, TimeUnit.SECONDS); }
catch (TimeoutException e) { f.cancel(true); return false; }
```

```javascript
// Node.js — no built-in timeout; event loop blocks during regex
// Options: re2 package, worker thread with timeout, safe-regex lint
const safeRegex = require('safe-regex');
if (!safeRegex(pattern)) throw new Error('Unsafe regex');
```

```python
# Python — signal-based timeout (Unix, main thread only)
import signal
def regex_with_timeout(pattern, string, timeout=1):
    def handler(signum, frame): raise TimeoutError()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try: return re.search(pattern, string)
    finally: signal.alarm(0)
```

### Step 6: Audit Common Vulnerable Validation Patterns

```python
# Email — VULNERABLE (nested [..]+)+
r'^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
# SAFE: r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'

# URL — VULNERABLE (nested [..]*)*
r'^(https?://)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
# SAFE: use urllib.parse instead

# HTML tag — VULNERABLE (nested [^<]+)*
r'<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)'
# SAFE: use an HTML parser

# File path — VULNERABLE (nested [\w\-\.]+)+
r'^(\/?[\w\-\.]+)+\/?$'
# SAFE: r'^[\w\-\.\/]+$'
```

### Step 7: Verify RE2 or Linear-Time Engine Usage

```python
# PITFALL: mixing re and re2
import re, re2
safe = re2.compile(r'(a+)+b')     # Linear-time
unsafe = re.compile(r'(a+)+b')    # Backtracking — VULNERABLE
# Verify ALL regex calls use re2, not just some
```

```go
import "regexp"    // SAFE: RE2
import "github.com/dlclark/regexp2"  // UNSAFE: backtracking
```

## Decision Tree

```
Code uses regex matching?
|
+-- NO --> SAFE
|
+-- YES
    |
    RE2/linear-time engine? (Go regexp, google-re2, rust regex)
    |
    +-- YES --> SAFE
    |
    +-- NO (Python re, Node.js, Java Pattern)
        |
        Pattern user-supplied?
        |
        +-- YES --> Timeout? YES --> HARDENED (Medium) / NO --> VULNERABLE (Critical)
        |
        +-- NO (developer pattern)
            |
            Nested quantifiers or overlapping alternations?
            +-- YES --> User input matched? YES --> VULNERABLE (High) / NO --> HARDENED (Low)
            +-- NO  --> Adjacent greedy quantifiers on same class?
                +-- YES --> HARDENED (Medium) — polynomial
                +-- NO  --> SAFE
```

## Real-World Examples

### Example 1: ReDoS in Node.js Express Route Validation

```javascript
const SAFE_PATH = /^([\w\-\.\/]+)+$/;
app.use((req, res, next) => {
    if (!SAFE_PATH.test(req.path)) return res.status(400).send('Invalid');
    next();
});
```

**Why vulnerable:** `([\w\-\.\/]+)+` has nested quantifiers. A long valid string
followed by an invalid character (e.g., `"a".repeat(50) + "\x00"`) causes exponential
backtracking. Node.js is single-threaded, so ALL requests are blocked.

**Impact:** Single request freezes entire process for minutes. Complete DoS.

**Fix:**
```javascript
const SAFE_PATH = /^[\w\-\.\/]+$/;  // Single quantifier, linear
// Or: const RE2 = require('re2'); new RE2('^([\\w\\-\\.\\/]+)+$');
```

### Example 2: User-Supplied Regex in Python Search

```python
@app.route('/api/logs/search', methods=['POST'])
def search_logs():
    pattern = request.json.get('pattern')
    regex = re.compile(pattern)  # User-controlled!
    matches = [line for line in load_logs() if regex.search(line)]
    return jsonify(matches)
```

**Why vulnerable:** Arbitrary regex compiled with backtracking engine. Pattern like
`(.*)*X` causes exponential backtracking on every log line.

**Impact:** CPU exhaustion. Single request consumes 100% CPU for hours.

**Fix:**
```python
import re2
try: regex = re2.compile(pattern)
except re2.error: return jsonify(error="Invalid regex"), 400
matches = [line for line in load_logs() if regex.search(line)]
```

### Example 3: ReDoS in Java Email Validation

```java
private static final Pattern EMAIL = Pattern.compile(
    "^([a-zA-Z0-9]+(\\.[a-zA-Z0-9]+)*)+@[a-zA-Z0-9-]+(\\.[a-zA-Z]{2,})+$"
);
public boolean isValid(String email) {
    return EMAIL.matcher(email).matches();
}
// Input: "aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa.aaa!@x.com" — exponential
```

**Why vulnerable:** `([a-zA-Z0-9]+(\.[...]+)*)+` has nested quantified groups, both
matching alphanumerics. Failed match explores all string partitions.

**Impact:** Each validation on crafted input takes seconds to minutes. Trivial DoS.

**Fix:**
```java
private static final Pattern EMAIL = Pattern.compile(
    "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
);  // No nested quantifiers
```

## Common False Positive Patterns

1. **Go `regexp` package** — RE2 engine guarantees linear time. Only flag `regexp2`.

2. **Rust `regex` crate** — Finite automaton with linear guarantee. Only flag
   `fancy-regex` which supports backtracking.

3. **Bounded input length** — If input max-length is enforced BEFORE regex matching
   (e.g., max 50 chars), even exponential patterns complete in bounded time.

4. **Simple literal patterns** — `r'^admin$'` or `r'error'` with no quantifiers,
   alternations, or groups have O(n) complexity regardless of engine.

5. **Build/deploy-time only** — Patterns in build scripts that never process user
   input at runtime are not exploitable via network requests.

6. **safe-regex lint in CI** — Static analyzer blocking vulnerable patterns at deploy
   time prevents new ReDoS. Verify coverage of all regex sources.

7. **Possessive quantifiers / atomic groups** — Java `a++` and `(?>...)` prevent
   backtracking into the group. Verify double `+` (possessive) not single (greedy).
