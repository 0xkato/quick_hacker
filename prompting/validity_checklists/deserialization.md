# Deserialization Vulnerability Proof Checklist

You are analyzing a potential unsafe deserialization vulnerability. Follow this evidence-gathering plan:

## 1. Identify the Sink (sink_present)

**Goal:** Prove that untrusted data is deserialized.

**Evidence Required:**
- Exact file path and line number of deserialization operation
- Function name: `pickle.loads()`, `yaml.load()`, `unserialize()`, `readObject()`, `JSON.parse()` with reviver, `eval()` on serialized data

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(pickle\\.loads?\\(|yaml\\.load\\(|yaml\\.unsafe_load\\(|unserialize\\(|readObject\\(|ObjectInputStream|deserialize\\()",
    "file_pattern": "**/*.{py,java,php,js,ts}",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if deserialization operation found
- `sink_present = PROVEN_FALSE` if no deserialization operations in codebase
- `sink_present = UNKNOWN` if files are missing or code is obfuscated

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls the serialized data being deserialized.

**Evidence Required:**
- Input comes from: request body, cookies, headers, files, database (user-controlled), network sockets
- NOT from: hardcoded values, config files, admin-only inputs, trusted internal services

**Common Patterns:**
- Python: `request.data`, `request.get_data()`, `request.files['upload'].read()`
- Java: Reading from HTTP request stream, file uploads
- PHP: `$_POST`, `$_COOKIE`, file uploads
- Node.js: `req.body`, `req.cookies`

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/session.py",
    "start_line": 40,
    "end_line": 70
  }
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if input is from HTTP request/external source
- `source_controlled_input = PROVEN_FALSE` if input is hardcoded or from trusted source
- `source_controlled_input = UNKNOWN` if input origin is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input flows to deserialization without cryptographic verification.

**Evidence Required:**
- Step-by-step path from source to sink
- Cite each intermediate variable/function with file:line
- Prove that HMAC/signature verification is absent or bypassable

**Safe Patterns (Signature Verification):**
If you see:
```python
# Signed cookies with HMAC verification (SAFE)
session_data = request.get_signed_cookie('session', secret=SECRET_KEY)
data = pickle.loads(session_data)
# SAFE - signature verified before deserialization
```

```python
# JSON with allowlist (SAFE)
data = json.loads(user_input)
if data['type'] in ALLOWED_TYPES:
    # Safe - JSON doesn't execute code, and type is allowlisted
```

**Unsafe Patterns (No Verification):**
If you see:
```python
# Pickle without verification (UNSAFE)
data = pickle.loads(request.data)
# UNSAFE - attacker can craft malicious pickle payload
```

```python
# YAML unsafe_load (UNSAFE)
config = yaml.unsafe_load(user_input)
# UNSAFE - can instantiate arbitrary Python objects
```

```java
// Java deserialization without filtering (UNSAFE)
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();
// UNSAFE - gadget chain attacks possible
```

**Tool Call Example:**
```json
{
  "tool": "trace_data_flow",
  "arguments": {
    "source": "request.cookies['session']",
    "file_path": "app/auth.py",
    "sink_patterns": ["pickle.loads(", "yaml.load("]
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unsigned/unverified deserialization
- `dataflow_evidenced = PROVEN_FALSE` if HMAC/signature verified or safe format (JSON)
- `dataflow_evidenced = UNKNOWN` if intermediate steps are missing

## 4. Verify Reachability (reachable)

**Goal:** Prove the vulnerable code path can actually execute.

**Evidence Required:**
- Function is called (not dead code)
- Route/API endpoint is registered
- No conditional guards that prevent execution

**Tool Call Example:**
```json
{
  "tool": "get_entry_points",
  "arguments": {
    "framework": "flask"
  }
}
```

**Checklist Update:**
- `reachable = PROVEN_TRUE` if function is called and route is registered
- `reachable = PROVEN_FALSE` if dead code or feature-flagged off
- `reachable = UNKNOWN` if call graph is incomplete

## 5. Verify Boundary Crossing (boundary_crossed)

**Goal:** Prove external input reaches the deserialization.

**Evidence Required:**
- Input comes from outside the system (HTTP, network socket, file upload, etc.)
- NOT an internal admin function or trusted service communication

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(@login_required|@admin_required|@require_auth|authenticate)",
    "file_pattern": "**/*.py",
    "max_results": 50
  }
}
```

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if externally accessible (e.g., public API, cookie handling)
- `boundary_crossed = PROVEN_FALSE` if internal-only trusted communication
- `boundary_crossed = UNKNOWN` if access controls are unclear

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Evidence Required:**
- Vulnerability exists regardless of config settings
- NOT just "trusted deserialization enabled" config flag

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a config issue
- `not_only_misconfig = UNKNOWN` if unclear

## 7. StrictClassifier Alignment

**Expected Disposition:**
- If ALL 6 items are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- If sink_present or source_controlled_input is PROVEN_FALSE → `BY_DESIGN` or `SPECULATIVE`
- If dataflow_evidenced is PROVEN_FALSE (signature verified) → `BY_DESIGN` (safe by design)
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE` (unless preliminary_disposition fast-tracks)

**Disposition-Sensitive Downgrades:**
- If preliminary_disposition is already `BUG` or `VALID_SECURITY_ISSUE`, critic should fast-track to `READY_TO_REPORT` unless contradictions exist
- If preliminary_disposition is `MISCONFIGURATION`, critic should return `STOP_FILTERED` with disposition_hint='MISCONFIGURATION'

## Common False Positives to Avoid

**Trap 1: JSON Deserialization**
```python
# JSON.loads() is SAFE - doesn't execute code
data = json.loads(user_input)
# sink_present = PROVEN_FALSE (JSON is not unsafe deserialization)
# UNLESS: Custom reviver/decoder executes code OR JSON values are used unsafely
```

**Trap 2: Signed Cookies**
```python
# Django signed cookies (SAFE)
from django.core.signing import loads
data = loads(cookie_value)
# SAFE - signature verified before deserialization
# dataflow_evidenced = PROVEN_FALSE
```

**Trap 3: YAML Safe Load**
```python
# yaml.safe_load() is SAFE (YAML 1.2)
config = yaml.safe_load(user_input)
# SAFE - only loads basic YAML types, no object instantiation
# sink_present = PROVEN_FALSE (or dataflow_evidenced = PROVEN_FALSE)
```

**Trap 4: Allowlisted Classes (Java)**
```java
// ObjectInputStream with allowlist filter (SAFER)
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(info -> {
    return ALLOWED_CLASSES.contains(info.serialClass()) ?
        ObjectInputFilter.Status.ALLOWED :
        ObjectInputFilter.Status.REJECTED;
});
Object obj = ois.readObject();
// SAFER - but allowlist must be verified to not contain gadget classes
// dataflow_evidenced may still be PROVEN_TRUE if gadgets in allowlist
```

**Trap 5: Trusted Internal Services**
```python
# Deserialization from trusted internal service (SAFER)
# If service-to-service communication with mTLS and network segmentation
data = pickle.loads(internal_service_response)
# boundary_crossed = PROVEN_FALSE (internal trusted boundary)
# But still risky - prefer JSON for inter-service communication
```

## Language-Specific Patterns

### Python
**Dangerous:**
- `pickle.loads(untrusted_data)` - Can execute arbitrary code via `__reduce__`
- `yaml.unsafe_load(untrusted_data)` or `yaml.load()` without Loader - Can instantiate arbitrary objects
- `marshal.loads(untrusted_data)` - Similar to pickle

**Safe:**
- `json.loads(untrusted_data)` - Safe (no code execution)
- `yaml.safe_load(untrusted_data)` - Safe (basic types only)
- `pickle.loads()` with HMAC signature verification

### Java
**Dangerous:**
- `ObjectInputStream.readObject()` without filtering - Gadget chain attacks
- Custom `Serializable` classes with dangerous `readObject()` methods

**Safe:**
- `ObjectInputStream` with allowlist filter (if allowlist is truly safe)
- JSON libraries (Jackson, Gson)

### PHP
**Dangerous:**
- `unserialize(untrusted_data)` - Can instantiate arbitrary classes
- Magic methods like `__wakeup()`, `__destruct()` can be exploited

**Safe:**
- `json_decode(untrusted_data)` - Safe
- `unserialize()` with `allowed_classes` option (if allowlist is safe)

### Node.js
**Dangerous:**
- `require('node-serialize').unserialize()` - Can execute code
- `eval()` on serialized data

**Safe:**
- `JSON.parse()` - Safe (no code execution by default)
- Avoid custom deserializers

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
- Never say "I believe" or "it appears" - use UNKNOWN if uncertain

## Key Insight

Deserialization vulnerabilities require:
1. **Dangerous format** (pickle, YAML unsafe_load, Java serialization, PHP unserialize)
2. **Attacker-controlled data** (not signed/verified)
3. **Exploitable gadget chain** (Python: `__reduce__`, Java: gadget classes, PHP: magic methods)

JSON deserialization is generally safe unless custom parsers execute code.
