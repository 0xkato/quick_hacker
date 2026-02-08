# Sensitive Data Exposure Detection

Detect sensitive information (PII, credentials, internal state) leaked through
API responses, logs, error pages, or client-side storage via careless
serialization or verbose error handling.

## Methodology

### Step 1 — Inventory Sensitive Fields

Build a project-wide list of fields that must never appear in untrusted output.

Universal: `password, password_hash, secret, token, api_key, ssn,
credit_card, cc_number, cvv, pan, private_key, signing_key, session_id`

PII: `email (context-dependent), phone, address, ip_address,
first_name+last_name (with identifiers), medical_record, diagnosis`

Search model definitions for these fields across Django, SQLAlchemy, Spring JPA.

### Step 2 — Trace Serialization Paths

Check every serializer and response builder for sensitive field inclusion.

```python
# VULNERABLE — Django REST: exposes password_hash via __all__
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
# SAFE — explicit allowlist
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "display_name"]
```

```python
# VULNERABLE — Flask: dumps entire ORM object
return jsonify(user.__dict__)
# SAFE — explicit projection
return jsonify({"id": user.id, "name": user.name})
```

```javascript
// VULNERABLE — Express: returns full DB row
res.json(user);
// SAFE — destructure needed fields only
const { id, name, avatar } = user;
res.json({ id, name, avatar });
```

```java
// VULNERABLE — Spring: returns entity with passwordHash
@GetMapping("/user/{id}") @ResponseBody
public User getUser(@PathVariable Long id) {
    return userRepository.findById(id).orElseThrow();
}
// SAFE — map to DTO excluding sensitive fields
public UserDTO getUser(@PathVariable Long id) { ... }
```

### Step 3 — Inspect Log Statements

Scan every log call for sensitive data interpolated directly.

```python
# VULNERABLE — plaintext password and full request body
logger.info(f"Login attempt for {username} with password {password}")
logger.debug(f"Request body: {request.json}")
# SAFE
logger.info(f"Login attempt for user_id={user.id}")
```

```java
// VULNERABLE — credit card number in payment log
log.info("Processing payment for card: {}", creditCardNumber);
// SAFE — mask all but last 4
log.info("Processing payment for card: ****{}", last4Digits);
```

### Step 4 — Analyze Error Responses

Check exception handlers and 500 pages for stack traces, SQL, and local vars.

```python
# VULNERABLE — stack trace sent to client
@app.errorhandler(500)
def handle_error(e):
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500
# VULNERABLE — Django DEBUG=True in production
```

```javascript
// VULNERABLE — full error object including DB query
app.use((err, req, res, next) => {
  res.status(500).json({ message: err.message, stack: err.stack, query: err.sql });
});
```

### Step 5 — Check Client-Side Storage

```javascript
// VULNERABLE — JWT in localStorage (XSS-accessible)
localStorage.setItem("authToken", response.data.token);
// VULNERABLE — PII cached in sessionStorage
sessionStorage.setItem("userProfile", JSON.stringify(fullProfile));
// SAFE — HttpOnly Secure cookie set server-side
```

### Step 6 — Evaluate Encryption at Rest

```python
# VULNERABLE — SSN in plaintext column
class Patient(models.Model):
    ssn = models.CharField(max_length=11)
# SAFE — field-level encryption
from django_cryptography.fields import encrypt
class Patient(models.Model):
    ssn = encrypt(models.CharField(max_length=11))
```

### Step 7 — Audit GraphQL Introspection

```javascript
// VULNERABLE — introspection enabled in production (default)
const server = new ApolloServer({ typeDefs, resolvers });
// SAFE — disabled outside development
const server = new ApolloServer({
  typeDefs, resolvers,
  introspection: process.env.NODE_ENV === "development",
});
```

## Decision Tree

```
START
  |
  v
Serializer uses "__all__", full-object dump, or returns ORM entity?
  |YES                          |NO
  v                             v
Sensitive fields on model?    Response uses minimum fields?
  |YES      |NO                |YES      |NO
  v         v                  v         v
VULN      Check logs         SAFE     Check each field vs inventory
(High)                                  |MATCH    |NO MATCH
                                        v         v
                                     VULN(High)  SAFE
--- Log Path ---
Log interpolates sensitive field?
  |YES                    |NO
  v                       v
Masked/hashed first?    SAFE
  |YES    |NO
  v       v
SAFE    VULN(High — PII/creds in logs)

--- Error Path ---
Error handler returns traces/SQL/locals?
  |YES                    |NO
  v                       v
Gated behind DEBUG?     SAFE
  |YES       |NO
  v          v
HARDENED   VULN(Critical)
(Medium)

--- Storage Path ---
Sensitive data in localStorage/sessionStorage?
  |YES          |NO
  v             v
VULN(High)    Auth token in non-HttpOnly cookie?
                |YES       |NO
                v          v
              VULN(High)  SAFE
```

## Real-World Examples

### Example 1 — Password Hash in User API (Django REST Framework)

```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User  # has password_hash, api_key columns
        fields = "__all__"
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
```

**Why vulnerable:** `fields = "__all__"` includes `password_hash` and `api_key`
in every response. Any authenticated caller receives credential material.

**Impact:** Critical. Offline hash cracking and API key theft escalate a single
low-privilege account to full credential exposure.

**Fix:** Use `fields = ["id", "username", "is_active"]` or `exclude`.

### Example 2 — Credit Card Numbers in Logs (Node.js)

```javascript
app.post("/api/checkout", async (req, res) => {
  const { cardNumber, cvv, expiry, amount } = req.body;
  logger.info(`Processing payment: card=${cardNumber}, amount=${amount}`);
  // ... also logged on failure path
});
```

**Why vulnerable:** Full card number written to logs on every transaction. Logs
are retained for months on shared infrastructure and aggregation platforms.

**Impact:** High. PCI-DSS 3.4 violation. Log breach exposes every processed card.

**Fix:** `logger.info(\`card=${"****" + cardNumber.slice(-4)}\`)`.

### Example 3 — Stack Trace in Error Response (Spring)

```java
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class) @ResponseBody
    public ResponseEntity<Map<String, Object>> handleAll(Exception ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("message", ex.getMessage());
        body.put("stackTrace", Arrays.toString(ex.getStackTrace()));
        body.put("rootCause", ex.getCause() != null ? ex.getCause().getMessage() : null);
        return ResponseEntity.status(500).body(body);
    }
}
```

**Why vulnerable:** Full stack trace and root cause (often SQL with table/column
names and partial row data) sent to the client.

**Impact:** Critical. Reveals class names, library versions, DB schema, and query
structure, enabling targeted injection attacks.

**Fix:** Log internally, return opaque error with a reference ID only.

## Common False Positive Patterns

1. **Admin-only endpoints returning full objects.** If restricted to superusers
   via enforced RBAC and the fields serve admin functionality, may be BY_DESIGN.
   Verify the auth gate is at middleware level, not just UI-hidden.

2. **Hashed/masked values resembling raw data.** A `password_hash` containing a
   bcrypt string (`$2b$12$...`) is not the raw password. Check actual content.

3. **Encrypted fields for client-side decryption.** E2E encrypted apps return
   opaque blobs by design. Verify the field is truly encrypted, not base64.

4. **Test fixtures with synthetic PII.** `ssn = "000-00-0000"` in test dirs with
   obviously fake values is not real exposure.

5. **Structured logging with redaction middleware.** Pino `redact`, logback
   custom converters strip fields before writing. Check logger config first.

6. **GraphQL introspection disabled at gateway.** Apollo may show
   `introspection: true` but Kong/AppSync blocks queries upstream. Check infra.

7. **Single-use expired tokens in logs.** Reset tokens with 15-min TTL and
   single-use enforcement in logs are HARDENED(Low), not VULNERABLE.
