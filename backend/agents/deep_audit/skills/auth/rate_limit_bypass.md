# Rate Limiting Bypass Detection

Rate limiting bypass vulnerabilities occur when an attacker circumvents rate controls
protecting sensitive endpoints. Missing rate limits on login, password reset, or OTP
verification enable brute-force attacks, credential stuffing, and account takeover.
Even when rate limiting exists, keying on a bypassable identifier (spoofable IP header,
rotatable API key) or implementing per-instance rather than globally negates the control.

## Methodology

### Step 1: Inventory Sensitive Endpoints

Identify every endpoint where unlimited requests create a security risk.

```
CRITICAL: POST /login, /password/reset, /otp/verify, /2fa/verify, /register, /oauth/token
HIGH:     POST /payment, /checkout (card testing), /invites (spam)
          GET  /users/:id (enumeration), /api/* (general abuse)
```

### Step 2: Verify Rate Limit Middleware Is Applied

Check that limiters are attached to endpoints, not just imported.

```python
# Flask-Limiter VULNERABLE: limiter exists but not applied
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/login", methods=["POST"])
def login():                            # no @limiter.limit() decorator
    user = authenticate(request.json["username"], request.json["password"])

# SAFE: decorator applied
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login(): ...
```

```javascript
// Express VULNERABLE: limiter defined but never used as middleware
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5 });
app.post("/api/login", async (req, res) => { ... }); // no loginLimiter

// SAFE: limiter in middleware chain
app.post("/api/login", loginLimiter, async (req, res) => { ... });
```

### Step 3: Examine the Rate Limit Key Function

If the key can be spoofed or rotated, the rate limit is bypassable.

```python
# VULNERABLE: keyed on X-Forwarded-For (attacker-controlled)
limiter = Limiter(app,
    key_func=lambda: request.headers.get("X-Forwarded-For", request.remote_addr))

# SAFE: keyed on authenticated user ID
limiter = Limiter(app,
    key_func=lambda: str(current_user.id) if current_user.is_authenticated
                     else request.remote_addr)

# SAFE: trusted proxy configured
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)  # trust only 1 proxy
```

```javascript
// VULNERABLE: trusts x-forwarded-for without proxy config
keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip

// SAFE: trust proxy configured, default key uses req.ip
app.set('trust proxy', 1);
```

### Step 4: Check Distributed Rate Limiting Consistency

In-memory storage is per-instance. With N instances, effective limit is Nx.

```python
# VULNERABLE: per-process memory
limiter = Limiter(app, storage_uri="memory://")  # each instance has own counter

# SAFE: shared Redis
limiter = Limiter(app, storage_uri="redis://redis:6379/0")
```

```javascript
// VULNERABLE: default MemoryStore (per-process)
const limiter = rateLimit({ windowMs: 15*60*1000, max: 5 });

// SAFE: Redis store
const limiter = rateLimit({ max: 5,
    store: new RedisStore({ sendCommand: (...args) => redis.sendCommand(args) })
});
```

### Step 5: Audit OTP/MFA Verification

Small code space (4-6 digits) makes brute force trivially fast without limits.

```python
# VULNERABLE: no rate limit, no attempt counter
@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    if User.query.get(request.json["user_id"]).otp_code == request.json["code"]:
        return jsonify({"verified": True})  # 6-digit: 1M possibilities

# SAFE: rate limit + attempt counter + expiry
@app.route("/api/verify-otp", methods=["POST"])
@limiter.limit("3 per minute")
def verify_otp():
    session = OTPSession.query.filter_by(token=request.json["token"]).first()
    if not session or session.expired: abort(400)
    if session.attempts >= 5:
        session.invalidate(); abort(429, "Request a new code")
    session.attempts += 1
    if session.code != request.json["code"]:
        db.session.commit(); abort(401)
    session.verified = True; db.session.commit()
```

### Step 6: Inspect GraphQL Query Cost and Batching

Single /graphql URL makes per-endpoint limiting insufficient. Nested queries and
batching multiply work per request.

```javascript
// VULNERABLE: flat rate limit regardless of query cost
app.use("/graphql", rateLimit({ max: 100 }));
// Attacker: [{ query: "..." }, { query: "..." }, ...] x100 in one request

// SAFE: query cost analysis + batch size limit
const cost = calculateQueryCost(document);
if (cost > MAX_QUERY_COST) throw new GraphQLError("Query too complex");
if (Array.isArray(req.body) && req.body.length > MAX_BATCH_SIZE)
    return res.status(400).json({ error: "Batch too large" });
```

### Step 7: Check Batch/Bulk REST Endpoints

Batch endpoints multiply effective rate by batch size.

```python
# VULNERABLE: 100 req/min limit but 1000 emails per request = 100K lookups/min
@app.route("/api/users/lookup", methods=["POST"])
@limiter.limit("100 per minute")
def bulk_lookup():
    emails = request.json["emails"]      # unbounded batch size
    return jsonify([{"email": e, "exists": bool(User.query.filter_by(email=e).first())}
                    for e in emails])

# SAFE: batch size capped
if len(emails) > 10: abort(400, "Maximum 10 per request")
```

### Step 8: Verify Nginx/API Gateway and Race Conditions

Check gateway-level limits cover sensitive paths, and that rate counters increment
before processing (not after).

```nginx
# VULNERABLE: /api/login not covered         # SAFE: stricter limit
location /api/login {                         limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    proxy_pass http://backend;                location /api/login {
}                                                 limit_req zone=login burst=3 nodelay;
                                                  proxy_pass http://backend; }
```

```python
# VULNERABLE: action before rate counter     # SAFE: middleware checks first
def password_reset():                         @limiter.limit("3 per hour")
    send_reset_email(user)                    def password_reset():
    increment_rate_counter(email)  # late         send_reset_email(user)
```

## Decision Tree

```
[Sensitive endpoint? (login, OTP, password reset, registration)]
    +--NO--> SAFE (rate limiting optional)
    +--YES
        [Rate limit applied?]
            +--NO--> VULNERABLE (Critical) "No rate limit"
            +--YES
                [Key from trusted source? (real IP, user ID)]
                    +--NO--> VULNERABLE (High) "Spoofable key"
                    +--YES
                        [Global storage (Redis) vs in-memory?]
                            +--IN-MEMORY + multi-instance --> VULNERABLE (High)
                            +--IN-MEMORY + single-instance --> HARDENED (Medium)
                            +--GLOBAL
                                [Batch/GraphQL multiplier checked?]
                                    +--NO--> VULNERABLE (High) "Batch bypass"
                                    +--YES
                                        [OTP: attempt counter + expiry?]
                                            +--NO--> HARDENED (Medium)
                                            +--YES--> SAFE
```

## Real-World Examples

### Example 1: Login Endpoint Without Rate Limiting

```python
@app.route("/api/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.json["email"]).first()
    if user and user.check_password(request.json["password"]):
        return jsonify({"access_token": create_access_token(identity=user.id)})
    return jsonify({"error": "Invalid credentials"}), 401
```

**Why vulnerable:** No rate limit, no lockout, no CAPTCHA. Thousands of password
attempts per second. Timing differences may also enable user enumeration.

**Impact:** Credential stuffing and brute-force at scale. Combined with breach dumps,
significant account compromise rate.

**Fix:**
```python
@limiter.limit("5 per minute;20 per hour",
    key_func=lambda: request.json.get("email", request.remote_addr))
def login(): ...  # plus account lockout after 10 failed attempts
```

### Example 2: Rate Limit Keyed on X-Forwarded-For

```javascript
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 100,
    keyGenerator: (req) => req.headers["x-forwarded-for"] || req.connection.remoteAddress,
});
```

**Why vulnerable:** X-Forwarded-For is client-set. Attacker rotates the header per
request, each value gets its own counter. Effective limit: infinite.

**Impact:** Complete rate limit bypass. All protections nullified.

**Fix:**
```javascript
app.set("trust proxy", 1);  // trust correct number of proxies
const limiter = rateLimit({ max: 100,  // default key uses req.ip
    store: new RedisStore({ sendCommand: (...args) => redis.sendCommand(args) }) });
```

### Example 3: OTP Without Attempt Limiting

```python
@app.route("/api/verify-phone", methods=["POST"])
@limiter.limit("60 per minute")
def verify_phone():
    stored = redis_client.get(f"otp:{request.json['phone']}")
    if stored and stored.decode() == request.json["code"]:
        return jsonify({"verified": True})
    return jsonify({"verified": False}), 400
```

**Why vulnerable:** 60 attempts/min against 4-digit OTP (10K possibilities) means
complete brute force in under 3 hours. No per-phone attempt counter; OTP is never
invalidated after failed attempts.

**Impact:** Phone verification bypass. Account takeover via MFA bypass.

**Fix:**
```python
@limiter.limit("5 per minute")
def verify_phone():
    attempts = int(redis_client.get(f"otp_attempts:{phone}") or 0)
    if attempts >= 5:
        redis_client.delete(f"otp:{phone}"); abort(429, "Request new code")
    redis_client.incr(f"otp_attempts:{phone}")
    redis_client.expire(f"otp_attempts:{phone}", 600)
```

## Common False Positive Patterns

1. **API gateway/CDN-level rate limiting** (Cloudflare, AWS API Gateway, Kong) not
   visible in application code. Check infra configs and Terraform templates.

2. **Internal/admin endpoints** behind VPN or IP allowlist, not publicly reachable.
   Rate limiting less critical behind network boundaries.

3. **Webhook receiver endpoints** from trusted services (Stripe, GitHub) authenticated
   by signature verification. High volume of callbacks is expected.

4. **Health check endpoints** (`/healthz`, `/metrics`) called by orchestration systems.
   Rate limiting these causes false deployment failures.

5. **Static asset endpoints** (`/static/`, `/assets/`) served by CDN with its own rate
   limiting and caching layer.

6. **WebSocket upgrade endpoints** establishing long-lived connections. Rate limiting
   the handshake is valid, but the persistent connection is not "unlimited requests."

7. **Read-only public endpoints** serving cached, non-sensitive data where high volume
   is an availability concern, not a security finding.
