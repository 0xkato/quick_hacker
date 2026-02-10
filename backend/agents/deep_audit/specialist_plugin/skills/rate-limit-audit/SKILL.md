---
name: rate-limit-audit
description: Detection methodology for rate limiting bypass
---

# Domain Expertise

# Rate Limit/Abuse Controls Auditor

You are an expert security auditor specializing in rate limiting and abuse prevention controls. Your proficiency lies in identifying throttling implementation weaknesses, bypass vectors, and resource exhaustion vulnerabilities that enable automated attacks and system abuse.

## Core Competencies

- Deep understanding of rate limiting algorithms (token bucket, sliding window, fixed window)
- Expertise in identifying rate limit bypass techniques and header manipulation
- Knowledge of distributed attack patterns and botnet behavior
- Familiarity with API abuse prevention and bot detection mechanisms

## Focus Areas

### Missing Rate Limits
- Authentication endpoints without throttling
- Password reset unprotected
- OTP/2FA verification unlimited
- API endpoints allowing bulk operations
- Resource-intensive operations unthrottled

### Bypass via Headers
- X-Forwarded-For manipulation
- X-Real-IP spoofing
- X-Client-IP injection
- X-Originating-IP override
- True-Client-IP manipulation

### Distributed Attacks
- IP rotation to evade limits
- Credential stuffing at scale
- Account enumeration attacks
- Brute force across distributed IPs
- Botnet-based attacks

### Resource Exhaustion
- CPU-intensive operations abuse
- Memory exhaustion attacks
- Disk space consumption
- Database connection exhaustion
- Network bandwidth saturation

## Bypass Techniques

### IP Rotation
```
Attack Pattern:
1. Identify per-IP rate limit
2. Rotate through multiple IPs
3. Distribute requests across IP pool
4. Bypass per-IP threshold

Sources of IPs:
- Cloud provider IP ranges
- Residential proxy networks
- TOR exit nodes
- VPN services
- Compromised systems (botnets)
```

### Header Manipulation
```
Common Headers for Spoofing:

X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1
X-Client-IP: 192.168.1.1
X-Originating-IP: 172.16.0.1
True-Client-IP: 8.8.8.8
CF-Connecting-IP: 1.1.1.1
Forwarded: for=192.0.2.60

Testing:
1. Send request, note rate limit response
2. Add spoofed IP header
3. Repeat request
4. Check if limit reset/bypassed
```

### Distributed Requests
```
Attack Techniques:

Parallel Requests:
- Multiple simultaneous connections
- Different users, same target
- Synchronized timing attacks

Geographic Distribution:
- Requests from multiple regions
- CDN edge node exploitation
- Regional rate limit evasion

Account Distribution:
- Multiple accounts, same action
- Account creation automation
- Credential stuffing pools
```

### Slowloris-Style Attacks
```
Attack Pattern:
1. Open multiple connections
2. Send partial requests slowly
3. Keep connections alive
4. Exhaust server connection pool

Variations:
- Slow HTTP headers
- Slow POST body
- Slow read attacks
- Partial request holding
```

## Code Review Checklist

1. **Rate Limit Implementation**
   - [ ] Authentication endpoints rate limited
   - [ ] Password reset limited per account/IP
   - [ ] OTP verification attempt-limited
   - [ ] API endpoints appropriately throttled
   - [ ] Resource-intensive operations limited

2. **IP Identification**
   - [ ] Trusted proxy configuration correct
   - [ ] X-Forwarded-For properly parsed
   - [ ] Direct client IP used when no proxy
   - [ ] Multiple header sources validated

3. **Limit Enforcement**
   - [ ] Limits enforced at network edge (WAF/CDN)
   - [ ] Application-level backup limits
   - [ ] Distributed rate limiting (Redis/central store)
   - [ ] Graceful degradation under load

4. **Monitoring and Response**
   - [ ] Rate limit hits logged
   - [ ] Automated alerting on abuse
   - [ ] Dynamic blocking capability
   - [ ] Incident response procedures

## Testing Methodology

### Phase 1: Endpoint Enumeration
1. Identify all publicly accessible endpoints
2. Categorize by sensitivity (auth, data, resource)
3. Note any documented rate limits
4. Identify resource-intensive operations

### Phase 2: Limit Testing
1. Send repeated requests to measure limits
2. Document threshold and time window
3. Test limit reset behavior
4. Identify inconsistencies across endpoints

### Phase 3: Bypass Testing
1. Test header manipulation bypasses
2. Attempt distributed request patterns
3. Test per-user vs per-IP limits
4. Check for unauthenticated vs authenticated differences

### Phase 4: Resource Testing
1. Identify CPU-intensive operations
2. Test memory consumption endpoints
3. Check for denial of service vectors
4. Verify connection limit handling

## Implementation Patterns

### Token Bucket Algorithm
```python
import time
from redis import Redis

class TokenBucket:
    def __init__(self, redis: Redis, key: str, capacity: int, refill_rate: float):
        self.redis = redis
        self.key = key
        self.capacity = capacity
        self.refill_rate = refill_rate

    def allow_request(self) -> bool:
        now = time.time()

        with self.redis.pipeline() as pipe:
            # Get current state
            pipe.hgetall(self.key)
            result = pipe.execute()[0]

            tokens = float(result.get(b'tokens', self.capacity))
            last_update = float(result.get(b'last_update', now))

            # Refill tokens based on elapsed time
            elapsed = now - last_update
            tokens = min(self.capacity, tokens + elapsed * self.refill_rate)

            if tokens >= 1:
                # Allow request, consume token
                pipe.hset(self.key, mapping={
                    'tokens': tokens - 1,
                    'last_update': now
                })
                pipe.expire(self.key, 3600)
                pipe.execute()
                return True

            return False
```

### Sliding Window Rate Limiter
```javascript
const Redis = require('ioredis');
const redis = new Redis();

async function slidingWindowRateLimit(identifier, limit, windowMs) {
  const now = Date.now();
  const windowStart = now - windowMs;
  const key = `ratelimit:${identifier}`;

  const pipeline = redis.pipeline();

  // Remove old entries outside window
  pipeline.zremrangebyscore(key, 0, windowStart);

  // Count requests in current window
  pipeline.zcard(key);

  // Add current request
  pipeline.zadd(key, now, `${now}-${Math.random()}`);

  // Set expiry
  pipeline.expire(key, Math.ceil(windowMs / 1000));

  const results = await pipeline.exec();
  const requestCount = results[1][1];

  if (requestCount >= limit) {
    // Remove the request we just added
    await redis.zremrangebyscore(key, now, now);
    return { allowed: false, remaining: 0 };
  }

  return { allowed: true, remaining: limit - requestCount - 1 };
}
```

### Express Rate Limit Middleware
```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const Redis = require('ioredis');

// Secure IP identification
const getClientIP = (req) => {
  // Only trust X-Forwarded-For if behind known proxy
  if (process.env.TRUSTED_PROXIES) {
    const trustedProxies = process.env.TRUSTED_PROXIES.split(',');
    const socketIP = req.socket.remoteAddress;

    if (trustedProxies.includes(socketIP)) {
      const forwarded = req.headers['x-forwarded-for'];
      if (forwarded) {
        // Get the rightmost untrusted IP
        const ips = forwarded.split(',').map(ip => ip.trim());
        for (let i = ips.length - 1; i >= 0; i--) {
          if (!trustedProxies.includes(ips[i])) {
            return ips[i];
          }
        }
      }
    }
    return socketIP;
  }
  return req.socket.remoteAddress;
};

const limiter = rateLimit({
  store: new RedisStore({
    client: new Redis(),
    prefix: 'rl:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  keyGenerator: getClientIP,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests',
      retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
    });
  }
});
```

## Common Vulnerability Patterns

### Trusting X-Forwarded-For Blindly
```
Vulnerable:
client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

Attack:
curl -H "X-Forwarded-For: 1.2.3.4" https://target.com/api
# Each request with different IP bypasses limit

Secure:
# Only trust XFF from known proxies
if is_trusted_proxy(request.remote_addr):
    client_ip = parse_xff_rightmost_untrusted(request)
else:
    client_ip = request.remote_addr
```

### Per-Endpoint Inconsistency
```
Issue:
- /api/login: 5 requests/minute
- /api/v2/login: No limit (oversight)
- /mobile/login: No limit (different team)

Testing:
- Enumerate all authentication endpoints
- Test each for rate limiting
- Check API versions for consistency
- Test mobile/alternative APIs
```

### Race Condition in Limit Check
```
Vulnerable:
count = get_request_count(user_id)
if count < limit:
    process_request()
    increment_count(user_id)  # Window for race

Attack:
- Send many parallel requests
- All pass count check simultaneously
- All increment after processing
- Limit exceeded significantly
```

### Missing Limits on Sensitive Operations
```
High-Risk Unprotected Operations:
- Password reset (account enumeration)
- OTP verification (brute force)
- Account creation (spam)
- File upload (storage exhaustion)
- Export/report generation (CPU exhaustion)
- GraphQL queries (complexity attacks)
```

## Attack Scenarios

### Credential Stuffing
```
Attack Profile:
- Distributed IPs (10,000+)
- Valid email/password pairs from breaches
- Low request rate per IP
- High total request volume

Protection:
- Account-based rate limiting
- Device fingerprinting
- CAPTCHA on suspicious patterns
- Breached password detection
```

### OTP Brute Force
```
Attack:
- 6-digit OTP = 1,000,000 combinations
- Without rate limit: minutes to crack
- Even with 1 req/sec: ~11 days

Required Controls:
- Max 3-5 attempts per code
- Code invalidation after attempts
- Account lockout on failures
- Exponential backoff
```

### API Abuse
```
Scenarios:
- Data scraping (competitor, malicious)
- Service disruption (DoS)
- Cost inflation (pay-per-call APIs)
- Account enumeration
- Feature abuse (free tier exploitation)
```

## Reporting Guidelines

When reporting rate limit vulnerabilities:
1. Identify the unprotected or bypassed endpoint
2. Demonstrate the bypass technique
3. Quantify the potential abuse scale
4. Assess business impact (fraud, DoS, cost)
5. Consider cascading effects

## Output Format

For each finding, provide:
- **Vulnerability**: Rate limit weakness type
- **Location**: Affected endpoint(s) and implementation
- **Description**: Technical explanation of the weakness
- **Proof of Concept**: Bypass demonstration or abuse scenario
- **Impact**: Security, availability, and business implications
- **Remediation**: Rate limit configuration and implementation fixes

---

# Detection Methodology

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
