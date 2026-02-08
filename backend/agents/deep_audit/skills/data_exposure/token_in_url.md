# Tokens and Secrets in URL Detection

Detect session tokens, API keys, reset tokens, JWTs, or other secrets in URL
query parameters or path segments. Tokens in URLs leak via Referer headers,
browser history, server/proxy/CDN access logs, and URL shortener databases.

## Methodology

### Step 1 — Identify Token-Bearing URL Patterns

Scan route definitions, URL builders, redirect constructors, and link generators
for parameters carrying auth material.

```javascript
// VULNERABLE — session token as query param
app.get("/dashboard", (req, res) => {
  const token = req.query.token;
  const session = validateToken(token);
});
// VULNERABLE — API key in path segment
router.get("/api/data/:apiKey/records", dataController.getRecords);
```

```python
# VULNERABLE — reset token as GET param, no expiry check
# /reset-password/?token=abc123def456
path("reset-password/", views.reset_password, name="reset_password"),
```

```java
// VULNERABLE — API key as query parameter
@GetMapping("/api/v1/data")
public ResponseEntity<List<Data>> getData(@RequestParam("api_key") String apiKey) {
    validateApiKey(apiKey);
    return ResponseEntity.ok(dataService.findAll());
}
```

```python
# VULNERABLE — JWT in query string
@app.route("/api/export")
def export_data():
    token = request.args.get("jwt")
    payload = decode_jwt(token)
    return generate_export(payload["user_id"])
```

### Step 2 — Trace Redirect Chains

Redirects leak tokens via Referer. When a page with `?token=X` loads external
resources, the full URL is sent in the Referer header.

```javascript
// VULNERABLE — redirect preserves token in query string
app.get("/auth/callback", (req, res) => {
  const accessToken = exchangeCode(req.query.code);
  res.redirect(`/app?access_token=${accessToken}`);
});
// SAFE — token in HttpOnly cookie, clean redirect
app.get("/auth/callback", (req, res) => {
  const accessToken = exchangeCode(req.query.code);
  res.cookie("session", accessToken, { httpOnly: true, secure: true });
  res.redirect("/app");
});
```

Multi-hop redirects compound the risk — each hop logs the full URL:
`/login?token=X -> 302 /verify?token=X -> 302 /dashboard?token=X`

### Step 3 — Check OAuth Flows for Token Placement

Fragment (`#`) values are not sent in Referer; query (`?`) values are.

```python
# VULNERABLE — response_mode=query with token response type
OAUTH_CONFIG = {
    "response_type": "token",
    "response_mode": "query",  # token after ?, leaked via Referer
}
# SAFER — fragment mode (implicit flow still deprecated; use code+PKCE)
OAUTH_CONFIG = {
    "response_type": "token",
    "response_mode": "fragment",  # token after #, not in Referer
}
```

### Step 4 — Inspect URL Construction in Frontend Code

Search client-side JS for token interpolation into URLs.

```javascript
// VULNERABLE — API key in fetch URL
await fetch(`https://api.example.com/data?api_key=${API_KEY}&q=${q}`);
// VULNERABLE — share link embeds auth token
function getShareLink(docId) {
  return `${origin}/doc/${docId}?token=${authToken}`;
}
// VULNERABLE — token in browser history via navigation
window.location.href = `/dashboard?session_token=${token}`;
```

### Step 5 — Evaluate Token Lifetime and Scope

| Property  | Lower Risk             | Higher Risk                |
|-----------|------------------------|----------------------------|
| Lifetime  | < 15 min               | Hours/days/no expiry       |
| Usage     | Single-use             | Reusable                   |
| Scope     | Single action          | Full session/API access    |
| Rotation  | Per-request            | Static/long-lived          |

```python
# BY_DESIGN — pre-signed S3 URL, 5-min expiry, single object
url = s3.generate_presigned_url("get_object",
    Params={"Bucket": "docs", "Key": "report.pdf"}, ExpiresIn=300)
# VULNERABLE — permanent API key in URL
url = f"https://api.example.com/v1/data?key={PERMANENT_API_KEY}"
```

### Step 6 — Check Server Access Log Configuration

Most defaults (nginx combined, Apache, cloud LBs) log the full request URI.

```nginx
# Default nginx — logs full query string
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
# GET /api?token=secret123 -> token in log file
```

```python
# Common Django middleware — logs full path including tokens
class RequestLoggingMiddleware:
    def __call__(self, request):
        logger.info(f"Request: {request.method} {request.get_full_path()}")
        return self.get_response(request)
```

### Step 7 — Inspect URL Shortener and Caching Behavior

```javascript
// VULNERABLE — shortener stores full URL with embedded token permanently
async function createShareLink(docId) {
  const fullUrl = `https://app.example.com/doc/${docId}?auth=${token}`;
  return await urlShortener.shorten(fullUrl);
}
```

Token-bearing URLs must not be cacheable by proxies:

```python
# VULNERABLE — no Cache-Control, proxies may cache keyed by full URL
@app.route("/api/report")
def get_report():
    token = request.args.get("token")
    validate(token)
    return jsonify(report_data)
# SAFE — no-store prevents proxy caching
resp.headers["Cache-Control"] = "no-store"
```

## Decision Tree

```
START
  |
  v
URL contains token/key/secret in query string or path?
  |NO            |YES
  v              v
SAFE          Token in fragment (#) only, never in query/path?
                |YES           |NO
                v              v
             HARDENED       Token lifetime?
             (Low)            |
                    +---------+---------+
                    |                   |
                 <= 15 min           > 15 min or
                 AND single-use      no expiry
                    |                   |
                    v                   v
                 Pre-signed URL?     Token type?
                  |YES   |NO         |          |         |        |
                  v      v        Session    API key   Reset    JWT/Bearer
               BY_    HARDENED    token                token
               DESIGN (Medium)      |          |         |        |
                                    v          v         v        v
                                 VULN       VULN      VULN     VULN
                                 (Crit)     (High)    (High)   (Crit)
                                    |
                                    v
                              Also leaks via Referer to external origins?
                                |YES          |NO
                                v             v
                             Escalate      Keep original
                             severity      severity
```

## Real-World Examples

### Example 1 — Session Token in Query Parameter (Express)

```javascript
function authenticate(req, res, next) {
  const token = req.query.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  req.user = jwt.verify(token, SECRET);
  next();
}
// Users bookmark: https://app.example.com/dashboard?token=eyJhbGci...
// Appears in: browser history, server logs, Referer headers, proxy logs
```

**Why vulnerable:** The JWT in the query string is a long-lived session token.
Every system seeing the URL captures a valid credential. On shared computers the
token persists in browser history indefinitely.

**Impact:** Critical. Session hijacking via log access, browser history, shoulder
surfing, or Referer leakage across the token's entire lifetime.

**Fix:** Accept tokens only via `Authorization` header or HttpOnly Secure cookie.

### Example 2 — Password Reset Token Without Expiry (Django)

```python
def request_reset(request):
    user = User.objects.get(email=request.POST["email"])
    token = secrets.token_urlsafe(32)
    user.reset_token = token  # no expiry, no single-use
    user.save()
    send_mail("Reset", f"https://app.example.com/reset-password/?token={token}",
              None, [user.email])

def reset_password(request):
    token = request.GET.get("token")  # GET query string
    user = User.objects.get(reset_token=token)
    if request.method == "POST":
        user.set_password(request.POST["new_password"])
        user.save()  # token NOT invalidated
```

**Why vulnerable:** No expiry, no single-use invalidation. The token persists in
server logs, proxy logs, and browser history permanently. Any log access yields
a permanent password reset capability.

**Impact:** High. Permanent account takeover via any log source.

**Fix:** Add 15-min expiry, invalidate after use, move token to path segment.

### Example 3 — API Key Leaked via Redirect Chain (Flask)

```python
@app.route("/proxy/weather")
def weather_proxy():
    api_key = os.environ["WEATHER_API_KEY"]
    upstream = f"https://api.weather.com/v1/forecast?key={api_key}&city={city}"
    resp = requests.get(upstream)  # follows redirects by default
    return jsonify(resp.json())
# Upstream 301 -> https://cdn.weather.com/...?key=abc123
# CDN access log now contains the permanent API key
```

**Why vulnerable:** Permanent API key in URL query string. The requests library
follows redirects, sending the full URL (with key) to the redirect target. Key
appears in access logs at every hop in the chain.

**Impact:** High. Permanent key compromise. Any party with log access at any hop
can use the key until rotation.

**Fix:** Send key in `Authorization` header; set `allow_redirects=False`.

## Common False Positive Patterns

1. **Pre-signed cloud storage URLs with short expiry.** S3 pre-signed URLs, GCS
   signed URLs, Azure SAS tokens are designed this way. Under 15 min expiry and
   single-object scope = BY_DESIGN.

2. **One-time email verification links.** `/verify-email?token=abc123` with
   single-use and sub-24h expiry is standard. Verify invalidation and expiry
   before classifying as SAFE.

3. **CSRF tokens in form action URLs.** Not session credentials; tied to a
   specific form submission. SAFE.

4. **Webhook verification tokens.** `/webhooks/stripe?verify=whsec_abc123` for
   setup-time endpoint verification. Short-lived, single-purpose. BY_DESIGN.

5. **OAuth authorization codes (not tokens).** `/callback?code=abc123` per
   RFC 6749 is single-use, short-lived, requires client secret. BY_DESIGN. Only
   flag if code has no expiry or is reusable.

6. **UUID path segments that are resource IDs, not tokens.** `/documents/a3f8b2c1`
   may look like a token but is a non-secret identifier behind authentication.
   Check if the ID alone grants access (bearer) vs requires separate auth. SAFE
   if auth-gated.

7. **Synthetic tokens in test/dev code.** `test_token_123` in test directories
   and fixtures is not real credential exposure.
